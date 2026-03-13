package service

import (
	"strings"
	"testing"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

func TestBuildPacketEvidencePrefersHTTPDataPackets(t *testing.T) {
	requestPacket := "GET /api/v1/deploy/release HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: test-client\r\n\r\n"
	responsePacket := "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html>not found</html>"
	event := shared.RawEvent{
		ID:        "raw-1",
		EventTime: time.Now().UTC(),
		Payload: shared.SuricataEvent{
			EventType: "alert",
			AppProto:  "http",
			FlowID:    "flow-1",
			Payload: map[string]any{
				"http": map[string]any{
					"http_method": "GET",
					"url":         "/api/v1/deploy/release",
					"hostname":    "api.example.com",
					"status":      404,
				},
				"_ndr_http_packets": map[string]any{
					"source":          "http-data.log",
					"request_packet":  requestPacket,
					"response_packet": responsePacket,
				},
			},
		},
	}

	evidence := buildPacketEvidence([]shared.RawEvent{event}, nil)
	if evidence == nil {
		t.Fatalf("expected packet evidence")
	}
	if evidence.Source != "http-data.log" {
		t.Fatalf("expected source http-data.log, got %q", evidence.Source)
	}
	if !strings.Contains(evidence.RequestPacket, "GET /api/v1/deploy/release HTTP/1.1") {
		t.Fatalf("expected request packet to come from http-data.log, got %q", evidence.RequestPacket)
	}
	if !strings.Contains(evidence.ResponsePacket, "HTTP/1.1 404 Not Found") {
		t.Fatalf("expected response packet to come from http-data.log, got %q", evidence.ResponsePacket)
	}
}

func TestBuildPacketEvidenceFallsBackToStructuredHTTPContext(t *testing.T) {
	event := shared.RawEvent{
		ID:        "raw-2",
		EventTime: time.Now().UTC(),
		Payload: shared.SuricataEvent{
			EventType: "http",
			AppProto:  "http",
			FlowID:    "flow-2",
			Payload: map[string]any{
				"http": map[string]any{
					"http_method": "POST",
					"url":         "/login",
					"hostname":    "192.168.2.88",
					"status":      404,
					"request_headers": []any{
						map[string]any{"name": "Host", "value": "192.168.2.88"},
						map[string]any{"name": "Content-Type", "value": "application/json"},
					},
					"response_headers": []any{
						map[string]any{"name": "Content-Type", "value": "text/html"},
					},
				},
				"http_request_body":            "{\"username\":\"yan\"}",
				"http_response_body_printable": "<html>404 Not Found</html>",
			},
		},
	}

	evidence := buildPacketEvidence([]shared.RawEvent{event}, nil)
	if evidence == nil {
		t.Fatalf("expected packet evidence")
	}
	if !strings.Contains(evidence.RequestPacket, "POST /login HTTP/1.1") {
		t.Fatalf("expected reconstructed request packet, got %q", evidence.RequestPacket)
	}
	if !strings.Contains(evidence.RequestPacket, "{\"username\":\"yan\"}") {
		t.Fatalf("expected request body in packet, got %q", evidence.RequestPacket)
	}
	if !strings.Contains(evidence.ResponsePacket, "HTTP/1.1 404 Not Found") {
		t.Fatalf("expected reconstructed response packet, got %q", evidence.ResponsePacket)
	}
	if !strings.Contains(evidence.ResponsePacket, "<html>404 Not Found</html>") {
		t.Fatalf("expected response body in packet, got %q", evidence.ResponsePacket)
	}
}
