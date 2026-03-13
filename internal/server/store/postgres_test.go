package store

import (
	"testing"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

func TestSanitizeRawEventForJSONB(t *testing.T) {
	event := shared.RawEvent{
		ID:         "raw-\x00bad",
		TenantID:   "demo-\x00tenant",
		ProbeID:    "probe-\x00id",
		EventType:  "alert",
		EventTime:  time.Now().UTC(),
		IngestTime: time.Now().UTC(),
		Payload: shared.SuricataEvent{
			Timestamp: "2026-03-12T06:48:06Z",
			EventType: "alert",
			SrcIP:     "10.0.0.1",
			DstIP:     "10.0.0.2",
			Proto:     "TCP",
			AppProto:  "http",
			FlowID:    "flow-\x00bad",
			Alert: &shared.SuricataAlert{
				SignatureID: 1,
				Signature:   "bad\x00sig",
				Category:    "cat",
				Severity:    1,
			},
			Payload: map[string]any{
				"payload_printable": string([]byte{'P', 'O', 0, 'S', 'T'}),
				"http": map[string]any{
					"http_request_body": string([]byte{0xff, 'A', 0, 'B'}),
				},
				"array": []any{"ok", string([]rune{'x', 0xD800, 'y'})},
			},
		},
	}

	sanitized := sanitizeRawEventForJSONB(event)

	assertNoNULOrSurrogate(t, sanitized.ID)
	assertNoNULOrSurrogate(t, sanitized.TenantID)
	assertNoNULOrSurrogate(t, sanitized.ProbeID)
	assertNoNULOrSurrogate(t, sanitized.Payload.FlowID)
	assertNoNULOrSurrogate(t, sanitized.Payload.Alert.Signature)

	printable, _ := sanitized.Payload.Payload["payload_printable"].(string)
	assertNoNULOrSurrogate(t, printable)

	httpPayload, _ := sanitized.Payload.Payload["http"].(map[string]any)
	body, _ := httpPayload["http_request_body"].(string)
	assertNoNULOrSurrogate(t, body)

	array, _ := sanitized.Payload.Payload["array"].([]any)
	if len(array) != 2 {
		t.Fatalf("expected sanitized array to have 2 items, got %d", len(array))
	}
	assertNoNULOrSurrogate(t, array[1].(string))
}

func assertNoNULOrSurrogate(t *testing.T, value string) {
	t.Helper()
	for _, r := range value {
		if r == 0 {
			t.Fatalf("unexpected NUL rune in %q", value)
		}
		if r >= 0xD800 && r <= 0xDFFF {
			t.Fatalf("unexpected surrogate rune in %q", value)
		}
	}
}
