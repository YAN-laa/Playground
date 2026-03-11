package search

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yan/ndr-platform/internal/shared"
)

func TestOpenSearchEngineEnsureReadyAndBulk(t *testing.T) {
	t.Helper()

	requests := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests = append(requests, req.Method+" "+req.URL.Path)
		switch {
		case req.Method == http.MethodHead && req.URL.Path == "/alerts-test":
			http.NotFound(w, req)
		case req.Method == http.MethodHead && req.URL.Path == "/flows-test":
			http.NotFound(w, req)
		case req.Method == http.MethodPut && (req.URL.Path == "/alerts-test" || req.URL.Path == "/flows-test"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"acknowledged":true}`))
		case req.Method == http.MethodPost && req.URL.Path == "/_bulk":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errors":false}`))
		case req.Method == http.MethodPost && req.URL.Path == "/alerts-test/_search":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hits": map[string]any{
					"total": map[string]any{"value": 1},
					"hits": []map[string]any{
						{"_source": map[string]any{
							"id":            "alert-1",
							"tenant_id":     "tenant-a",
							"signature":     "Suspicious SMB Activity",
							"status":        "open",
							"severity":      1,
							"risk_score":    90,
							"first_seen_at": "2026-03-11T00:00:00Z",
							"last_seen_at":  "2026-03-11T00:00:00Z",
						}},
					},
				},
			})
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
	}))
	defer server.Close()

	engine := NewOpenSearchEngine(OpenSearchConfig{
		BaseURL:    server.URL,
		AlertIndex: "alerts-test",
		FlowIndex:  "flows-test",
	})
	if err := engine.EnsureReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := engine.IndexAlerts(context.Background(), []shared.Alert{{ID: "alert-1", TenantID: "tenant-a", Signature: "Suspicious SMB Activity"}}); err != nil {
		t.Fatal(err)
	}
	if err := engine.IndexFlows(context.Background(), []shared.Flow{{ID: "flow-1", TenantID: "tenant-a", FlowID: "flow-a"}}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.SearchAlerts(context.Background(), shared.AlertQuery{
		TenantID: "tenant-a",
		Page:     1,
		PageSize: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Items) != 1 {
		t.Fatalf("unexpected search result: %+v", result)
	}

	joined := strings.Join(requests, "\n")
	for _, expected := range []string{
		"HEAD /alerts-test",
		"PUT /alerts-test",
		"HEAD /flows-test",
		"PUT /flows-test",
		"POST /_bulk",
		"POST /alerts-test/_search",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected request %q in\n%s", expected, joined)
		}
	}
}

func TestOpenSearchEngineBulkRetryAndDLQ(t *testing.T) {
	t.Helper()

	attempts := 0
	tmpDir := t.TempDir()
	dlqFile := filepath.Join(tmpDir, "search.dlq")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/_bulk":
			attempts++
			if attempts < 2 {
				http.Error(w, "temporary failure", http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errors":false}`))
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
	}))
	defer server.Close()

	engine := NewOpenSearchEngine(OpenSearchConfig{
		BaseURL:      server.URL,
		AlertIndex:   "alerts-test",
		FlowIndex:    "flows-test",
		RetryMax:     2,
		RetryBackoff: 1,
		DLQFile:      dlqFile,
	})
	if err := engine.IndexAlerts(context.Background(), []shared.Alert{{ID: "alert-1", TenantID: "tenant-a"}}); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 bulk attempts, got %d", attempts)
	}
	if _, err := os.Stat(dlqFile); !os.IsNotExist(err) {
		t.Fatalf("expected no dlq file on eventual success, stat err=%v", err)
	}
}

func TestOpenSearchEngineBulkDLQOnFailure(t *testing.T) {
	t.Helper()

	tmpDir := t.TempDir()
	dlqFile := filepath.Join(tmpDir, "search.dlq")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "permanent failure", http.StatusBadGateway)
	}))
	defer server.Close()

	engine := NewOpenSearchEngine(OpenSearchConfig{
		BaseURL:      server.URL,
		AlertIndex:   "alerts-test",
		FlowIndex:    "flows-test",
		RetryMax:     1,
		RetryBackoff: 1,
		DLQFile:      dlqFile,
	})
	err := engine.IndexAlerts(context.Background(), []shared.Alert{{ID: "alert-1", TenantID: "tenant-a"}})
	if err == nil {
		t.Fatal("expected bulk indexing failure")
	}
	data, readErr := os.ReadFile(dlqFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(data), `"id":"alert-1"`) {
		t.Fatalf("expected dlq content to include alert id, got %s", string(data))
	}
}
