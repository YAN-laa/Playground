package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yan/ndr-platform/internal/shared"
)

func TestListQueuedBatchesSkipsStateFilesAndEmptyPayloads(t *testing.T) {
	dir := t.TempDir()

	statePayload := map[string]any{
		"path":   "/var/log/suricata/eve.json",
		"offset": 123,
	}
	stateBytes, err := json.Marshal(statePayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "eve-offset.json"), stateBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	batch := shared.EventBatch{
		TenantID: "demo-tenant",
		ProbeID:  "probe-1",
		Events: []shared.SuricataEvent{
			{Timestamp: "2026-03-12T06:48:06Z", EventType: "alert"},
		},
	}
	batchBytes, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "123456-probe-1.json"), batchBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	items, err := listQueuedBatches(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 queued batch, got %d", len(items))
	}
	if items[0].FileName != "123456-probe-1.json" {
		t.Fatalf("unexpected batch file: %s", items[0].FileName)
	}
}
