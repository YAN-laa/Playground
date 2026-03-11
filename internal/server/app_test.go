package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

func TestEndToEndFlow(t *testing.T) {
	t.Setenv("APP_EXPORT_DIR", t.TempDir())
	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var login shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &login, http.StatusOK, "")

	authHeader := "Bearer " + login.Token

	registerBody := shared.RegisterProbeRequest{
		TenantID:    "tenant-a",
		ProbeCode:   "probe-a-01",
		Name:        "Probe A",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}
	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, registerBody, &probe, http.StatusCreated, "")

	heartbeatBody := shared.HeartbeatRequest{
		TenantID: "tenant-a",
		ProbeID:  probe.ID,
		Status:   "online",
		CPUUsage: 10,
		MemUsage: 20,
		DropRate: 0,
	}
	doJSON(t, handler, "/api/v1/probes/heartbeat", http.MethodPost, heartbeatBody, nil, http.StatusOK, "")

	var asset shared.Asset
	doJSON(t, handler, "/api/v1/assets", http.MethodPost, shared.CreateAssetRequest{
		TenantID:        "tenant-a",
		Name:            "FileServer-01",
		IP:              "192.168.1.10",
		AssetType:       "server",
		ImportanceLevel: "critical",
		Owner:           "secops",
		Tags:            []string{"prod", "windows"},
	}, &asset, http.StatusCreated, authHeader)

	var intel shared.ThreatIntel
	doJSON(t, handler, "/api/v1/threat-intel", http.MethodPost, shared.CreateThreatIntelRequest{
		TenantID: "tenant-a",
		Type:     "ip",
		Value:    "10.0.0.1",
		Severity: "high",
		Source:   "manual",
		Tags:     []string{"botnet", "ransomware"},
	}, &intel, http.StatusCreated, authHeader)

	now := time.Now().UTC().Format(time.RFC3339)
	ingestBody := shared.EventBatch{
		TenantID: "tenant-a",
		ProbeID:  probe.ID,
		Events: []shared.SuricataEvent{
			{
				Timestamp: now,
				EventType: "alert",
				SrcIP:     "10.0.0.1",
				SrcPort:   50100,
				DstIP:     "192.168.1.10",
				DstPort:   445,
				Proto:     "TCP",
				AppProto:  "smb",
				FlowID:    "flow-a-01",
				Alert: &shared.SuricataAlert{
					SignatureID: 1001,
					Signature:   "Suspicious SMB Activity",
					Category:    "Attempted Admin",
					Severity:    1,
				},
			},
			{
				Timestamp: now,
				EventType: "alert",
				SrcIP:     "10.0.0.1",
				SrcPort:   50101,
				DstIP:     "192.168.1.10",
				DstPort:   445,
				Proto:     "TCP",
				AppProto:  "smb",
				FlowID:    "flow-a-02",
				Alert: &shared.SuricataAlert{
					SignatureID: 1001,
					Signature:   "Suspicious SMB Activity",
					Category:    "Attempted Admin",
					Severity:    1,
				},
			},
		},
	}
	doJSON(t, handler, "/api/v1/events/ingest", http.MethodPost, ingestBody, nil, http.StatusAccepted, "")

	var alerts shared.AlertListResponse
	doJSON(t, handler, "/api/v1/alerts?tenant_id=tenant-a", http.MethodGet, nil, &alerts, http.StatusOK, authHeader)
	if len(alerts.Items) != 1 {
		t.Fatalf("expected 1 aggregated alert, got %d", len(alerts.Items))
	}
	if alerts.Items[0].EventCount != 2 {
		t.Fatalf("expected event_count=2, got %d", alerts.Items[0].EventCount)
	}

	var detail shared.AlertDetail
	doJSON(t, handler, "/api/v1/alerts/"+alerts.Items[0].ID+"/detail", http.MethodGet, nil, &detail, http.StatusOK, authHeader)
	if len(detail.Events) != 2 {
		t.Fatalf("expected 2 related events, got %d", len(detail.Events))
	}
	if len(detail.Flows) != 2 {
		t.Fatalf("expected 2 related flows, got %d", len(detail.Flows))
	}
	if detail.Alert.TargetAssetName != asset.Name {
		t.Fatalf("expected target asset enrichment, got %+v", detail.Alert)
	}
	if len(detail.Alert.ThreatIntelTags) == 0 {
		t.Fatalf("expected intel enrichment, got %+v", detail.Alert)
	}

	var flows []shared.Flow
	doJSON(t, handler, "/api/v1/flows?tenant_id=tenant-a&src_ip=10.0.0.1", http.MethodGet, nil, &flows, http.StatusOK, authHeader)
	if len(flows) != 2 {
		t.Fatalf("expected 2 flows in flow search, got %d", len(flows))
	}
	var assets []shared.Asset
	doJSON(t, handler, "/api/v1/assets?tenant_id=tenant-a", http.MethodGet, nil, &assets, http.StatusOK, authHeader)
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	var intelList []shared.ThreatIntel
	doJSON(t, handler, "/api/v1/threat-intel?tenant_id=tenant-a", http.MethodGet, nil, &intelList, http.StatusOK, authHeader)
	if len(intelList) != 1 {
		t.Fatalf("expected 1 intel entry, got %d", len(intelList))
	}

	var notifyChannel shared.NotificationChannel
	doJSON(t, handler, "/api/v1/notifications/channels", http.MethodPost, shared.CreateNotificationChannelRequest{
		TenantID: "tenant-a",
		Name:     "ops-console",
		Type:     "console",
		Enabled:  true,
		Events:   []string{"alert.updated", "ticket.created", "ticket.updated"},
	}, &notifyChannel, http.StatusCreated, authHeader)

	updateBody := shared.UpdateAlertStatusRequest{
		Status:   "ack",
		Assignee: "analyst-1",
	}
	var updated shared.Alert
	doJSON(t, handler, "/api/v1/alerts/"+alerts.Items[0].ID, http.MethodPatch, updateBody, &updated, http.StatusOK, authHeader)
	if updated.Status != "ack" {
		t.Fatalf("expected status ack, got %s", updated.Status)
	}

	createTicketBody := shared.CreateTicketRequest{
		TenantID:    "tenant-a",
		AlertID:     alerts.Items[0].ID,
		Title:       "Investigate suspicious SMB traffic",
		Description: "Auto-created from alert",
		Priority:    "high",
		Assignee:    "analyst-1",
	}
	var ticket shared.Ticket
	doJSON(t, handler, "/api/v1/tickets", http.MethodPost, createTicketBody, &ticket, http.StatusCreated, authHeader)
	if ticket.AlertID != alerts.Items[0].ID {
		t.Fatalf("unexpected ticket alert id: %s", ticket.AlertID)
	}

	doJSON(t, handler, "/api/v1/alerts/"+alerts.Items[0].ID+"/detail", http.MethodGet, nil, &detail, http.StatusOK, authHeader)
	if len(detail.Tickets) != 1 {
		t.Fatalf("expected 1 related ticket, got %d", len(detail.Tickets))
	}
	if len(detail.Activities) == 0 {
		t.Fatal("expected activities to be present in detail")
	}

	var ticketDetail shared.TicketDetail
	doJSON(t, handler, "/api/v1/tickets/"+ticket.ID, http.MethodGet, nil, &ticketDetail, http.StatusOK, authHeader)
	if ticketDetail.Ticket.ID != ticket.ID {
		t.Fatalf("unexpected ticket detail id: %s", ticketDetail.Ticket.ID)
	}

	var updatedTicket shared.Ticket
	doJSON(t, handler, "/api/v1/tickets/"+ticket.ID, http.MethodPatch, shared.UpdateTicketStatusRequest{
		Status:   "closed",
		Assignee: "analyst-1",
	}, &updatedTicket, http.StatusOK, authHeader)
	if updatedTicket.Status != "closed" {
		t.Fatalf("expected closed ticket, got %s", updatedTicket.Status)
	}

	var role shared.Role
	doJSON(t, handler, "/api/v1/roles", http.MethodPost, shared.CreateRoleRequest{
		TenantID:    "tenant-a",
		Name:        "analyst",
		Description: "Security analyst",
		Permissions: []string{"alert.read", "ticket.write"},
	}, &role, http.StatusCreated, authHeader)

	var user shared.User
	doJSON(t, handler, "/api/v1/users", http.MethodPost, shared.CreateUserRequest{
		TenantID:    "tenant-a",
		Username:    "alice",
		DisplayName: "Alice",
		Password:    "alice123",
		Roles:       []string{role.Name},
	}, &user, http.StatusCreated, authHeader)

	var auditLogs []shared.AuditLog
	doJSON(t, handler, "/api/v1/audit/logs?tenant_id=tenant-a", http.MethodGet, nil, &auditLogs, http.StatusOK, authHeader)
	if len(auditLogs) == 0 {
		t.Fatal("expected audit logs to be created")
	}
	foundQueryAudit := false
	for _, log := range auditLogs {
		if log.Action == "query" && (log.ResourceType == "alert_search" || log.ResourceType == "flow_search") {
			foundQueryAudit = true
			break
		}
	}
	if !foundQueryAudit {
		t.Fatal("expected query audit logs to be created")
	}

	var analystLogin shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "tenant-a",
		Username: "alice",
		Password: "alice123",
	}, &analystLogin, http.StatusOK, "")

	doJSON(t, handler, "/api/v1/audit/logs?tenant_id=tenant-a", http.MethodGet, nil, nil, http.StatusForbidden, "Bearer "+analystLogin.Token)

	var probeConfig shared.ProbeConfig
	doJSON(t, handler, "/api/v1/probe-configs", http.MethodPost, shared.CreateProbeConfigRequest{
		TenantID:    "tenant-a",
		Name:        "default-tap",
		Description: "Default capture profile",
		Filters:     []string{"tcp", "not port 22"},
		OutputTypes: []string{"alert", "flow"},
	}, &probeConfig, http.StatusCreated, authHeader)

	var ruleBundle shared.RuleBundle
	doJSON(t, handler, "/api/v1/rule-bundles", http.MethodPost, shared.CreateRuleBundleRequest{
		TenantID:    "tenant-a",
		Version:     "suricata-2026.03",
		Description: "March rule set",
		Enabled:     true,
	}, &ruleBundle, http.StatusCreated, authHeader)

	var probeBinding shared.ProbeBinding
	doJSON(t, handler, "/api/v1/probe-bindings", http.MethodPost, shared.ApplyProbeBindingRequest{
		TenantID:      "tenant-a",
		ProbeID:       probe.ID,
		ProbeConfigID: probeConfig.ID,
		RuleBundleID:  ruleBundle.ID,
	}, &probeBinding, http.StatusCreated, authHeader)
	if probeBinding.ProbeID != probe.ID {
		t.Fatalf("unexpected probe binding probe id: %s", probeBinding.ProbeID)
	}

	var bindingDetail shared.ProbeBindingDetail
	doJSON(t, handler, "/api/v1/probes/"+probe.ID+"/binding", http.MethodGet, nil, &bindingDetail, http.StatusOK, "")
	if bindingDetail.Binding.ProbeID != probe.ID {
		t.Fatalf("unexpected binding detail probe id: %s", bindingDetail.Binding.ProbeID)
	}

	var bindings []shared.ProbeBinding
	doJSON(t, handler, "/api/v1/probe-bindings?tenant_id=tenant-a", http.MethodGet, nil, &bindings, http.StatusOK, authHeader)
	if len(bindings) != 1 {
		t.Fatalf("expected 1 probe binding, got %d", len(bindings))
	}

	var deployments []shared.DeploymentRecord
	doJSON(t, handler, "/api/v1/deployments?tenant_id=tenant-a", http.MethodGet, nil, &deployments, http.StatusOK, authHeader)
	if len(deployments) != 1 {
		t.Fatalf("expected 1 deployment record, got %d", len(deployments))
	}
	if deployments[0].Status != "pending" {
		t.Fatalf("expected pending deployment status, got %s", deployments[0].Status)
	}

	var acked shared.DeploymentRecord
	doJSON(t, handler, "/api/v1/deployments/ack", http.MethodPost, shared.DeploymentAckRequest{
		TenantID:      "tenant-a",
		ProbeID:       probe.ID,
		ProbeConfigID: probeConfig.ID,
		RuleBundleID:  ruleBundle.ID,
		Status:        "applied",
		Message:       "probe pulled binding",
	}, &acked, http.StatusCreated, "")
	if acked.Status != "applied" {
		t.Fatalf("expected applied deployment status, got %s", acked.Status)
	}

	var probes []shared.Probe
	doJSON(t, handler, "/api/v1/probes?tenant_id=tenant-a", http.MethodGet, nil, &probes, http.StatusOK, authHeader)
	if len(probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(probes))
	}
	if probes[0].AppliedConfigID != probeConfig.ID || probes[0].AppliedRuleID != ruleBundle.ID || probes[0].LastDeployStatus != "applied" {
		t.Fatalf("unexpected probe deployment state: %+v", probes[0])
	}

	var probeDetail shared.ProbeDetail
	doJSON(t, handler, "/api/v1/probes/"+probe.ID, http.MethodGet, nil, &probeDetail, http.StatusOK, authHeader)
	if probeDetail.Probe.ID != probe.ID || len(probeDetail.Deployments) == 0 || len(probeDetail.Metrics) == 0 {
		t.Fatalf("unexpected probe detail: %+v", probeDetail)
	}

	var batchBindings shared.BatchApplyProbeBindingResponse
	doJSON(t, handler, "/api/v1/probe-bindings/batch", http.MethodPost, shared.BatchApplyProbeBindingRequest{
		TenantID:      "tenant-a",
		ProbeIDs:      []string{probe.ID},
		ProbeConfigID: probeConfig.ID,
		RuleBundleID:  ruleBundle.ID,
	}, &batchBindings, http.StatusCreated, authHeader)
	if batchBindings.Applied != 1 || len(batchBindings.Items) != 1 {
		t.Fatalf("unexpected batch binding response: %+v", batchBindings)
	}

	var metrics []shared.ProbeMetric
	doJSON(t, handler, "/api/v1/probes/"+probe.ID+"/metrics?limit=5", http.MethodGet, nil, &metrics, http.StatusOK, authHeader)
	if len(metrics) == 0 {
		t.Fatal("expected probe metrics")
	}
	doJSON(t, handler, "/api/v1/probes/"+probe.ID+"/metrics?limit=5&since="+time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339), http.MethodGet, nil, &metrics, http.StatusOK, authHeader)
	if len(metrics) != 0 {
		t.Fatalf("expected 0 probe metrics after future since filter, got %d", len(metrics))
	}

	var disabledRuleBundle shared.RuleBundle
	doJSON(t, handler, "/api/v1/rule-bundles", http.MethodPost, shared.CreateRuleBundleRequest{
		TenantID:    "tenant-a",
		Version:     "suricata-disabled",
		Description: "Disabled rule set",
		Enabled:     false,
	}, &disabledRuleBundle, http.StatusCreated, authHeader)

	doJSON(t, handler, "/api/v1/probe-bindings", http.MethodPost, shared.ApplyProbeBindingRequest{
		TenantID:      "tenant-a",
		ProbeID:       probe.ID,
		ProbeConfigID: probeConfig.ID,
		RuleBundleID:  disabledRuleBundle.ID,
	}, &probeBinding, http.StatusCreated, authHeader)

	var failed shared.DeploymentRecord
	doJSON(t, handler, "/api/v1/deployments/ack", http.MethodPost, shared.DeploymentAckRequest{
		TenantID:      "tenant-a",
		ProbeID:       probe.ID,
		ProbeConfigID: probeConfig.ID,
		RuleBundleID:  disabledRuleBundle.ID,
		Status:        "failed",
		Message:       "rule bundle is disabled",
	}, &failed, http.StatusCreated, "")
	if failed.Status != "failed" {
		t.Fatalf("expected failed deployment status, got %s", failed.Status)
	}

	doJSON(t, handler, "/api/v1/deployments?tenant_id=tenant-a", http.MethodGet, nil, &deployments, http.StatusOK, authHeader)
	if len(deployments) != 5 {
		t.Fatalf("expected 5 deployment records after success, failure, and batch apply, got %d", len(deployments))
	}
	doJSON(t, handler, "/api/v1/deployments?tenant_id=tenant-a&probe_id="+probe.ID+"&status=failed&limit=2", http.MethodGet, nil, &deployments, http.StatusOK, authHeader)
	if len(deployments) != 1 || deployments[0].Status != "failed" {
		t.Fatalf("unexpected filtered deployments: %+v", deployments)
	}

	doJSON(t, handler, "/api/v1/probes?tenant_id=tenant-a", http.MethodGet, nil, &probes, http.StatusOK, authHeader)
	if probes[0].AppliedRuleID != ruleBundle.ID || probes[0].LastDeployStatus != "failed" {
		t.Fatalf("unexpected probe state after failed deployment: %+v", probes[0])
	}

	var tickets shared.TicketListResponse
	doJSON(t, handler, "/api/v1/tickets?tenant_id=tenant-a&page=1&page_size=1", http.MethodGet, nil, &tickets, http.StatusOK, authHeader)
	if len(tickets.Items) != 1 || tickets.Total == 0 {
		t.Fatalf("unexpected paged tickets response: %+v", tickets)
	}

	var stats shared.DashboardStats
	doJSON(t, handler, "/api/v1/dashboard/stats?tenant_id=tenant-a", http.MethodGet, nil, &stats, http.StatusOK, authHeader)
	if stats.ProbesOnline == 0 || stats.AlertsOpen == 0 {
		t.Fatalf("unexpected dashboard stats: %+v", stats)
	}

	var report shared.ReportSummary
	doJSON(t, handler, "/api/v1/reports/summary?tenant_id=tenant-a", http.MethodGet, nil, &report, http.StatusOK, authHeader)
	if len(report.AlertTrend) == 0 {
		t.Fatal("expected alert trend data")
	}

	var queryStats []shared.QueryStat
	doJSON(t, handler, "/api/v1/query-stats", http.MethodGet, nil, &queryStats, http.StatusOK, authHeader)
	if len(queryStats) == 0 {
		t.Fatal("expected query stats to be present")
	}

	var notifyChannels []shared.NotificationChannel
	doJSON(t, handler, "/api/v1/notifications/channels?tenant_id=tenant-a", http.MethodGet, nil, &notifyChannels, http.StatusOK, authHeader)
	if len(notifyChannels) != 1 {
		t.Fatalf("expected 1 notification channel, got %d", len(notifyChannels))
	}
	var notifyRecords []shared.NotificationRecord
	doJSON(t, handler, "/api/v1/notifications/records?tenant_id=tenant-a", http.MethodGet, nil, &notifyRecords, http.StatusOK, authHeader)
	if len(notifyRecords) < 3 {
		t.Fatalf("expected at least 3 notification records, got %d", len(notifyRecords))
	}
	if notifyRecords[0].ChannelID != notifyChannel.ID {
		t.Fatalf("unexpected notification channel id: %+v", notifyRecords[0])
	}

	var exportTask shared.ExportTask
	doJSON(t, handler, "/api/v1/exports", http.MethodPost, shared.ExportTaskRequest{
		TenantID:     "tenant-a",
		ResourceType: "alerts",
		Format:       "json",
		AlertQuery: shared.AlertQuery{
			Status: "in_progress",
		},
	}, &exportTask, http.StatusCreated, authHeader)
	if exportTask.Status != "pending" {
		t.Fatalf("unexpected initial export task status: %+v", exportTask)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		doJSON(t, handler, "/api/v1/exports/"+exportTask.ID, http.MethodGet, nil, &exportTask, http.StatusOK, authHeader)
		if exportTask.Status == "completed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if exportTask.Status != "completed" {
		t.Fatalf("expected completed export task, got %+v", exportTask)
	}
	if exportTask.FilePath == "" {
		t.Fatal("expected export task file path")
	}
	var exportTasks []shared.ExportTask
	doJSON(t, handler, "/api/v1/exports?tenant_id=tenant-a", http.MethodGet, nil, &exportTasks, http.StatusOK, authHeader)
	if len(exportTasks) == 0 {
		t.Fatal("expected export tasks list")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/exports/"+exportTask.ID+"/download", nil)
	req.Header.Set("Authorization", authHeader)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Result().StatusCode != http.StatusOK {
		t.Fatalf("unexpected export download status: %d", recorder.Result().StatusCode)
	}

	var flowExport shared.ExportTask
	doJSON(t, handler, "/api/v1/exports", http.MethodPost, shared.ExportTaskRequest{
		TenantID:     "tenant-a",
		ResourceType: "flows",
		Format:       "csv",
		FlowQuery: shared.FlowQuery{
			SrcIP: "10.0.0.1",
		},
	}, &flowExport, http.StatusCreated, authHeader)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		doJSON(t, handler, "/api/v1/exports/"+flowExport.ID, http.MethodGet, nil, &flowExport, http.StatusOK, authHeader)
		if flowExport.Status == "completed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/exports/"+flowExport.ID+"/download", nil)
	req.Header.Set("Authorization", authHeader)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Result().StatusCode != http.StatusOK {
		t.Fatalf("unexpected csv export download status: %d", recorder.Result().StatusCode)
	}
	if !strings.Contains(recorder.Body.String(), "flow_id") {
		t.Fatalf("expected csv export body, got %s", recorder.Body.String())
	}
}

func TestProbeReconnectReusesExistingProbe(t *testing.T) {
	t.Setenv("APP_EXPORT_DIR", t.TempDir())
	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	registerBody := shared.RegisterProbeRequest{
		TenantID:    "tenant-probe",
		ProbeCode:   "probe-stable-01",
		Name:        "Stable Probe",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}

	var first shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, registerBody, &first, http.StatusCreated, "")
	time.Sleep(5 * time.Millisecond)

	var second shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, registerBody, &second, http.StatusCreated, "")

	if first.ID != second.ID {
		t.Fatalf("expected reconnect to reuse probe id, got first=%s second=%s", first.ID, second.ID)
	}

	var login shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &login, http.StatusOK, "")
	authHeader := "Bearer " + login.Token

	var probes []shared.Probe
	doJSON(t, handler, "/api/v1/probes?tenant_id=tenant-probe", http.MethodGet, nil, &probes, http.StatusOK, authHeader)
	if len(probes) != 1 {
		t.Fatalf("expected one visible probe after reconnect, got %d", len(probes))
	}
	if probes[0].ProbeCode != registerBody.ProbeCode {
		t.Fatalf("unexpected probe code: %+v", probes[0])
	}
}

func TestProbeBecomesOfflineAfterHeartbeatTimeout(t *testing.T) {
	t.Setenv("APP_EXPORT_DIR", t.TempDir())
	t.Setenv("APP_PROBE_OFFLINE_AFTER", "20ms")
	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-offline",
		ProbeCode:   "probe-offline-01",
		Name:        "Offline Probe",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probe, http.StatusCreated, "")

	time.Sleep(40 * time.Millisecond)

	var login shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &login, http.StatusOK, "")
	authHeader := "Bearer " + login.Token

	var probes []shared.Probe
	doJSON(t, handler, "/api/v1/probes?tenant_id=tenant-offline", http.MethodGet, nil, &probes, http.StatusOK, authHeader)
	if len(probes) != 1 {
		t.Fatalf("expected one probe, got %d", len(probes))
	}
	if probes[0].Status != "offline" {
		t.Fatalf("expected probe to be offline after timeout, got %s", probes[0].Status)
	}

	var detail shared.ProbeDetail
	doJSON(t, handler, "/api/v1/probes/"+probe.ID, http.MethodGet, nil, &detail, http.StatusOK, authHeader)
	if detail.Probe.Status != "offline" {
		t.Fatalf("expected probe detail to show offline, got %s", detail.Probe.Status)
	}
}

func TestExportTaskExpires(t *testing.T) {
	t.Setenv("APP_EXPORT_DIR", t.TempDir())
	t.Setenv("APP_EXPORT_TTL", "100ms")
	t.Setenv("APP_EXPORT_CLEANUP_INTERVAL", "50ms")

	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var login shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &login, http.StatusOK, "")
	authHeader := "Bearer " + login.Token

	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-expire",
		ProbeCode:   "probe-expire-01",
		Name:        "Probe Expire",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probe, http.StatusCreated, "")
	doJSON(t, handler, "/api/v1/events/ingest", http.MethodPost, shared.EventBatch{
		TenantID: "tenant-expire",
		ProbeID:  probe.ID,
		Events: []shared.SuricataEvent{{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "alert",
			SrcIP:     "10.1.0.1",
			SrcPort:   1001,
			DstIP:     "192.168.2.1",
			DstPort:   443,
			Proto:     "TCP",
			AppProto:  "tls",
			FlowID:    "flow-expire-1",
			Alert: &shared.SuricataAlert{
				SignatureID: 9999,
				Signature:   "Expire Export Test",
				Category:    "Test",
				Severity:    1,
			},
		}},
	}, nil, http.StatusAccepted, "")

	var task shared.ExportTask
	doJSON(t, handler, "/api/v1/exports", http.MethodPost, shared.ExportTaskRequest{
		TenantID:     "tenant-expire",
		ResourceType: "alerts",
		Format:       "json",
		AlertQuery: shared.AlertQuery{
			Status: "",
		},
	}, &task, http.StatusCreated, authHeader)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		doJSON(t, handler, "/api/v1/exports/"+task.ID, http.MethodGet, nil, &task, http.StatusOK, authHeader)
		if task.Status == "expired" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if task.Status != "expired" {
		t.Fatalf("expected expired export task, got %+v", task)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/exports/"+task.ID+"/download", nil)
	req.Header.Set("Authorization", authHeader)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Result().StatusCode != http.StatusConflict {
		t.Fatalf("expected expired export download conflict, got %d", recorder.Result().StatusCode)
	}
}

func doJSON(t *testing.T, handler http.Handler, path, method string, body any, out any, wantStatus int, authHeader string) {
	t.Helper()

	var reqPayload io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reqPayload = bytes.NewReader(payload)
	} else {
		reqPayload = http.NoBody
	}

	req := httptest.NewRequest(method, path, reqPayload)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != wantStatus {
		t.Fatalf("unexpected status: got=%d want=%d", resp.StatusCode, wantStatus)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSuppressionRuleAndRiskPolicy(t *testing.T) {
	t.Setenv("APP_EXPORT_DIR", t.TempDir())
	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var login shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &login, http.StatusOK, "")
	authHeader := "Bearer " + login.Token

	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-policy",
		ProbeCode:   "probe-policy-01",
		Name:        "Policy Probe",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probe, http.StatusCreated, "")

	var suppression shared.SuppressionRule
	doJSON(t, handler, "/api/v1/suppression-rules", http.MethodPost, shared.CreateSuppressionRuleRequest{
		TenantID: "tenant-policy",
		Name:     "suppress-src",
		SrcIP:    "172.16.1.10",
		Enabled:  true,
	}, &suppression, http.StatusCreated, authHeader)
	if suppression.ID == "" {
		t.Fatal("expected suppression rule id")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	doJSON(t, handler, "/api/v1/events/ingest", http.MethodPost, shared.EventBatch{
		TenantID: "tenant-policy",
		ProbeID:  probe.ID,
		Events: []shared.SuricataEvent{{
			Timestamp: now,
			EventType: "alert",
			SrcIP:     "172.16.1.10",
			SrcPort:   43000,
			DstIP:     "192.168.10.10",
			DstPort:   443,
			Proto:     "TCP",
			AppProto:  "tls",
			FlowID:    "suppressed-flow-1",
			Alert: &shared.SuricataAlert{
				SignatureID: 2001,
				Signature:   "Suppressed Match",
				Category:    "Policy Test",
				Severity:    1,
			},
		}},
	}, nil, http.StatusAccepted, "")

	var alerts shared.AlertListResponse
	doJSON(t, handler, "/api/v1/alerts?tenant_id=tenant-policy", http.MethodGet, nil, &alerts, http.StatusOK, authHeader)
	if len(alerts.Items) != 0 {
		t.Fatalf("expected suppressed alert to be dropped, got %d alerts", len(alerts.Items))
	}

	var asset shared.Asset
	doJSON(t, handler, "/api/v1/assets", http.MethodPost, shared.CreateAssetRequest{
		TenantID:        "tenant-policy",
		Name:            "Critical API",
		IP:              "192.168.10.20",
		AssetType:       "server",
		ImportanceLevel: "critical",
		Owner:           "soc",
	}, &asset, http.StatusCreated, authHeader)

	var intel shared.ThreatIntel
	doJSON(t, handler, "/api/v1/threat-intel", http.MethodPost, shared.CreateThreatIntelRequest{
		TenantID: "tenant-policy",
		Type:     "ip",
		Value:    "10.10.10.10",
		Severity: "high",
		Source:   "manual",
		Tags:     []string{"c2"},
	}, &intel, http.StatusCreated, authHeader)

	var policy shared.RiskPolicy
	doJSON(t, handler, "/api/v1/risk-policies", http.MethodPost, shared.CreateRiskPolicyRequest{
		TenantID:           "tenant-policy",
		Name:               "custom-policy",
		Severity1Score:     30,
		Severity2Score:     20,
		Severity3Score:     10,
		DefaultScore:       5,
		IntelHitBonus:      5,
		CriticalAssetBonus: 7,
		Enabled:            true,
	}, &policy, http.StatusCreated, authHeader)
	if policy.ID == "" {
		t.Fatal("expected risk policy id")
	}

	doJSON(t, handler, "/api/v1/events/ingest", http.MethodPost, shared.EventBatch{
		TenantID: "tenant-policy",
		ProbeID:  probe.ID,
		Events: []shared.SuricataEvent{{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "alert",
			SrcIP:     "10.10.10.10",
			SrcPort:   51000,
			DstIP:     "192.168.10.20",
			DstPort:   8443,
			Proto:     "TCP",
			AppProto:  "http2",
			FlowID:    "risk-flow-1",
			Alert: &shared.SuricataAlert{
				SignatureID: 3001,
				Signature:   "Risk Policy Match",
				Category:    "Risk Test",
				Severity:    1,
			},
		}},
	}, nil, http.StatusAccepted, "")

	doJSON(t, handler, "/api/v1/alerts?tenant_id=tenant-policy", http.MethodGet, nil, &alerts, http.StatusOK, authHeader)
	if len(alerts.Items) != 1 {
		t.Fatalf("expected 1 alert after risk policy ingest, got %d", len(alerts.Items))
	}
	if alerts.Items[0].RiskScore != 42 {
		t.Fatalf("expected risk score 42, got %d", alerts.Items[0].RiskScore)
	}

	var suppressionRules []shared.SuppressionRule
	doJSON(t, handler, "/api/v1/suppression-rules?tenant_id=tenant-policy", http.MethodGet, nil, &suppressionRules, http.StatusOK, authHeader)
	if len(suppressionRules) != 1 {
		t.Fatalf("expected 1 suppression rule, got %d", len(suppressionRules))
	}

	var riskPolicies []shared.RiskPolicy
	doJSON(t, handler, "/api/v1/risk-policies?tenant_id=tenant-policy", http.MethodGet, nil, &riskPolicies, http.StatusOK, authHeader)
	if len(riskPolicies) != 1 {
		t.Fatalf("expected 1 risk policy, got %d", len(riskPolicies))
	}
}

func TestJWTAuthMode(t *testing.T) {
	t.Setenv("APP_AUTH_MODE", "jwt")
	t.Setenv("APP_JWT_SECRET", "test-secret-key")

	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var login shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &login, http.StatusOK, "")
	if strings.Count(login.Token, ".") != 2 {
		t.Fatalf("expected jwt-style token, got %s", login.Token)
	}

	var me shared.User
	doJSON(t, handler, "/api/v1/auth/me", http.MethodGet, nil, &me, http.StatusOK, "Bearer "+login.Token)
	if me.Username != "admin" {
		t.Fatalf("unexpected current user: %+v", me)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.value")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized for invalid jwt, got %d", recorder.Result().StatusCode)
	}
}

func TestDataScopeEnforcement(t *testing.T) {
	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var admin shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &admin, http.StatusOK, "")
	adminAuth := "Bearer " + admin.Token

	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-scope",
		ProbeCode:   "probe-scope-01",
		Name:        "Probe Scope",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probe, http.StatusCreated, "")
	doJSON(t, handler, "/api/v1/events/ingest", http.MethodPost, shared.EventBatch{
		TenantID: "tenant-scope",
		ProbeID:  probe.ID,
		Events: []shared.SuricataEvent{{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "alert",
			SrcIP:     "10.5.0.1",
			SrcPort:   1234,
			DstIP:     "192.168.5.5",
			DstPort:   80,
			Proto:     "TCP",
			AppProto:  "http",
			FlowID:    "flow-scope-1",
			Alert:     &shared.SuricataAlert{SignatureID: 5001, Signature: "Scope Alert", Category: "Test", Severity: 2},
		}},
	}, nil, http.StatusAccepted, "")

	var role shared.Role
	doJSON(t, handler, "/api/v1/roles", http.MethodPost, shared.CreateRoleRequest{
		TenantID:    "tenant-scope",
		Name:        "scope-analyst",
		Description: "Scoped analyst",
		Permissions: []string{"alert.read", "probe.read", "ticket.read"},
	}, &role, http.StatusCreated, adminAuth)

	var user shared.User
	doJSON(t, handler, "/api/v1/users", http.MethodPost, shared.CreateUserRequest{
		TenantID:        "tenant-scope",
		Username:        "scoped",
		DisplayName:     "Scoped User",
		Password:        "scope123",
		Roles:           []string{role.Name},
		AllowedTenants:  []string{"tenant-scope"},
		AllowedProbeIDs: []string{probe.ID},
	}, &user, http.StatusCreated, adminAuth)

	var login shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "tenant-scope",
		Username: "scoped",
		Password: "scope123",
	}, &login, http.StatusOK, "")
	auth := "Bearer " + login.Token

	var alerts shared.AlertListResponse
	doJSON(t, handler, "/api/v1/alerts?tenant_id=tenant-scope", http.MethodGet, nil, &alerts, http.StatusOK, auth)
	if len(alerts.Items) != 1 {
		t.Fatalf("expected scoped user to see 1 alert, got %d", len(alerts.Items))
	}
	doJSON(t, handler, "/api/v1/alerts?tenant_id=demo-tenant", http.MethodGet, nil, nil, http.StatusForbidden, auth)
}

func TestTicketSLABreach(t *testing.T) {
	t.Setenv("APP_SLA_HIGH", "50ms")
	t.Setenv("APP_TICKET_SLA_SCAN_INTERVAL", "20ms")

	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var admin shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &admin, http.StatusOK, "")
	auth := "Bearer " + admin.Token

	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-sla",
		ProbeCode:   "probe-sla-01",
		Name:        "Probe SLA",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probe, http.StatusCreated, "")
	doJSON(t, handler, "/api/v1/events/ingest", http.MethodPost, shared.EventBatch{
		TenantID: "tenant-sla",
		ProbeID:  probe.ID,
		Events: []shared.SuricataEvent{{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "alert",
			SrcIP:     "10.6.0.1",
			SrcPort:   8080,
			DstIP:     "192.168.6.6",
			DstPort:   443,
			Proto:     "TCP",
			AppProto:  "tls",
			FlowID:    "flow-sla-1",
			Alert:     &shared.SuricataAlert{SignatureID: 6001, Signature: "SLA Alert", Category: "Test", Severity: 1},
		}},
	}, nil, http.StatusAccepted, "")

	var alerts shared.AlertListResponse
	doJSON(t, handler, "/api/v1/alerts?tenant_id=tenant-sla", http.MethodGet, nil, &alerts, http.StatusOK, auth)

	var _channel shared.NotificationChannel
	doJSON(t, handler, "/api/v1/notifications/channels", http.MethodPost, shared.CreateNotificationChannelRequest{
		TenantID: "tenant-sla",
		Name:     "sla-console",
		Type:     "console",
		Enabled:  true,
		Events:   []string{"ticket.sla_breach"},
	}, &_channel, http.StatusCreated, auth)

	var ticket shared.Ticket
	doJSON(t, handler, "/api/v1/tickets", http.MethodPost, shared.CreateTicketRequest{
		TenantID:    "tenant-sla",
		AlertID:     alerts.Items[0].ID,
		Title:       "SLA Ticket",
		Description: "SLA breach test",
		Priority:    "high",
		Assignee:    "analyst-1",
	}, &ticket, http.StatusCreated, auth)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var detail shared.TicketDetail
		doJSON(t, handler, "/api/v1/tickets/"+ticket.ID, http.MethodGet, nil, &detail, http.StatusOK, auth)
		if detail.Ticket.SLAStatus == "breached" {
			var records []shared.NotificationRecord
			doJSON(t, handler, "/api/v1/notifications/records?tenant_id=tenant-sla", http.MethodGet, nil, &records, http.StatusOK, auth)
			if len(records) > 0 {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("expected ticket SLA breach and notification record")
}

func TestTicketAutomationReminderAndEscalation(t *testing.T) {
	t.Setenv("APP_SLA_CRITICAL", "80ms")
	t.Setenv("APP_TICKET_SLA_SCAN_INTERVAL", "20ms")

	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var admin shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &admin, http.StatusOK, "")
	auth := "Bearer " + admin.Token

	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-auto",
		ProbeCode:   "probe-auto-01",
		Name:        "Probe Auto",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probe, http.StatusCreated, "")
	doJSON(t, handler, "/api/v1/events/ingest", http.MethodPost, shared.EventBatch{
		TenantID: "tenant-auto",
		ProbeID:  probe.ID,
		Events: []shared.SuricataEvent{{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "alert",
			SrcIP:     "10.7.0.1",
			SrcPort:   9090,
			DstIP:     "192.168.7.7",
			DstPort:   443,
			Proto:     "TCP",
			AppProto:  "tls",
			FlowID:    "flow-auto-1",
			Alert:     &shared.SuricataAlert{SignatureID: 7001, Signature: "AUTO Alert", Category: "Test", Severity: 1},
		}},
	}, nil, http.StatusAccepted, "")

	var alerts shared.AlertListResponse
	doJSON(t, handler, "/api/v1/alerts?tenant_id=tenant-auto", http.MethodGet, nil, &alerts, http.StatusOK, auth)

	var _channel shared.NotificationChannel
	doJSON(t, handler, "/api/v1/notifications/channels", http.MethodPost, shared.CreateNotificationChannelRequest{
		TenantID: "tenant-auto",
		Name:     "auto-console",
		Type:     "console",
		Enabled:  true,
		Events:   []string{"ticket.reminder", "ticket.escalated"},
	}, &_channel, http.StatusCreated, auth)

	var policy shared.TicketAutomationPolicy
	doJSON(t, handler, "/api/v1/ticket-automation-policies", http.MethodPost, shared.CreateTicketAutomationPolicyRequest{
		TenantID:            "tenant-auto",
		Name:                "default-ticket-auto",
		ReminderBeforeMins:  1,
		EscalationAfterMins: 0,
		EscalationAssignee:  "team-lead",
		EscalationStatus:    "escalated",
		Enabled:             true,
	}, &policy, http.StatusCreated, auth)

	var policies []shared.TicketAutomationPolicy
	doJSON(t, handler, "/api/v1/ticket-automation-policies?tenant_id=tenant-auto", http.MethodGet, nil, &policies, http.StatusOK, auth)
	if len(policies) != 1 {
		t.Fatalf("expected 1 automation policy, got %d", len(policies))
	}

	var ticket shared.Ticket
	doJSON(t, handler, "/api/v1/tickets", http.MethodPost, shared.CreateTicketRequest{
		TenantID:    "tenant-auto",
		AlertID:     alerts.Items[0].ID,
		Title:       "AUTO Ticket",
		Description: "Automation test",
		Priority:    "critical",
		Assignee:    "analyst-1",
	}, &ticket, http.StatusCreated, auth)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var detail shared.TicketDetail
		doJSON(t, handler, "/api/v1/tickets/"+ticket.ID, http.MethodGet, nil, &detail, http.StatusOK, auth)
		if !detail.Ticket.RemindedAt.IsZero() && !detail.Ticket.EscalatedAt.IsZero() && detail.Ticket.Assignee == "team-lead" && detail.Ticket.Status == "escalated" {
			var records []shared.NotificationRecord
			doJSON(t, handler, "/api/v1/notifications/records?tenant_id=tenant-auto", http.MethodGet, nil, &records, http.StatusOK, auth)
			seenReminder := false
			seenEscalation := false
			for _, record := range records {
				if record.EventType == "ticket.reminder" {
					seenReminder = true
				}
				if record.EventType == "ticket.escalated" {
					seenEscalation = true
				}
			}
			if seenReminder && seenEscalation {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("expected ticket reminder and escalation to run")
}

func TestProbeUpgradeTaskFlow(t *testing.T) {
	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var admin shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &admin, http.StatusOK, "")
	auth := "Bearer " + admin.Token

	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-upgrade",
		ProbeCode:   "probe-upgrade-01",
		Name:        "Probe Upgrade",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probe, http.StatusCreated, "")

	var pkg shared.UpgradePackage
	doJSON(t, handler, "/api/v1/upgrade-packages", http.MethodPost, shared.CreateUpgradePackageRequest{
		TenantID:   "tenant-upgrade",
		Version:    "0.2.0",
		PackageURL: "https://example.com/probe-0.2.0.tar.gz",
		Checksum:   "sha256:demo",
		Notes:      "first rollout",
		Enabled:    true,
	}, &pkg, http.StatusCreated, auth)

	var task shared.ProbeUpgradeTask
	doJSON(t, handler, "/api/v1/probe-upgrades", http.MethodPost, shared.CreateProbeUpgradeTaskRequest{
		TenantID:      "tenant-upgrade",
		ProbeID:       probe.ID,
		Action:        "upgrade",
		TargetVersion: "0.2.0",
		MaxRetries:    1,
	}, &task, http.StatusCreated, auth)
	if task.PackageID != pkg.ID {
		t.Fatalf("expected package id %s, got %s", pkg.ID, task.PackageID)
	}
	if task.Status != "pending" {
		t.Fatalf("expected pending task, got %+v", task)
	}

	var pending shared.ProbeUpgradeTask
	doJSON(t, handler, "/api/v1/probes/"+probe.ID+"/upgrade-task", http.MethodGet, nil, &pending, http.StatusOK, "")
	if pending.ID != task.ID {
		t.Fatalf("unexpected pending task: %+v", pending)
	}

	var updatedTask shared.ProbeUpgradeTask
	doJSON(t, handler, "/api/v1/probe-upgrades/ack", http.MethodPost, shared.ProbeUpgradeAckRequest{
		TenantID:      "tenant-upgrade",
		ProbeID:       probe.ID,
		Action:        "upgrade",
		TargetVersion: "0.2.0",
		Status:        "failed",
		Message:       "temporary network failure",
	}, &updatedTask, http.StatusCreated, "")
	if updatedTask.Status != "pending" || updatedTask.RetryCount != 1 {
		t.Fatalf("expected task to stay pending after first failure, got %+v", updatedTask)
	}

	doJSON(t, handler, "/api/v1/probe-upgrades/ack", http.MethodPost, shared.ProbeUpgradeAckRequest{
		TenantID:      "tenant-upgrade",
		ProbeID:       probe.ID,
		Action:        "upgrade",
		TargetVersion: "0.2.0",
		Status:        "applied",
		Message:       "probe upgraded successfully",
	}, &updatedTask, http.StatusCreated, "")
	if updatedTask.Status != "applied" {
		t.Fatalf("expected applied task status, got %+v", updatedTask)
	}

	var probes []shared.Probe
	doJSON(t, handler, "/api/v1/probes?tenant_id=tenant-upgrade", http.MethodGet, nil, &probes, http.StatusOK, auth)
	if len(probes) != 1 || probes[0].Version != "0.2.0" {
		t.Fatalf("expected probe version updated to 0.2.0, got %+v", probes)
	}

	var tasks []shared.ProbeUpgradeTask
	doJSON(t, handler, "/api/v1/probe-upgrades?tenant_id=tenant-upgrade", http.MethodGet, nil, &tasks, http.StatusOK, auth)
	if len(tasks) != 1 || tasks[0].Status != "applied" {
		t.Fatalf("unexpected upgrade tasks list: %+v", tasks)
	}

	var detail shared.ProbeDetail
	doJSON(t, handler, "/api/v1/probes/"+probe.ID, http.MethodGet, nil, &detail, http.StatusOK, auth)
	if len(detail.VersionHistory) == 0 || detail.VersionHistory[0].ToVersion != "0.2.0" {
		t.Fatalf("expected probe version history, got %+v", detail.VersionHistory)
	}
}

func TestUpgradePackagesAndBatchProbeUpgrades(t *testing.T) {
	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var login shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &login, http.StatusOK, "")
	auth := "Bearer " + login.Token

	var probeA shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-upgrade-batch",
		ProbeCode:   "probe-upgrade-02",
		Name:        "Probe Upgrade 02",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probeA, http.StatusCreated, "")

	var probeB shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-upgrade-batch",
		ProbeCode:   "probe-upgrade-03",
		Name:        "Probe Upgrade 03",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probeB, http.StatusCreated, "")

	var pkg shared.UpgradePackage
	doJSON(t, handler, "/api/v1/upgrade-packages", http.MethodPost, shared.CreateUpgradePackageRequest{
		TenantID:   "tenant-upgrade-batch",
		Version:    "0.3.0",
		PackageURL: "https://example.com/probe-0.3.0.tar.gz",
		Checksum:   "sha256:batch",
		Notes:      "batch rollout",
		Enabled:    true,
	}, &pkg, http.StatusCreated, auth)

	var packages []shared.UpgradePackage
	doJSON(t, handler, "/api/v1/upgrade-packages?tenant_id=tenant-upgrade-batch", http.MethodGet, nil, &packages, http.StatusOK, auth)
	if len(packages) != 1 || packages[0].Version != "0.3.0" {
		t.Fatalf("expected listed package, got %+v", packages)
	}

	var resp shared.BatchCreateProbeUpgradeTaskResponse
	doJSON(t, handler, "/api/v1/probe-upgrades/batch", http.MethodPost, shared.BatchCreateProbeUpgradeTaskRequest{
		TenantID:      "tenant-upgrade-batch",
		ProbeIDs:      []string{probeA.ID, probeB.ID},
		Action:        "upgrade",
		TargetVersion: "0.3.0",
		MaxRetries:    2,
	}, &resp, http.StatusCreated, auth)
	if resp.Requested != 2 || resp.Applied != 2 || len(resp.Items) != 2 {
		t.Fatalf("unexpected batch response: %+v", resp)
	}
	for _, item := range resp.Items {
		if item.PackageID != pkg.ID {
			t.Fatalf("expected package id %s, got %+v", pkg.ID, item)
		}
	}

	var tasks []shared.ProbeUpgradeTask
	doJSON(t, handler, "/api/v1/probe-upgrades?tenant_id=tenant-upgrade-batch", http.MethodGet, nil, &tasks, http.StatusOK, auth)
	if len(tasks) != 2 {
		t.Fatalf("expected 2 batch tasks, got %d", len(tasks))
	}
}

func TestNotificationTemplateAndRetry(t *testing.T) {
	t.Setenv("APP_NOTIFY_RETRY_MAX", "1")
	t.Setenv("APP_NOTIFY_RETRY_BACKOFF", "10ms")
	t.Setenv("APP_NOTIFY_RETRY_SCAN_INTERVAL", "50ms")

	var hits atomic.Int32
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	handler, cleanup, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var admin shared.LoginResponse
	doJSON(t, handler, "/api/v1/auth/login", http.MethodPost, shared.LoginRequest{
		TenantID: "demo-tenant",
		Username: "admin",
		Password: "admin123",
	}, &admin, http.StatusOK, "")
	auth := "Bearer " + admin.Token

	var probe shared.Probe
	doJSON(t, handler, "/api/v1/probes/register", http.MethodPost, shared.RegisterProbeRequest{
		TenantID:    "tenant-notify",
		ProbeCode:   "probe-notify-01",
		Name:        "Probe Notify",
		Version:     "0.1.0",
		RuleVersion: "rules-v1",
	}, &probe, http.StatusCreated, "")
	doJSON(t, handler, "/api/v1/events/ingest", http.MethodPost, shared.EventBatch{
		TenantID: "tenant-notify",
		ProbeID:  probe.ID,
		Events: []shared.SuricataEvent{{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "alert",
			SrcIP:     "10.7.0.1",
			SrcPort:   9090,
			DstIP:     "192.168.7.7",
			DstPort:   8443,
			Proto:     "TCP",
			AppProto:  "tls",
			FlowID:    "flow-notify-1",
			Alert:     &shared.SuricataAlert{SignatureID: 7001, Signature: "Notify Alert", Category: "Test", Severity: 1},
		}},
	}, nil, http.StatusAccepted, "")

	var alerts shared.AlertListResponse
	doJSON(t, handler, "/api/v1/alerts?tenant_id=tenant-notify", http.MethodGet, nil, &alerts, http.StatusOK, auth)

	var tmpl shared.NotificationTemplate
	doJSON(t, handler, "/api/v1/notifications/templates", http.MethodPost, shared.CreateNotificationTemplateRequest{
		TenantID:      "tenant-notify",
		Name:          "alert-template",
		EventType:     "alert.updated",
		TitleTemplate: "{{event_type}} {{resource_id}}",
		BodyTemplate:  "status={{status}} signature={{signature}}",
	}, &tmpl, http.StatusCreated, auth)

	var channel shared.NotificationChannel
	doJSON(t, handler, "/api/v1/notifications/channels", http.MethodPost, shared.CreateNotificationChannelRequest{
		TenantID: "tenant-notify",
		Name:     "webhook-retry",
		Type:     "webhook",
		Target:   webhook.URL,
		Enabled:  true,
		Events:   []string{"alert.updated"},
	}, &channel, http.StatusCreated, auth)

	var alert shared.Alert
	doJSON(t, handler, "/api/v1/alerts/"+alerts.Items[0].ID, http.MethodPatch, shared.UpdateAlertStatusRequest{
		Status:   "ack",
		Assignee: "analyst-1",
	}, &alert, http.StatusOK, auth)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var records []shared.NotificationRecord
		doJSON(t, handler, "/api/v1/notifications/records?tenant_id=tenant-notify", http.MethodGet, nil, &records, http.StatusOK, auth)
		if len(records) > 0 && records[0].Status == "sent" && strings.Contains(records[0].Summary, "signature=Notify Alert") {
			if hits.Load() >= 3 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("expected notification retry to succeed with rendered template")
}
