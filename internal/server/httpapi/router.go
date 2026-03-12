package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/yan/ndr-platform/internal/server/service"
	"github.com/yan/ndr-platform/internal/shared"
)

type Router struct {
	service *service.Service
	mux     *http.ServeMux
}

type contextKey string

const currentUserKey contextKey = "current_user"

//go:embed web/*
var webFS embed.FS

func New(service *service.Service) *Router {
	r := &Router{
		service: service,
		mux:     http.NewServeMux(),
	}
	r.register()
	return r
}

func (r *Router) Handler() http.Handler {
	return loggingMiddleware(authMiddleware(r.service, r.mux))
}

func (r *Router) register() {
	webSub, _ := fs.Sub(webFS, "web")
	r.mux.Handle("/", http.FileServer(http.FS(webSub)))
	r.mux.HandleFunc("GET /healthz", r.handleHealth)
	r.mux.HandleFunc("GET /api/v1/dashboard/stats", r.handleDashboardStats)
	r.mux.HandleFunc("GET /api/v1/dashboard/workbench", r.handleDashboardWorkbench)
	r.mux.HandleFunc("GET /api/v1/reports/summary", r.handleReportSummary)
	r.mux.HandleFunc("POST /api/v1/probes/register", r.handleRegisterProbe)
	r.mux.HandleFunc("POST /api/v1/probes/heartbeat", r.handleHeartbeat)
	r.mux.HandleFunc("GET /api/v1/probes", r.handleListProbes)
	r.mux.HandleFunc("GET /api/v1/probes/{id}", r.handleGetProbe)
	r.mux.HandleFunc("GET /api/v1/probes/{id}/metrics", r.handleListProbeMetrics)
	r.mux.HandleFunc("GET /api/v1/probes/{id}/binding", r.handleGetProbeBinding)
	r.mux.HandleFunc("GET /api/v1/probes/{id}/upgrade-task", r.handleGetProbeUpgradeTask)
	r.mux.HandleFunc("POST /api/v1/probe-configs", r.handleCreateProbeConfig)
	r.mux.HandleFunc("GET /api/v1/probe-configs", r.handleListProbeConfigs)
	r.mux.HandleFunc("POST /api/v1/rule-bundles", r.handleCreateRuleBundle)
	r.mux.HandleFunc("GET /api/v1/rule-bundles", r.handleListRuleBundles)
	r.mux.HandleFunc("POST /api/v1/probe-bindings", r.handleApplyProbeBinding)
	r.mux.HandleFunc("POST /api/v1/probe-bindings/batch", r.handleBatchApplyProbeBinding)
	r.mux.HandleFunc("GET /api/v1/probe-bindings", r.handleListProbeBindings)
	r.mux.HandleFunc("GET /api/v1/deployments", r.handleListDeployments)
	r.mux.HandleFunc("POST /api/v1/deployments/ack", r.handleAcknowledgeDeployment)
	r.mux.HandleFunc("POST /api/v1/upgrade-packages", r.handleCreateUpgradePackage)
	r.mux.HandleFunc("POST /api/v1/upgrade-packages/upload", r.handleUploadUpgradePackage)
	r.mux.HandleFunc("GET /api/v1/upgrade-packages", r.handleListUpgradePackages)
	r.mux.HandleFunc("GET /api/v1/upgrade-packages/{id}/download", r.handleDownloadUpgradePackage)
	r.mux.HandleFunc("POST /api/v1/probe-upgrades", r.handleCreateProbeUpgradeTask)
	r.mux.HandleFunc("POST /api/v1/probe-upgrades/batch", r.handleBatchCreateProbeUpgradeTask)
	r.mux.HandleFunc("GET /api/v1/probe-upgrades", r.handleListProbeUpgradeTasks)
	r.mux.HandleFunc("POST /api/v1/probe-upgrades/ack", r.handleAcknowledgeProbeUpgradeTask)
	r.mux.HandleFunc("POST /api/v1/events/ingest", r.handleIngest)
	r.mux.HandleFunc("GET /api/v1/alerts", r.handleListAlerts)
	r.mux.HandleFunc("GET /api/v1/raw-alerts", r.handleListRawAlerts)
	r.mux.HandleFunc("GET /api/v1/raw-alerts/{id}/detail", r.handleGetRawAlertDetail)
	r.mux.HandleFunc("POST /api/v1/alerts/batch", r.handleBatchUpdateAlerts)
	r.mux.HandleFunc("GET /api/v1/alerts/{id}", r.handleGetAlert)
	r.mux.HandleFunc("GET /api/v1/alerts/{id}/detail", r.handleGetAlertDetail)
	r.mux.HandleFunc("PATCH /api/v1/alerts/{id}", r.handleUpdateAlert)
	r.mux.HandleFunc("GET /api/v1/flows", r.handleListFlows)
	r.mux.HandleFunc("POST /api/v1/assets", r.handleCreateAsset)
	r.mux.HandleFunc("GET /api/v1/assets", r.handleListAssets)
	r.mux.HandleFunc("POST /api/v1/organizations", r.handleCreateOrganization)
	r.mux.HandleFunc("GET /api/v1/organizations", r.handleListOrganizations)
	r.mux.HandleFunc("POST /api/v1/threat-intel", r.handleCreateThreatIntel)
	r.mux.HandleFunc("GET /api/v1/threat-intel", r.handleListThreatIntel)
	r.mux.HandleFunc("POST /api/v1/suppression-rules", r.handleCreateSuppressionRule)
	r.mux.HandleFunc("GET /api/v1/suppression-rules", r.handleListSuppressionRules)
	r.mux.HandleFunc("POST /api/v1/risk-policies", r.handleCreateRiskPolicy)
	r.mux.HandleFunc("GET /api/v1/risk-policies", r.handleListRiskPolicies)
	r.mux.HandleFunc("POST /api/v1/ticket-automation-policies", r.handleCreateTicketAutomationPolicy)
	r.mux.HandleFunc("GET /api/v1/ticket-automation-policies", r.handleListTicketAutomationPolicies)
	r.mux.HandleFunc("POST /api/v1/tickets", r.handleCreateTicket)
	r.mux.HandleFunc("POST /api/v1/tickets/batch", r.handleBatchCreateTickets)
	r.mux.HandleFunc("GET /api/v1/tickets", r.handleListTickets)
	r.mux.HandleFunc("GET /api/v1/tickets/{id}", r.handleGetTicket)
	r.mux.HandleFunc("PATCH /api/v1/tickets/{id}", r.handleUpdateTicket)
	r.mux.HandleFunc("POST /api/v1/tickets/batch-update", r.handleBatchUpdateTickets)
	r.mux.HandleFunc("POST /api/v1/auth/login", r.handleLogin)
	r.mux.HandleFunc("GET /api/v1/auth/me", r.handleCurrentUser)
	r.mux.HandleFunc("POST /api/v1/users", r.handleCreateUser)
	r.mux.HandleFunc("GET /api/v1/users", r.handleListUsers)
	r.mux.HandleFunc("GET /api/v1/role-templates", r.handleListRoleTemplates)
	r.mux.HandleFunc("POST /api/v1/roles", r.handleCreateRole)
	r.mux.HandleFunc("GET /api/v1/roles", r.handleListRoles)
	r.mux.HandleFunc("GET /api/v1/audit/logs", r.handleListAuditLogs)
	r.mux.HandleFunc("GET /api/v1/query-stats", r.handleListQueryStats)
	r.mux.HandleFunc("POST /api/v1/notifications/channels", r.handleCreateNotificationChannel)
	r.mux.HandleFunc("GET /api/v1/notifications/channels", r.handleListNotificationChannels)
	r.mux.HandleFunc("POST /api/v1/notifications/templates", r.handleCreateNotificationTemplate)
	r.mux.HandleFunc("GET /api/v1/notifications/templates", r.handleListNotificationTemplates)
	r.mux.HandleFunc("GET /api/v1/notifications/records", r.handleListNotificationRecords)
	r.mux.HandleFunc("POST /api/v1/exports", r.handleCreateExportTask)
	r.mux.HandleFunc("GET /api/v1/exports", r.handleListExportTasks)
	r.mux.HandleFunc("GET /api/v1/exports/{id}", r.handleGetExportTask)
	r.mux.HandleFunc("GET /api/v1/exports/{id}/download", r.handleDownloadExportTask)
}

func (r *Router) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (r *Router) handleDashboardStats(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	stats, err := r.service.DashboardStatsForUser(req.Context(), operator, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (r *Router) handleDashboardWorkbench(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	if operator.ID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	workbench, err := r.service.DashboardWorkbench(req.Context(), operator)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, workbench)
}

func (r *Router) handleReportSummary(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	var since time.Time
	if raw := req.URL.Query().Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid since"})
			return
		}
		since = parsed
	}
	report, err := r.service.ReportSummaryForUser(req.Context(), operator, tenantID, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (r *Router) handleRegisterProbe(w http.ResponseWriter, req *http.Request) {
	var body shared.RegisterProbeRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	probe, err := r.service.RegisterProbe(req.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, probe)
}

func (r *Router) handleHeartbeat(w http.ResponseWriter, req *http.Request) {
	var body shared.HeartbeatRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	probe, ok, err := r.service.Heartbeat(req.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "probe not found"})
		return
	}
	writeJSON(w, http.StatusOK, probe)
}

func (r *Router) handleListProbes(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	probes, err := r.service.ListProbes(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, probes)
}

func (r *Router) handleGetProbe(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	id := req.PathValue("id")
	if !accessibleProbeOrDeny(w, operator, id) {
		return
	}
	detail, ok, err := r.service.GetProbeDetail(req.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "probe not found"})
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (r *Router) handleListProbeMetrics(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	id := req.PathValue("id")
	if !accessibleProbeOrDeny(w, operator, id) {
		return
	}
	query := shared.ProbeMetricQuery{
		ProbeID: id,
		Limit:   parseIntDefault(req.URL.Query().Get("limit"), 20),
	}
	if raw := req.URL.Query().Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid since"})
			return
		}
		query.Since = parsed
	}
	metrics, err := r.service.ListProbeMetrics(req.Context(), query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

func (r *Router) handleGetProbeBinding(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	detail, ok, err := r.service.GetProbeBindingDetail(req.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "probe binding not found"})
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (r *Router) handleGetProbeUpgradeTask(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	task, ok, err := r.service.GetPendingProbeUpgradeTask(req.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "probe upgrade task not found"})
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func (r *Router) handleCreateProbeConfig(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateProbeConfigRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	config, err := r.service.CreateProbeConfig(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, config)
}

func (r *Router) handleListProbeConfigs(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	configs, err := r.service.ListProbeConfigs(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, configs)
}

func (r *Router) handleCreateRuleBundle(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateRuleBundleRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	bundle, err := r.service.CreateRuleBundle(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, bundle)
}

func (r *Router) handleListRuleBundles(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	bundles, err := r.service.ListRuleBundles(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, bundles)
}

func (r *Router) handleApplyProbeBinding(w http.ResponseWriter, req *http.Request) {
	var body shared.ApplyProbeBindingRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	if !accessibleProbeOrDeny(w, operator, body.ProbeID) {
		return
	}
	binding, err := r.service.ApplyProbeBinding(req.Context(), body, operator.ID)
	if err != nil {
		if err.Error() == "probe not found" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, binding)
}

func (r *Router) handleBatchApplyProbeBinding(w http.ResponseWriter, req *http.Request) {
	var body shared.BatchApplyProbeBindingRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	for _, probeID := range body.ProbeIDs {
		if !accessibleProbeOrDeny(w, operator, probeID) {
			return
		}
	}
	items, err := r.service.BatchApplyProbeBinding(req.Context(), body, operator.ID)
	if err != nil {
		if err.Error() == "probe not found" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, items)
}

func (r *Router) handleListProbeBindings(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListProbeBindings(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleListDeployments(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	query := shared.DeploymentQuery{
		TenantID: tenantID,
		ProbeID:  req.URL.Query().Get("probe_id"),
		Status:   req.URL.Query().Get("status"),
		Limit:    parseIntDefault(req.URL.Query().Get("limit"), 100),
	}
	if raw := req.URL.Query().Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid since"})
			return
		}
		query.Since = parsed
	}
	items, err := r.service.ListDeploymentRecords(req.Context(), query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleAcknowledgeDeployment(w http.ResponseWriter, req *http.Request) {
	var body shared.DeploymentAckRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	record, err := r.service.AcknowledgeDeployment(req.Context(), body)
	if err != nil {
		if err.Error() == "probe not found" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (r *Router) handleCreateProbeUpgradeTask(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateProbeUpgradeTaskRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	if !accessibleProbeOrDeny(w, operator, body.ProbeID) {
		return
	}
	task, err := r.service.CreateProbeUpgradeTask(req.Context(), body, operator.ID)
	if err != nil {
		switch err.Error() {
		case "probe not found":
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		case "upgrade package not found", "target version is required":
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, task)
}

func (r *Router) handleCreateUpgradePackage(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateUpgradePackageRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	pkg, err := r.service.CreateUpgradePackage(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, pkg)
}

func (r *Router) handleUploadUpgradePackage(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	if err := req.ParseMultipartForm(64 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.FormValue("tenant_id"))
	if !ok {
		return
	}
	file, header, err := req.FormFile("package")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "package file is required"})
		return
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pkg, err := r.service.UploadUpgradePackage(
		req.Context(),
		tenantID,
		req.FormValue("version"),
		req.FormValue("notes"),
		header.Filename,
		strings.EqualFold(req.FormValue("enabled"), "true"),
		content,
		operator.ID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, pkg)
}

func (r *Router) handleListUpgradePackages(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListUpgradePackages(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleDownloadUpgradePackage(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID := req.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = operator.TenantID
	}
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, tenantID)
	if !ok {
		return
	}
	pkg, found, err := r.service.GetUpgradePackage(req.Context(), tenantID, req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "upgrade package not found"})
		return
	}
	http.ServeFile(w, req, r.service.UpgradePackagePath(pkg))
}

func (r *Router) handleBatchCreateProbeUpgradeTask(w http.ResponseWriter, req *http.Request) {
	var body shared.BatchCreateProbeUpgradeTaskRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	for _, probeID := range body.ProbeIDs {
		if !accessibleProbeOrDeny(w, operator, probeID) {
			return
		}
	}
	resp, err := r.service.BatchCreateProbeUpgradeTasks(req.Context(), body, operator.ID)
	if err != nil {
		switch err.Error() {
		case "probe not found":
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		case "upgrade package not found", "target version is required":
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (r *Router) handleListProbeUpgradeTasks(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListProbeUpgradeTasks(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	filtered := make([]shared.ProbeUpgradeTask, 0, len(items))
	for _, item := range items {
		if canAccessProbe(operator, item.ProbeID) {
			filtered = append(filtered, item)
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (r *Router) handleAcknowledgeProbeUpgradeTask(w http.ResponseWriter, req *http.Request) {
	var body shared.ProbeUpgradeAckRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	task, err := r.service.AcknowledgeProbeUpgradeTask(req.Context(), body)
	if err != nil {
		if err.Error() == "pending upgrade task not found" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, task)
}

func (r *Router) handleIngest(w http.ResponseWriter, req *http.Request) {
	var body shared.EventBatch
	if !decodeJSON(req, &body, w) {
		return
	}
	alerts, err := r.service.Ingest(req.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ingested_events":  len(body.Events),
		"generated_alerts": alerts,
	})
}

func (r *Router) handleListAlerts(w http.ResponseWriter, req *http.Request) {
	startedAt := time.Now()
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	query := shared.AlertQuery{
		TenantID:  tenantID,
		Status:    req.URL.Query().Get("status"),
		SrcIP:     req.URL.Query().Get("src_ip"),
		DstIP:     req.URL.Query().Get("dst_ip"),
		Signature: req.URL.Query().Get("signature"),
		Assignee:  req.URL.Query().Get("assignee"),
		SortBy:    req.URL.Query().Get("sort_by"),
		SortOrder: req.URL.Query().Get("sort_order"),
	}
	var since time.Time
	if raw := req.URL.Query().Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid since"})
			return
		}
		since = parsed
	}
	query.Since = since
	if raw := req.URL.Query().Get("severity"); raw != "" {
		var severity int
		if _, err := fmt.Sscanf(raw, "%d", &severity); err == nil {
			query.Severity = severity
		}
	}
	query.AttackResult = req.URL.Query().Get("attack_result")
	query.MinProbeCount = parseIntDefault(req.URL.Query().Get("min_probe_count"), 0)
	query.MaxProbeCount = parseIntDefault(req.URL.Query().Get("max_probe_count"), 0)
	query.MinWindowMins = parseIntDefault(req.URL.Query().Get("min_window_mins"), 0)
	query.MaxWindowMins = parseIntDefault(req.URL.Query().Get("max_window_mins"), 0)
	query.Page = parseIntDefault(req.URL.Query().Get("page"), 1)
	query.PageSize = parseIntDefault(req.URL.Query().Get("page_size"), 10)
	alerts, err := r.service.SearchAlertsForUser(req.Context(), operator, query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(operator.AllowedProbeIDs) > 0 && !containsString(operator.Permissions, "*") {
		filtered := make([]shared.Alert, 0, len(alerts.Items))
		for _, item := range alerts.Items {
			item.ProbeIDs = r.service.FilterProbeIDs(operator, item.ProbeIDs)
			if len(item.ProbeIDs) == 0 {
				continue
			}
			filtered = append(filtered, item)
		}
		alerts.Items = filtered
		alerts.Total = len(filtered)
	}
	summary := summarizeAlertQuery(query)
	durationMS := time.Since(startedAt).Milliseconds()
	_ = r.service.RecordQueryAudit(req.Context(), query.TenantID, operator.ID, "alert_search", summary, fmt.Sprintf("rows=%d", len(alerts.Items)))
	stat := r.service.RecordQueryStat(shared.QueryStat{
		QueryType:   "alert_search",
		TenantID:    query.TenantID,
		UserID:      operator.ID,
		Summary:     summary,
		DurationMS:  durationMS,
		ResultCount: len(alerts.Items),
		RecordedAt:  time.Now().UTC(),
	})
	if stat.Slow {
		_ = r.service.RecordQueryAudit(req.Context(), query.TenantID, operator.ID, "slow_query", summary, fmt.Sprintf("duration_ms=%d", durationMS))
	}
	writeJSON(w, http.StatusOK, alerts)
}

func (r *Router) handleListRawAlerts(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	query := shared.RawAlertQuery{
		TenantID:     tenantID,
		SrcIP:        req.URL.Query().Get("src_ip"),
		DstIP:        req.URL.Query().Get("dst_ip"),
		Signature:    req.URL.Query().Get("signature"),
		ProbeID:      req.URL.Query().Get("probe_id"),
		AttackResult: req.URL.Query().Get("attack_result"),
		Page:         parseIntDefault(req.URL.Query().Get("page"), 1),
		PageSize:     parseIntDefault(req.URL.Query().Get("page_size"), 20),
	}
	if raw := req.URL.Query().Get("severity"); raw != "" {
		var severity int
		if _, err := fmt.Sscanf(raw, "%d", &severity); err == nil {
			query.Severity = severity
		}
	}
	if raw := req.URL.Query().Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid since"})
			return
		}
		query.Since = parsed
	}
	result, err := r.service.SearchRawAlertsForUser(req.Context(), operator, query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (r *Router) handleGetAlert(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	id := req.PathValue("id")
	alert, ok, err := r.service.GetAlert(req.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if !r.service.CanAccessTenant(operator, alert.TenantID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "tenant access denied"})
		return
	}
	if !r.service.CanAccessAlert(req.Context(), operator, alert) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "alert access denied"})
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

func (r *Router) handleListFlows(w http.ResponseWriter, req *http.Request) {
	startedAt := time.Now()
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	query := shared.FlowQuery{
		TenantID: tenantID,
		SrcIP:    req.URL.Query().Get("src_ip"),
		DstIP:    req.URL.Query().Get("dst_ip"),
		AppProto: req.URL.Query().Get("app_proto"),
	}
	if raw := req.URL.Query().Get("since"); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			query.Since = parsed
		}
	}
	flows, err := r.service.ListFlowsForUser(req.Context(), operator, query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	summary := summarizeFlowQuery(query)
	durationMS := time.Since(startedAt).Milliseconds()
	_ = r.service.RecordQueryAudit(req.Context(), query.TenantID, operator.ID, "flow_search", summary, fmt.Sprintf("rows=%d", len(flows)))
	stat := r.service.RecordQueryStat(shared.QueryStat{
		QueryType:   "flow_search",
		TenantID:    query.TenantID,
		UserID:      operator.ID,
		Summary:     summary,
		DurationMS:  durationMS,
		ResultCount: len(flows),
		RecordedAt:  time.Now().UTC(),
	})
	if stat.Slow {
		_ = r.service.RecordQueryAudit(req.Context(), query.TenantID, operator.ID, "slow_query", summary, fmt.Sprintf("duration_ms=%d", durationMS))
	}
	writeJSON(w, http.StatusOK, flows)
}

func (r *Router) handleCreateAsset(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateAssetRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	asset, err := r.service.CreateAsset(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, asset)
}

func (r *Router) handleListAssets(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListAssetsForUser(req.Context(), operator, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleGetRawAlertDetail(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	id := req.PathValue("id")
	detail, ok, err := r.service.GetRawAlertDetail(req.Context(), operator, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "raw alert not found"})
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (r *Router) handleCreateOrganization(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateOrganizationRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	item, err := r.service.CreateOrganization(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (r *Router) handleListOrganizations(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListOrganizationsForUser(req.Context(), operator, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleCreateThreatIntel(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateThreatIntelRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	intel, err := r.service.CreateThreatIntel(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, intel)
}

func (r *Router) handleListThreatIntel(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListThreatIntel(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleCreateSuppressionRule(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateSuppressionRuleRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	item, err := r.service.CreateSuppressionRule(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (r *Router) handleListSuppressionRules(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListSuppressionRules(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleCreateRiskPolicy(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateRiskPolicyRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	item, err := r.service.CreateRiskPolicy(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (r *Router) handleListRiskPolicies(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListRiskPolicies(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleCreateTicketAutomationPolicy(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateTicketAutomationPolicyRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	item, err := r.service.CreateTicketAutomationPolicy(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (r *Router) handleListTicketAutomationPolicies(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListTicketAutomationPolicies(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleCreateNotificationChannel(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateNotificationChannelRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	channel, err := r.service.CreateNotificationChannel(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, channel)
}

func (r *Router) handleCreateNotificationTemplate(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateNotificationTemplateRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	template, err := r.service.CreateNotificationTemplate(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, template)
}

func (r *Router) handleListNotificationTemplates(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListNotificationTemplates(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleListNotificationChannels(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListNotificationChannels(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleListNotificationRecords(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListNotificationRecords(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleListQueryStats(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	slowOnly := req.URL.Query().Get("slow_only") == "true"
	writeJSON(w, http.StatusOK, r.service.ListQueryStats(tenantID, slowOnly))
}

func (r *Router) handleCreateExportTask(w http.ResponseWriter, req *http.Request) {
	var body shared.ExportTaskRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	task, err := r.service.CreateExportTask(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, task)
}

func (r *Router) handleListExportTasks(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	items, err := r.service.ListExportTasksForUser(req.Context(), operator, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (r *Router) handleGetExportTask(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	task, ok, err := r.service.GetExportTask(req.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "export task not found"})
		return
	}
	operator := currentUser(req.Context())
	if operator.TenantID != "" && task.TenantID != operator.TenantID {
		allowed, err := r.service.Authorize(req.Context(), operator, "*")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !allowed {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "permission denied"})
			return
		}
	}
	if !containsString(operator.Permissions, "*") && task.UserID != operator.ID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "export task access denied"})
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func (r *Router) handleDownloadExportTask(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	task, ok, err := r.service.GetExportTask(req.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "export task not found"})
		return
	}
	operator := currentUser(req.Context())
	if operator.TenantID != "" && task.TenantID != operator.TenantID {
		allowed, err := r.service.Authorize(req.Context(), operator, "*")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !allowed {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "permission denied"})
			return
		}
	}
	if !containsString(operator.Permissions, "*") && task.UserID != operator.ID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "export task access denied"})
		return
	}
	if task.Status != "completed" || task.FilePath == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "export task not ready"})
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(task.FilePath)))
	http.ServeFile(w, req, task.FilePath)
}

func (r *Router) handleGetAlertDetail(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	id := req.PathValue("id")
	detail, ok, err := r.service.GetAlertDetail(req.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if !r.service.CanAccessTenant(operator, detail.Alert.TenantID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "tenant access denied"})
		return
	}
	if !r.service.CanAccessAlert(req.Context(), operator, detail.Alert) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "alert access denied"})
		return
	}
	if len(detail.SimilarSourceAlerts) > 0 {
		filtered := make([]shared.Alert, 0, len(detail.SimilarSourceAlerts))
		for _, item := range detail.SimilarSourceAlerts {
			if r.service.CanAccessAlert(req.Context(), operator, item) {
				filtered = append(filtered, item)
			}
		}
		detail.SimilarSourceAlerts = filtered
	}
	if len(detail.SimilarTargetAlerts) > 0 {
		filtered := make([]shared.Alert, 0, len(detail.SimilarTargetAlerts))
		for _, item := range detail.SimilarTargetAlerts {
			if r.service.CanAccessAlert(req.Context(), operator, item) {
				filtered = append(filtered, item)
			}
		}
		detail.SimilarTargetAlerts = filtered
	}
	writeJSON(w, http.StatusOK, detail)
}

func (r *Router) handleUpdateAlert(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	var body shared.UpdateAlertStatusRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	alert, ok, err := r.service.UpdateAlertStatus(req.Context(), id, body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

func (r *Router) handleBatchUpdateAlerts(w http.ResponseWriter, req *http.Request) {
	var body shared.BatchUpdateAlertStatusRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID)
	if !ok {
		return
	}
	body.TenantID = tenantID
	if len(body.AlertIDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "alert_ids is required"})
		return
	}
	result, err := r.service.BatchUpdateAlertStatus(req.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (r *Router) handleCreateTicket(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateTicketRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	ticket, ok, err := r.service.CreateTicket(req.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	writeJSON(w, http.StatusCreated, ticket)
}

func (r *Router) handleBatchCreateTickets(w http.ResponseWriter, req *http.Request) {
	var body shared.BatchCreateTicketRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	result, err := r.service.BatchCreateTickets(req.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (r *Router) handleListTickets(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	query := shared.TicketQuery{
		TenantID:  tenantID,
		Status:    req.URL.Query().Get("status"),
		SortBy:    req.URL.Query().Get("sort_by"),
		SortOrder: req.URL.Query().Get("sort_order"),
		Page:      parseIntDefault(req.URL.Query().Get("page"), 1),
		PageSize:  parseIntDefault(req.URL.Query().Get("page_size"), 10),
	}
	if raw := req.URL.Query().Get("since"); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			query.Since = parsed
		}
	}
	tickets, err := r.service.ListTicketsForUser(req.Context(), operator, query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, tickets)
}

func (r *Router) handleGetTicket(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	id := req.PathValue("id")
	detail, ok, err := r.service.GetTicketDetail(req.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "ticket not found"})
		return
	}
	if !r.service.CanAccessTenant(operator, detail.Ticket.TenantID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "tenant access denied"})
		return
	}
	if !r.service.CanAccessTicket(req.Context(), operator, detail.Ticket) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "ticket access denied"})
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (r *Router) handleUpdateTicket(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	var body shared.UpdateTicketStatusRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	ticket, ok, err := r.service.UpdateTicketStatus(req.Context(), id, body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "ticket not found"})
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}

func (r *Router) handleBatchUpdateTickets(w http.ResponseWriter, req *http.Request) {
	var body shared.BatchUpdateTicketStatusRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	result, err := r.service.BatchUpdateTicketStatus(req.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (r *Router) handleLogin(w http.ResponseWriter, req *http.Request) {
	var body shared.LoginRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	resp, ok, err := r.service.Login(req.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (r *Router) handleCurrentUser(w http.ResponseWriter, req *http.Request) {
	user := currentUser(req.Context())
	if user.ID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (r *Router) handleCreateUser(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateUserRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	user, err := r.service.CreateUser(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (r *Router) handleListUsers(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	users, err := r.service.ListUsers(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (r *Router) handleCreateRole(w http.ResponseWriter, req *http.Request) {
	var body shared.CreateRoleRequest
	if !decodeJSON(req, &body, w) {
		return
	}
	operator := currentUser(req.Context())
	if _, ok := scopedTenantOrDeny(w, operator, r.service, body.TenantID); !ok {
		return
	}
	role, err := r.service.CreateRole(req.Context(), body, operator.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (r *Router) handleListRoles(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	roles, err := r.service.ListRoles(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, roles)
}

func (r *Router) handleListRoleTemplates(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, r.service.ListRoleTemplates(req.Context()))
}

func (r *Router) handleListAuditLogs(w http.ResponseWriter, req *http.Request) {
	operator := currentUser(req.Context())
	tenantID, ok := scopedTenantOrDeny(w, operator, r.service, req.URL.Query().Get("tenant_id"))
	if !ok {
		return
	}
	logs, err := r.service.ListAuditLogs(req.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

func scopedTenantOrDeny(w http.ResponseWriter, operator shared.User, svc *service.Service, tenantID string) (string, bool) {
	resolved := strings.TrimSpace(tenantID)
	if resolved == "" {
		if containsString(operator.Permissions, "*") {
			return "", true
		}
		resolved = operator.TenantID
	}
	if !svc.CanAccessTenant(operator, resolved) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "tenant access denied"})
		return "", false
	}
	return resolved, true
}

func accessibleProbeOrDeny(w http.ResponseWriter, operator shared.User, probeID string) bool {
	if canAccessProbe(operator, probeID) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "probe access denied"})
	return false
}

func canAccessProbe(operator shared.User, probeID string) bool {
	if len(operator.AllowedProbeIDs) == 0 || containsString(operator.Permissions, "*") {
		return true
	}
	for _, allowed := range operator.AllowedProbeIDs {
		if allowed == probeID {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func decodeJSON(req *http.Request, target any, w http.ResponseWriter) bool {
	defer req.Body.Close()
	if err := json.NewDecoder(req.Body).Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func currentUser(ctx context.Context) shared.User {
	user, _ := ctx.Value(currentUserKey).(shared.User)
	return user
}

func authMiddleware(svc *service.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if isPublicPath(req.URL.Path) {
			next.ServeHTTP(w, req)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		user, ok, err := svc.Authenticate(req.Context(), token)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid bearer token"})
			return
		}
		permission := requiredPermission(req.Method, req.URL.Path)
		allowed, err := svc.Authorize(req.Context(), user, permission)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !allowed {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "permission denied"})
			return
		}
		ctx := context.WithValue(req.Context(), currentUserKey, user)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(w, req)
	})
}

func isPublicPath(path string) bool {
	return path == "/" ||
		strings.HasPrefix(path, "/assets/") ||
		path == "/healthz" ||
		path == "/api/v1/auth/login" ||
		path == "/api/v1/probes/register" ||
		path == "/api/v1/probes/heartbeat" ||
		path == "/api/v1/events/ingest" ||
		(strings.HasPrefix(path, "/api/v1/probes/") && strings.HasSuffix(path, "/upgrade-task")) ||
		(strings.HasPrefix(path, "/api/v1/probes/") && strings.HasSuffix(path, "/binding")) ||
		path == "/api/v1/deployments/ack" ||
		path == "/api/v1/probe-upgrades/ack"
}

func requiredPermission(method, path string) string {
	switch {
	case method == http.MethodGet && path == "/api/v1/probes":
		return "probe.read"
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/probes/") && strings.HasSuffix(path, "/metrics"):
		return "probe.read"
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/probes/") && strings.HasSuffix(path, "/upgrade-task"):
		return ""
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/probes/") && !strings.HasSuffix(path, "/binding"):
		return "probe.read"
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/probes/") && strings.HasSuffix(path, "/binding"):
		return ""
	case method == http.MethodGet && path == "/api/v1/dashboard/stats":
		return ""
	case method == http.MethodGet && path == "/api/v1/dashboard/workbench":
		return ""
	case method == http.MethodGet && path == "/api/v1/reports/summary":
		return ""
	case method == http.MethodGet && path == "/api/v1/probe-configs":
		return "probe.read"
	case method == http.MethodPost && path == "/api/v1/probe-configs":
		return "probe.write"
	case method == http.MethodGet && path == "/api/v1/rule-bundles":
		return "probe.read"
	case method == http.MethodPost && path == "/api/v1/rule-bundles":
		return "probe.write"
	case method == http.MethodGet && path == "/api/v1/probe-bindings":
		return "probe.read"
	case method == http.MethodPost && path == "/api/v1/probe-bindings":
		return "probe.write"
	case method == http.MethodPost && path == "/api/v1/probe-bindings/batch":
		return "probe.write"
	case method == http.MethodGet && path == "/api/v1/deployments":
		return "probe.read"
	case method == http.MethodPost && path == "/api/v1/deployments/ack":
		return ""
	case method == http.MethodGet && path == "/api/v1/upgrade-packages":
		return "probe.read"
	case method == http.MethodPost && path == "/api/v1/upgrade-packages":
		return "probe.write"
	case method == http.MethodPost && path == "/api/v1/upgrade-packages/upload":
		return "probe.write"
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/upgrade-packages/") && strings.HasSuffix(path, "/download"):
		return "probe.read"
	case method == http.MethodGet && path == "/api/v1/probe-upgrades":
		return "probe.read"
	case method == http.MethodPost && path == "/api/v1/probe-upgrades":
		return "probe.write"
	case method == http.MethodPost && path == "/api/v1/probe-upgrades/batch":
		return "probe.write"
	case method == http.MethodPost && path == "/api/v1/probe-upgrades/ack":
		return ""
	case method == http.MethodGet && path == "/api/v1/auth/me":
		return ""
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/alerts"):
		return "alert.read"
	case method == http.MethodPost && path == "/api/v1/alerts/batch":
		return "alert.write"
	case method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/alerts/"):
		return "alert.write"
	case method == http.MethodGet && path == "/api/v1/flows":
		return "alert.read"
	case method == http.MethodGet && path == "/api/v1/assets":
		return "asset.read"
	case method == http.MethodPost && path == "/api/v1/assets":
		return "asset.write"
	case method == http.MethodGet && path == "/api/v1/organizations":
		return "asset.read"
	case method == http.MethodPost && path == "/api/v1/organizations":
		return "asset.write"
	case method == http.MethodGet && path == "/api/v1/threat-intel":
		return "intel.read"
	case method == http.MethodPost && path == "/api/v1/threat-intel":
		return "intel.write"
	case method == http.MethodGet && path == "/api/v1/suppression-rules":
		return "policy.read"
	case method == http.MethodPost && path == "/api/v1/suppression-rules":
		return "policy.write"
	case method == http.MethodGet && path == "/api/v1/risk-policies":
		return "policy.read"
	case method == http.MethodPost && path == "/api/v1/risk-policies":
		return "policy.write"
	case method == http.MethodGet && path == "/api/v1/ticket-automation-policies":
		return "policy.read"
	case method == http.MethodPost && path == "/api/v1/ticket-automation-policies":
		return "policy.write"
	case method == http.MethodGet && path == "/api/v1/tickets":
		return "ticket.read"
	case method == http.MethodPost && path == "/api/v1/tickets":
		return "ticket.write"
	case method == http.MethodPost && path == "/api/v1/tickets/batch":
		return "ticket.write"
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/tickets/"):
		return "ticket.read"
	case method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/tickets/"):
		return "ticket.write"
	case method == http.MethodPost && path == "/api/v1/tickets/batch-update":
		return "ticket.write"
	case method == http.MethodGet && path == "/api/v1/users":
		return "user.read"
	case method == http.MethodPost && path == "/api/v1/users":
		return "user.write"
	case method == http.MethodGet && path == "/api/v1/role-templates":
		return ""
	case method == http.MethodGet && path == "/api/v1/roles":
		return "role.read"
	case method == http.MethodPost && path == "/api/v1/roles":
		return "role.write"
	case method == http.MethodGet && path == "/api/v1/audit/logs":
		return "audit.read"
	case method == http.MethodGet && path == "/api/v1/query-stats":
		return "audit.read"
	case method == http.MethodPost && path == "/api/v1/notifications/channels":
		return "notify.write"
	case method == http.MethodGet && path == "/api/v1/notifications/channels":
		return "notify.read"
	case method == http.MethodPost && path == "/api/v1/notifications/templates":
		return "notify.write"
	case method == http.MethodGet && path == "/api/v1/notifications/templates":
		return "notify.read"
	case method == http.MethodGet && path == "/api/v1/notifications/records":
		return "notify.read"
	case method == http.MethodPost && path == "/api/v1/exports":
		return "alert.read"
	case method == http.MethodGet && path == "/api/v1/exports":
		return "alert.read"
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/exports/") && strings.HasSuffix(path, "/download"):
		return "alert.read"
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/exports/"):
		return "alert.read"
	default:
		return ""
	}
}

func parseIntDefault(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	var value int
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil {
		return fallback
	}
	return value
}

func summarizeAlertQuery(query shared.AlertQuery) string {
	parts := []string{
		"tenant=" + query.TenantID,
		"status=" + query.Status,
		"src=" + query.SrcIP,
		"dst=" + query.DstIP,
		"signature=" + query.Signature,
		"assignee=" + query.Assignee,
		fmt.Sprintf("severity=%d", query.Severity),
		fmt.Sprintf("page=%d", query.Page),
		fmt.Sprintf("page_size=%d", query.PageSize),
	}
	if !query.Since.IsZero() {
		parts = append(parts, "since="+query.Since.Format(time.RFC3339))
	}
	return strings.Join(parts, ";")
}

func summarizeFlowQuery(query shared.FlowQuery) string {
	parts := []string{
		"tenant=" + query.TenantID,
		"src=" + query.SrcIP,
		"dst=" + query.DstIP,
		"app_proto=" + query.AppProto,
	}
	if !query.Since.IsZero() {
		parts = append(parts, "since="+query.Since.Format(time.RFC3339))
	}
	return strings.Join(parts, ";")
}
