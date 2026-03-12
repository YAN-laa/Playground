package store

import (
	"context"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

type Repository interface {
	UpsertProbe(ctx context.Context, probe shared.Probe) (shared.Probe, error)
	GetProbe(ctx context.Context, id string) (shared.Probe, bool, error)
	FindProbeByCode(ctx context.Context, tenantID, probeCode string) (shared.Probe, bool, error)
	ListProbes(ctx context.Context, tenantID string) ([]shared.Probe, error)
	CreateProbeConfig(ctx context.Context, config shared.ProbeConfig) (shared.ProbeConfig, error)
	GetProbeConfig(ctx context.Context, id string) (shared.ProbeConfig, bool, error)
	ListProbeConfigs(ctx context.Context, tenantID string) ([]shared.ProbeConfig, error)
	CreateRuleBundle(ctx context.Context, bundle shared.RuleBundle) (shared.RuleBundle, error)
	GetRuleBundle(ctx context.Context, id string) (shared.RuleBundle, bool, error)
	ListRuleBundles(ctx context.Context, tenantID string) ([]shared.RuleBundle, error)
	UpsertProbeBinding(ctx context.Context, binding shared.ProbeBinding) (shared.ProbeBinding, error)
	GetProbeBindingByProbeID(ctx context.Context, probeID string) (shared.ProbeBinding, bool, error)
	ListProbeBindings(ctx context.Context, tenantID string) ([]shared.ProbeBinding, error)
	CreateDeploymentRecord(ctx context.Context, record shared.DeploymentRecord) (shared.DeploymentRecord, error)
	ListDeploymentRecords(ctx context.Context, tenantID string) ([]shared.DeploymentRecord, error)
	CreateUpgradePackage(ctx context.Context, pkg shared.UpgradePackage) (shared.UpgradePackage, error)
	ListUpgradePackages(ctx context.Context, tenantID string) ([]shared.UpgradePackage, error)
	FindUpgradePackageByID(ctx context.Context, tenantID, id string) (shared.UpgradePackage, bool, error)
	FindUpgradePackageByVersion(ctx context.Context, tenantID, version string) (shared.UpgradePackage, bool, error)
	CreateProbeUpgradeTask(ctx context.Context, task shared.ProbeUpgradeTask) (shared.ProbeUpgradeTask, error)
	ListProbeUpgradeTasks(ctx context.Context, tenantID string) ([]shared.ProbeUpgradeTask, error)
	GetPendingProbeUpgradeTask(ctx context.Context, probeID string) (shared.ProbeUpgradeTask, bool, error)
	UpdateProbeUpgradeTask(ctx context.Context, task shared.ProbeUpgradeTask) (shared.ProbeUpgradeTask, error)
	AddProbeVersionHistory(ctx context.Context, item shared.ProbeVersionHistory) error
	ListProbeVersionHistory(ctx context.Context, tenantID, probeID string) ([]shared.ProbeVersionHistory, error)
	AddProbeMetric(ctx context.Context, metric shared.ProbeMetric) error
	ListProbeMetrics(ctx context.Context, query shared.ProbeMetricQuery) ([]shared.ProbeMetric, error)

	AddRawEvent(ctx context.Context, event shared.RawEvent) error
	ListRawEvents(ctx context.Context, tenantID string, since, until time.Time, probeIDs []string) ([]shared.RawEvent, error)
	UpsertFlow(ctx context.Context, flow shared.Flow) (shared.Flow, error)
	ListFlowsByIDs(ctx context.Context, tenantID string, flowIDs []string) ([]shared.Flow, error)
	ListFlows(ctx context.Context, query shared.FlowQuery) ([]shared.Flow, error)
	CreateAsset(ctx context.Context, asset shared.Asset) (shared.Asset, error)
	ListAssets(ctx context.Context, tenantID string) ([]shared.Asset, error)
	FindAssetByIP(ctx context.Context, tenantID, ip string) (shared.Asset, bool, error)
	CreateOrganization(ctx context.Context, org shared.Organization) (shared.Organization, error)
	ListOrganizations(ctx context.Context, tenantID string) ([]shared.Organization, error)
	GetOrganization(ctx context.Context, id string) (shared.Organization, bool, error)
	CreateThreatIntel(ctx context.Context, intel shared.ThreatIntel) (shared.ThreatIntel, error)
	ListThreatIntel(ctx context.Context, tenantID string) ([]shared.ThreatIntel, error)
	FindThreatIntelByValue(ctx context.Context, tenantID, value string) ([]shared.ThreatIntel, error)
	CreateSuppressionRule(ctx context.Context, rule shared.SuppressionRule) (shared.SuppressionRule, error)
	ListSuppressionRules(ctx context.Context, tenantID string) ([]shared.SuppressionRule, error)
	CreateRiskPolicy(ctx context.Context, policy shared.RiskPolicy) (shared.RiskPolicy, error)
	ListRiskPolicies(ctx context.Context, tenantID string) ([]shared.RiskPolicy, error)
	CreateTicketAutomationPolicy(ctx context.Context, policy shared.TicketAutomationPolicy) (shared.TicketAutomationPolicy, error)
	ListTicketAutomationPolicies(ctx context.Context, tenantID string) ([]shared.TicketAutomationPolicy, error)
	UpsertAlertByFingerprint(ctx context.Context, fp string, build func(existing *shared.Alert) shared.Alert) (shared.Alert, error)
	GetAlert(ctx context.Context, id string) (shared.Alert, bool, error)
	UpdateAlertStatus(ctx context.Context, id string, mutate func(alert shared.Alert) shared.Alert) (shared.Alert, bool, error)
	ListAlerts(ctx context.Context, query shared.AlertQuery) ([]shared.Alert, error)

	CreateTicket(ctx context.Context, ticket shared.Ticket) (shared.Ticket, error)
	ListTickets(ctx context.Context, tenantID string) ([]shared.Ticket, error)
	ListTicketsByAlert(ctx context.Context, tenantID, alertID string) ([]shared.Ticket, error)
	GetTicket(ctx context.Context, id string) (shared.Ticket, bool, error)
	UpdateTicketStatus(ctx context.Context, id string, mutate func(ticket shared.Ticket) shared.Ticket) (shared.Ticket, bool, error)

	CreateUser(ctx context.Context, user shared.User) (shared.User, error)
	ListUsers(ctx context.Context, tenantID string) ([]shared.User, error)
	FindUser(ctx context.Context, tenantID, username string) (shared.User, bool, error)
	GetUser(ctx context.Context, id string) (shared.User, bool, error)

	CreateRole(ctx context.Context, role shared.Role) (shared.Role, error)
	ListRoles(ctx context.Context, tenantID string) ([]shared.Role, error)

	SaveToken(ctx context.Context, token, userID string) error
	LookupToken(ctx context.Context, token string) (shared.User, bool, error)

	AddAuditLog(ctx context.Context, log shared.AuditLog) error
	ListAuditLogs(ctx context.Context, tenantID string) ([]shared.AuditLog, error)
	AddActivity(ctx context.Context, activity shared.Activity) error
	ListActivities(ctx context.Context, tenantID, resourceType, resourceID string) ([]shared.Activity, error)
	CreateExportTask(ctx context.Context, task shared.ExportTask) (shared.ExportTask, error)
	UpdateExportTask(ctx context.Context, task shared.ExportTask) (shared.ExportTask, error)
	GetExportTask(ctx context.Context, id string) (shared.ExportTask, bool, error)
	ListExportTasks(ctx context.Context, tenantID string) ([]shared.ExportTask, error)
	CreateNotificationChannel(ctx context.Context, channel shared.NotificationChannel) (shared.NotificationChannel, error)
	ListNotificationChannels(ctx context.Context, tenantID string) ([]shared.NotificationChannel, error)
	CreateNotificationTemplate(ctx context.Context, template shared.NotificationTemplate) (shared.NotificationTemplate, error)
	ListNotificationTemplates(ctx context.Context, tenantID string) ([]shared.NotificationTemplate, error)
	CreateNotificationRecord(ctx context.Context, record shared.NotificationRecord) (shared.NotificationRecord, error)
	UpdateNotificationRecord(ctx context.Context, record shared.NotificationRecord) (shared.NotificationRecord, error)
	ListNotificationRecords(ctx context.Context, tenantID string) ([]shared.NotificationRecord, error)
}
