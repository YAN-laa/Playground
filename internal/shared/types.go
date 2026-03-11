package shared

import "time"

type Probe struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	ProbeCode         string    `json:"probe_code"`
	Name              string    `json:"name"`
	Status            string    `json:"status"`
	Version           string    `json:"version"`
	RuleVersion       string    `json:"rule_version"`
	AppliedConfigID   string    `json:"applied_config_id"`
	AppliedRuleID     string    `json:"applied_rule_id"`
	LastDeployStatus  string    `json:"last_deploy_status"`
	LastDeployMessage string    `json:"last_deploy_message"`
	LastDeployAt      time.Time `json:"last_deploy_at"`
	CPUUsage          float64   `json:"cpu_usage"`
	MemUsage          float64   `json:"mem_usage"`
	DropRate          float64   `json:"drop_rate"`
	LastHeartbeatAt   time.Time `json:"last_heartbeat_at"`
	CreatedAt         time.Time `json:"created_at"`
}

type ProbeConfig struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Filters     []string  `json:"filters"`
	OutputTypes []string  `json:"output_types"`
	CreatedAt   time.Time `json:"created_at"`
}

type RuleBundle struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Version     string    `json:"version"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

type ProbeBinding struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProbeID       string    `json:"probe_id"`
	ProbeName     string    `json:"probe_name"`
	ProbeConfigID string    `json:"probe_config_id"`
	RuleBundleID  string    `json:"rule_bundle_id"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type DeploymentRecord struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProbeID       string    `json:"probe_id"`
	ProbeName     string    `json:"probe_name"`
	ProbeConfigID string    `json:"probe_config_id"`
	RuleBundleID  string    `json:"rule_bundle_id"`
	Status        string    `json:"status"`
	Message       string    `json:"message"`
	CreatedAt     time.Time `json:"created_at"`
}

type ProbeBindingDetail struct {
	Binding     ProbeBinding `json:"binding"`
	ProbeConfig ProbeConfig  `json:"probe_config"`
	RuleBundle  RuleBundle   `json:"rule_bundle"`
}

type ProbeDetail struct {
	Probe          Probe                 `json:"probe"`
	Binding        *ProbeBinding         `json:"binding,omitempty"`
	UpgradeTask    *ProbeUpgradeTask     `json:"upgrade_task,omitempty"`
	VersionHistory []ProbeVersionHistory `json:"version_history"`
	Deployments    []DeploymentRecord    `json:"deployments"`
	Metrics        []ProbeMetric         `json:"metrics"`
}

type UpgradePackage struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Version    string    `json:"version"`
	PackageURL string    `json:"package_url"`
	Checksum   string    `json:"checksum"`
	Notes      string    `json:"notes"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

type CreateUpgradePackageRequest struct {
	TenantID   string `json:"tenant_id"`
	Version    string `json:"version"`
	PackageURL string `json:"package_url"`
	Checksum   string `json:"checksum"`
	Notes      string `json:"notes"`
	Enabled    bool   `json:"enabled"`
}

type ProbeUpgradeTask struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	ProbeID         string    `json:"probe_id"`
	ProbeName       string    `json:"probe_name"`
	PackageID       string    `json:"package_id"`
	Action          string    `json:"action"`
	PreviousVersion string    `json:"previous_version"`
	TargetVersion   string    `json:"target_version"`
	Status          string    `json:"status"`
	RetryCount      int       `json:"retry_count"`
	MaxRetries      int       `json:"max_retries"`
	Message         string    `json:"message"`
	CreatedAt       time.Time `json:"created_at"`
	CompletedAt     time.Time `json:"completed_at"`
}

type CreateProbeUpgradeTaskRequest struct {
	TenantID      string `json:"tenant_id"`
	ProbeID       string `json:"probe_id"`
	Action        string `json:"action"`
	TargetVersion string `json:"target_version"`
	MaxRetries    int    `json:"max_retries"`
}

type BatchCreateProbeUpgradeTaskRequest struct {
	TenantID      string   `json:"tenant_id"`
	ProbeIDs      []string `json:"probe_ids"`
	Action        string   `json:"action"`
	TargetVersion string   `json:"target_version"`
	MaxRetries    int      `json:"max_retries"`
}

type BatchCreateProbeUpgradeTaskResponse struct {
	Requested int                `json:"requested"`
	Applied   int                `json:"applied"`
	Items     []ProbeUpgradeTask `json:"items"`
}

type ProbeUpgradeAckRequest struct {
	TenantID      string `json:"tenant_id"`
	ProbeID       string `json:"probe_id"`
	Action        string `json:"action"`
	TargetVersion string `json:"target_version"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}

type ProbeVersionHistory struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	ProbeID     string    `json:"probe_id"`
	ProbeName   string    `json:"probe_name"`
	Action      string    `json:"action"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	Result      string    `json:"result"`
	Message     string    `json:"message"`
	CreatedAt   time.Time `json:"created_at"`
}

type BatchApplyProbeBindingRequest struct {
	TenantID      string   `json:"tenant_id"`
	ProbeIDs      []string `json:"probe_ids"`
	ProbeConfigID string   `json:"probe_config_id"`
	RuleBundleID  string   `json:"rule_bundle_id"`
}

type BatchApplyProbeBindingResponse struct {
	Requested int            `json:"requested"`
	Applied   int            `json:"applied"`
	Items     []ProbeBinding `json:"items"`
}

type DeploymentQuery struct {
	TenantID string
	ProbeID  string
	Status   string
	Since    time.Time
	Limit    int
}

type ProbeMetric struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ProbeID   string    `json:"probe_id"`
	CPUUsage  float64   `json:"cpu_usage"`
	MemUsage  float64   `json:"mem_usage"`
	DropRate  float64   `json:"drop_rate"`
	CreatedAt time.Time `json:"created_at"`
}

type ProbeMetricQuery struct {
	TenantID string
	ProbeID  string
	Since    time.Time
	Limit    int
}

type RegisterProbeRequest struct {
	TenantID    string `json:"tenant_id"`
	ProbeCode   string `json:"probe_code"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	RuleVersion string `json:"rule_version"`
}

type HeartbeatRequest struct {
	TenantID string  `json:"tenant_id"`
	ProbeID  string  `json:"probe_id"`
	Status   string  `json:"status"`
	CPUUsage float64 `json:"cpu_usage"`
	MemUsage float64 `json:"mem_usage"`
	DropRate float64 `json:"drop_rate"`
}

type EventBatch struct {
	TenantID string          `json:"tenant_id"`
	ProbeID  string          `json:"probe_id"`
	Events   []SuricataEvent `json:"events"`
}

type SuricataEvent struct {
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	SrcIP     string         `json:"src_ip"`
	SrcPort   int            `json:"src_port"`
	DstIP     string         `json:"dst_ip"`
	DstPort   int            `json:"dst_port"`
	Proto     string         `json:"proto"`
	AppProto  string         `json:"app_proto"`
	Alert     *SuricataAlert `json:"alert,omitempty"`
	FlowID    string         `json:"flow_id,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type SuricataAlert struct {
	SignatureID int    `json:"signature_id"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

type RawEvent struct {
	ID         string        `json:"id"`
	TenantID   string        `json:"tenant_id"`
	ProbeID    string        `json:"probe_id"`
	EventType  string        `json:"event_type"`
	EventTime  time.Time     `json:"event_time"`
	IngestTime time.Time     `json:"ingest_time"`
	Payload    SuricataEvent `json:"payload"`
}

type Flow struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenant_id"`
	ProbeID  string    `json:"probe_id"`
	FlowID   string    `json:"flow_id"`
	SrcIP    string    `json:"src_ip"`
	SrcPort  int       `json:"src_port"`
	DstIP    string    `json:"dst_ip"`
	DstPort  int       `json:"dst_port"`
	Proto    string    `json:"proto"`
	AppProto string    `json:"app_proto"`
	SeenAt   time.Time `json:"seen_at"`
}

type Asset struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Name            string    `json:"name"`
	IP              string    `json:"ip"`
	AssetType       string    `json:"asset_type"`
	ImportanceLevel string    `json:"importance_level"`
	Owner           string    `json:"owner"`
	Tags            []string  `json:"tags"`
	CreatedAt       time.Time `json:"created_at"`
}

type CreateAssetRequest struct {
	TenantID        string   `json:"tenant_id"`
	Name            string   `json:"name"`
	IP              string   `json:"ip"`
	AssetType       string   `json:"asset_type"`
	ImportanceLevel string   `json:"importance_level"`
	Owner           string   `json:"owner"`
	Tags            []string `json:"tags"`
}

type ThreatIntel struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Severity  string    `json:"severity"`
	Source    string    `json:"source"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateThreatIntelRequest struct {
	TenantID string   `json:"tenant_id"`
	Type     string   `json:"type"`
	Value    string   `json:"value"`
	Severity string   `json:"severity"`
	Source   string   `json:"source"`
	Tags     []string `json:"tags"`
}

type SuppressionRule struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SignatureID int       `json:"signature_id"`
	Signature   string    `json:"signature"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

type CreateSuppressionRuleRequest struct {
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SignatureID int    `json:"signature_id"`
	Signature   string `json:"signature"`
	Enabled     bool   `json:"enabled"`
}

type RiskPolicy struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	Name               string    `json:"name"`
	Severity1Score     int       `json:"severity1_score"`
	Severity2Score     int       `json:"severity2_score"`
	Severity3Score     int       `json:"severity3_score"`
	DefaultScore       int       `json:"default_score"`
	IntelHitBonus      int       `json:"intel_hit_bonus"`
	CriticalAssetBonus int       `json:"critical_asset_bonus"`
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at"`
}

type CreateRiskPolicyRequest struct {
	TenantID           string `json:"tenant_id"`
	Name               string `json:"name"`
	Severity1Score     int    `json:"severity1_score"`
	Severity2Score     int    `json:"severity2_score"`
	Severity3Score     int    `json:"severity3_score"`
	DefaultScore       int    `json:"default_score"`
	IntelHitBonus      int    `json:"intel_hit_bonus"`
	CriticalAssetBonus int    `json:"critical_asset_bonus"`
	Enabled            bool   `json:"enabled"`
}

type TicketAutomationPolicy struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	Name                string    `json:"name"`
	ReminderBeforeMins  int       `json:"reminder_before_mins"`
	EscalationAfterMins int       `json:"escalation_after_mins"`
	EscalationAssignee  string    `json:"escalation_assignee"`
	EscalationStatus    string    `json:"escalation_status"`
	Enabled             bool      `json:"enabled"`
	CreatedAt           time.Time `json:"created_at"`
}

type CreateTicketAutomationPolicyRequest struct {
	TenantID            string `json:"tenant_id"`
	Name                string `json:"name"`
	ReminderBeforeMins  int    `json:"reminder_before_mins"`
	EscalationAfterMins int    `json:"escalation_after_mins"`
	EscalationAssignee  string `json:"escalation_assignee"`
	EscalationStatus    string `json:"escalation_status"`
	Enabled             bool   `json:"enabled"`
}

type Alert struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Fingerprint     string    `json:"fingerprint"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	EventCount      int       `json:"event_count"`
	ProbeIDs        []string  `json:"probe_ids"`
	SrcIP           string    `json:"src_ip"`
	DstIP           string    `json:"dst_ip"`
	DstPort         int       `json:"dst_port"`
	Proto           string    `json:"proto"`
	SignatureID     int       `json:"signature_id"`
	Signature       string    `json:"signature"`
	Category        string    `json:"category"`
	Severity        int       `json:"severity"`
	RiskScore       int       `json:"risk_score"`
	Status          string    `json:"status"`
	Assignee        string    `json:"assignee"`
	SourceAssetID   string    `json:"source_asset_id"`
	SourceAssetName string    `json:"source_asset_name"`
	TargetAssetID   string    `json:"target_asset_id"`
	TargetAssetName string    `json:"target_asset_name"`
	ThreatIntelTags []string  `json:"threat_intel_tags"`
	ThreatIntelHits []string  `json:"threat_intel_hits"`
}

type AlertDetail struct {
	Alert         Alert      `json:"alert"`
	Events        []RawEvent `json:"events"`
	ContextEvents []RawEvent `json:"context_events"`
	Flows         []Flow     `json:"flows"`
	Tickets       []Ticket   `json:"tickets"`
	Activities    []Activity `json:"activities"`
}

type AlertQuery struct {
	TenantID  string    `json:"tenant_id"`
	Status    string    `json:"status"`
	Since     time.Time `json:"since"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	Signature string    `json:"signature"`
	Severity  int       `json:"severity"`
	Assignee  string    `json:"assignee"`
	SortBy    string    `json:"sort_by"`
	SortOrder string    `json:"sort_order"`
	Page      int       `json:"page"`
	PageSize  int       `json:"page_size"`
}

type AlertListResponse struct {
	Items    []Alert `json:"items"`
	Total    int     `json:"total"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
}

type Ticket struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	AlertID     string    `json:"alert_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"`
	Status      string    `json:"status"`
	Assignee    string    `json:"assignee"`
	SLADeadline time.Time `json:"sla_deadline"`
	SLAStatus   string    `json:"sla_status"`
	RemindedAt  time.Time `json:"reminded_at"`
	EscalatedAt time.Time `json:"escalated_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type TicketDetail struct {
	Ticket     Ticket     `json:"ticket"`
	Alert      *Alert     `json:"alert,omitempty"`
	Activities []Activity `json:"activities"`
}

type TicketQuery struct {
	TenantID  string    `json:"tenant_id"`
	Status    string    `json:"status"`
	Since     time.Time `json:"since"`
	SortBy    string    `json:"sort_by"`
	SortOrder string    `json:"sort_order"`
	Page      int       `json:"page"`
	PageSize  int       `json:"page_size"`
}

type TicketListResponse struct {
	Items    []Ticket `json:"items"`
	Total    int      `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"page_size"`
}

type CreateTicketRequest struct {
	TenantID    string `json:"tenant_id"`
	AlertID     string `json:"alert_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Assignee    string `json:"assignee"`
}

type UpdateTicketStatusRequest struct {
	Status   string `json:"status"`
	Assignee string `json:"assignee"`
}

type CreateProbeConfigRequest struct {
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Filters     []string `json:"filters"`
	OutputTypes []string `json:"output_types"`
}

type CreateRuleBundleRequest struct {
	TenantID    string `json:"tenant_id"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type ApplyProbeBindingRequest struct {
	TenantID      string `json:"tenant_id"`
	ProbeID       string `json:"probe_id"`
	ProbeConfigID string `json:"probe_config_id"`
	RuleBundleID  string `json:"rule_bundle_id"`
}

type DeploymentAckRequest struct {
	TenantID      string `json:"tenant_id"`
	ProbeID       string `json:"probe_id"`
	ProbeConfigID string `json:"probe_config_id"`
	RuleBundleID  string `json:"rule_bundle_id"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}

type DashboardStats struct {
	AlertsOpen    int `json:"alerts_open"`
	AlertsClosed  int `json:"alerts_closed"`
	ProbesOnline  int `json:"probes_online"`
	TicketsOpen   int `json:"tickets_open"`
	FlowsObserved int `json:"flows_observed"`
}

type TrendPoint struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type ReportSummary struct {
	AlertTrend    []TrendPoint `json:"alert_trend"`
	TicketTrend   []TrendPoint `json:"ticket_trend"`
	TopSignatures []TrendPoint `json:"top_signatures"`
	TopSourceIPs  []TrendPoint `json:"top_source_ips"`
}

type FlowQuery struct {
	TenantID string    `json:"tenant_id"`
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip"`
	AppProto string    `json:"app_proto"`
	Since    time.Time `json:"since"`
}

type UpdateAlertStatusRequest struct {
	Status   string `json:"status"`
	Assignee string `json:"assignee"`
}

type User struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Username        string    `json:"username"`
	DisplayName     string    `json:"display_name"`
	Password        string    `json:"-"`
	Status          string    `json:"status"`
	Roles           []string  `json:"roles"`
	AllowedTenants  []string  `json:"allowed_tenants,omitempty"`
	AllowedProbeIDs []string  `json:"allowed_probe_ids,omitempty"`
	Permissions     []string  `json:"permissions,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Role struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

type AuditLog struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	UserID       string    `json:"user_id"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Result       string    `json:"result"`
	CreatedAt    time.Time `json:"created_at"`
}

type Activity struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Action       string    `json:"action"`
	Operator     string    `json:"operator"`
	Detail       string    `json:"detail"`
	CreatedAt    time.Time `json:"created_at"`
}

type CreateUserRequest struct {
	TenantID        string   `json:"tenant_id"`
	Username        string   `json:"username"`
	DisplayName     string   `json:"display_name"`
	Password        string   `json:"password"`
	Roles           []string `json:"roles"`
	AllowedTenants  []string `json:"allowed_tenants"`
	AllowedProbeIDs []string `json:"allowed_probe_ids"`
}

type CreateRoleRequest struct {
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type LoginRequest struct {
	TenantID string `json:"tenant_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type QueryStat struct {
	QueryType   string    `json:"query_type"`
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id"`
	Summary     string    `json:"summary"`
	DurationMS  int64     `json:"duration_ms"`
	ResultCount int       `json:"result_count"`
	Slow        bool      `json:"slow"`
	RecordedAt  time.Time `json:"recorded_at"`
}

type ExportTask struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	UserID       string    `json:"user_id"`
	ResourceType string    `json:"resource_type"`
	Format       string    `json:"format"`
	Status       string    `json:"status"`
	QuerySummary string    `json:"query_summary"`
	FilePath     string    `json:"file_path"`
	ErrorMessage string    `json:"error_message"`
	CreatedAt    time.Time `json:"created_at"`
	CompletedAt  time.Time `json:"completed_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type ExportTaskRequest struct {
	TenantID     string     `json:"tenant_id"`
	ResourceType string     `json:"resource_type"`
	Format       string     `json:"format"`
	AlertQuery   AlertQuery `json:"alert_query"`
	FlowQuery    FlowQuery  `json:"flow_query"`
}

type NotificationChannel struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Target    string    `json:"target"`
	Enabled   bool      `json:"enabled"`
	Events    []string  `json:"events"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateNotificationChannelRequest struct {
	TenantID string   `json:"tenant_id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Target   string   `json:"target"`
	Enabled  bool     `json:"enabled"`
	Events   []string `json:"events"`
}

type NotificationRecord struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	ChannelID    string    `json:"channel_id"`
	ChannelName  string    `json:"channel_name"`
	ChannelType  string    `json:"channel_type"`
	Target       string    `json:"target"`
	EventType    string    `json:"event_type"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Status       string    `json:"status"`
	Summary      string    `json:"summary"`
	ErrorMessage string    `json:"error_message"`
	RetryCount   int       `json:"retry_count"`
	NextRetryAt  time.Time `json:"next_retry_at"`
	CreatedAt    time.Time `json:"created_at"`
	DeliveredAt  time.Time `json:"delivered_at"`
}

type NotificationTemplate struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	EventType     string    `json:"event_type"`
	TitleTemplate string    `json:"title_template"`
	BodyTemplate  string    `json:"body_template"`
	CreatedAt     time.Time `json:"created_at"`
}

type CreateNotificationTemplateRequest struct {
	TenantID      string `json:"tenant_id"`
	Name          string `json:"name"`
	EventType     string `json:"event_type"`
	TitleTemplate string `json:"title_template"`
	BodyTemplate  string `json:"body_template"`
}
