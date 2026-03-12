package store

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

type MemoryStore struct {
	mu                    sync.RWMutex
	probes                map[string]shared.Probe
	probeConfigs          map[string]shared.ProbeConfig
	ruleBundles           map[string]shared.RuleBundle
	probeBindings         map[string]shared.ProbeBinding
	deployments           map[string]shared.DeploymentRecord
	upgradePackages       map[string]shared.UpgradePackage
	probeUpgradeTasks     map[string]shared.ProbeUpgradeTask
	probeVersionHistory   map[string]shared.ProbeVersionHistory
	probeMetrics          map[string]shared.ProbeMetric
	rawEvents             map[string]shared.RawEvent
	flows                 map[string]shared.Flow
	assets                map[string]shared.Asset
	organizations         map[string]shared.Organization
	threatIntel           map[string]shared.ThreatIntel
	suppressionRules      map[string]shared.SuppressionRule
	riskPolicies          map[string]shared.RiskPolicy
	ticketPolicies        map[string]shared.TicketAutomationPolicy
	alerts                map[string]shared.Alert
	fingerprint           map[string]string
	tickets               map[string]shared.Ticket
	users                 map[string]shared.User
	roles                 map[string]shared.Role
	auditLogs             map[string]shared.AuditLog
	activities            map[string]shared.Activity
	exportTasks           map[string]shared.ExportTask
	notificationChannels  map[string]shared.NotificationChannel
	notificationTemplates map[string]shared.NotificationTemplate
	notificationRecords   map[string]shared.NotificationRecord
	tokens                map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		probes:                make(map[string]shared.Probe),
		probeConfigs:          make(map[string]shared.ProbeConfig),
		ruleBundles:           make(map[string]shared.RuleBundle),
		probeBindings:         make(map[string]shared.ProbeBinding),
		deployments:           make(map[string]shared.DeploymentRecord),
		upgradePackages:       make(map[string]shared.UpgradePackage),
		probeUpgradeTasks:     make(map[string]shared.ProbeUpgradeTask),
		probeVersionHistory:   make(map[string]shared.ProbeVersionHistory),
		probeMetrics:          make(map[string]shared.ProbeMetric),
		rawEvents:             make(map[string]shared.RawEvent),
		flows:                 make(map[string]shared.Flow),
		assets:                make(map[string]shared.Asset),
		organizations:         make(map[string]shared.Organization),
		threatIntel:           make(map[string]shared.ThreatIntel),
		suppressionRules:      make(map[string]shared.SuppressionRule),
		riskPolicies:          make(map[string]shared.RiskPolicy),
		ticketPolicies:        make(map[string]shared.TicketAutomationPolicy),
		alerts:                make(map[string]shared.Alert),
		fingerprint:           make(map[string]string),
		tickets:               make(map[string]shared.Ticket),
		users:                 make(map[string]shared.User),
		roles:                 make(map[string]shared.Role),
		auditLogs:             make(map[string]shared.AuditLog),
		activities:            make(map[string]shared.Activity),
		exportTasks:           make(map[string]shared.ExportTask),
		notificationChannels:  make(map[string]shared.NotificationChannel),
		notificationTemplates: make(map[string]shared.NotificationTemplate),
		notificationRecords:   make(map[string]shared.NotificationRecord),
		tokens:                make(map[string]string),
	}
}

func (s *MemoryStore) UpsertProbe(_ context.Context, probe shared.Probe) (shared.Probe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probes[probe.ID] = probe
	return probe, nil
}

func (s *MemoryStore) GetProbe(_ context.Context, id string) (shared.Probe, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	probe, ok := s.probes[id]
	return probe, ok, nil
}

func (s *MemoryStore) FindProbeByCode(_ context.Context, tenantID, probeCode string) (shared.Probe, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found shared.Probe
	ok := false
	for _, probe := range s.probes {
		if probe.TenantID != tenantID || probe.ProbeCode != probeCode {
			continue
		}
		if !ok || probe.LastHeartbeatAt.After(found.LastHeartbeatAt) || (probe.LastHeartbeatAt.Equal(found.LastHeartbeatAt) && probe.CreatedAt.After(found.CreatedAt)) {
			found = probe
			ok = true
		}
	}
	return found, ok, nil
}

func (s *MemoryStore) ListProbes(_ context.Context, tenantID string) ([]shared.Probe, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	latestByCode := make(map[string]shared.Probe)
	for _, probe := range s.probes {
		if tenantID != "" && probe.TenantID != tenantID {
			continue
		}
		key := probe.TenantID + "\x00" + probe.ProbeCode
		current, ok := latestByCode[key]
		if !ok || probe.LastHeartbeatAt.After(current.LastHeartbeatAt) || (probe.LastHeartbeatAt.Equal(current.LastHeartbeatAt) && probe.CreatedAt.After(current.CreatedAt)) {
			latestByCode[key] = probe
		}
	}
	out := make([]shared.Probe, 0, len(latestByCode))
	for _, probe := range latestByCode {
		out = append(out, probe)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) CreateProbeConfig(_ context.Context, config shared.ProbeConfig) (shared.ProbeConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeConfigs[config.ID] = config
	return config, nil
}

func (s *MemoryStore) GetProbeConfig(_ context.Context, id string) (shared.ProbeConfig, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.probeConfigs[id]
	return cfg, ok, nil
}

func (s *MemoryStore) ListProbeConfigs(_ context.Context, tenantID string) ([]shared.ProbeConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.ProbeConfig, 0, len(s.probeConfigs))
	for _, cfg := range s.probeConfigs {
		if tenantID != "" && cfg.TenantID != tenantID {
			continue
		}
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateRuleBundle(_ context.Context, bundle shared.RuleBundle) (shared.RuleBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ruleBundles[bundle.ID] = bundle
	return bundle, nil
}

func (s *MemoryStore) GetRuleBundle(_ context.Context, id string) (shared.RuleBundle, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bundle, ok := s.ruleBundles[id]
	return bundle, ok, nil
}

func (s *MemoryStore) ListRuleBundles(_ context.Context, tenantID string) ([]shared.RuleBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.RuleBundle, 0, len(s.ruleBundles))
	for _, bundle := range s.ruleBundles {
		if tenantID != "" && bundle.TenantID != tenantID {
			continue
		}
		out = append(out, bundle)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) UpsertProbeBinding(_ context.Context, binding shared.ProbeBinding) (shared.ProbeBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeBindings[binding.ProbeID] = binding
	return binding, nil
}

func (s *MemoryStore) GetProbeBindingByProbeID(_ context.Context, probeID string) (shared.ProbeBinding, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, ok := s.probeBindings[probeID]
	return binding, ok, nil
}

func (s *MemoryStore) ListProbeBindings(_ context.Context, tenantID string) ([]shared.ProbeBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.ProbeBinding, 0, len(s.probeBindings))
	for _, binding := range s.probeBindings {
		if tenantID != "" && binding.TenantID != tenantID {
			continue
		}
		out = append(out, binding)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateDeploymentRecord(_ context.Context, record shared.DeploymentRecord) (shared.DeploymentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deployments[record.ID] = record
	return record, nil
}

func (s *MemoryStore) ListDeploymentRecords(_ context.Context, tenantID string) ([]shared.DeploymentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.DeploymentRecord, 0, len(s.deployments))
	for _, record := range s.deployments {
		if tenantID != "" && record.TenantID != tenantID {
			continue
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateUpgradePackage(_ context.Context, pkg shared.UpgradePackage) (shared.UpgradePackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upgradePackages[pkg.ID] = pkg
	return pkg, nil
}

func (s *MemoryStore) ListUpgradePackages(_ context.Context, tenantID string) ([]shared.UpgradePackage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.UpgradePackage, 0, len(s.upgradePackages))
	for _, item := range s.upgradePackages {
		if tenantID != "" && item.TenantID != tenantID {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) FindUpgradePackageByID(_ context.Context, tenantID, id string) (shared.UpgradePackage, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.upgradePackages[id]
	if !ok || item.TenantID != tenantID {
		return shared.UpgradePackage{}, false, nil
	}
	return item, true, nil
}

func (s *MemoryStore) FindUpgradePackageByVersion(_ context.Context, tenantID, version string) (shared.UpgradePackage, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found shared.UpgradePackage
	ok := false
	for _, item := range s.upgradePackages {
		if tenantID != "" && item.TenantID != tenantID {
			continue
		}
		if strings.TrimSpace(item.Version) != strings.TrimSpace(version) {
			continue
		}
		if !ok || item.CreatedAt.After(found.CreatedAt) {
			found = item
			ok = true
		}
	}
	return found, ok, nil
}

func (s *MemoryStore) CreateProbeUpgradeTask(_ context.Context, task shared.ProbeUpgradeTask) (shared.ProbeUpgradeTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeUpgradeTasks[task.ID] = task
	return task, nil
}

func (s *MemoryStore) ListProbeUpgradeTasks(_ context.Context, tenantID string) ([]shared.ProbeUpgradeTask, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.ProbeUpgradeTask, 0, len(s.probeUpgradeTasks))
	for _, item := range s.probeUpgradeTasks {
		if tenantID != "" && item.TenantID != tenantID {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) GetPendingProbeUpgradeTask(_ context.Context, probeID string) (shared.ProbeUpgradeTask, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found shared.ProbeUpgradeTask
	ok := false
	for _, item := range s.probeUpgradeTasks {
		if item.ProbeID != probeID || item.Status != "pending" {
			continue
		}
		if !ok || item.CreatedAt.After(found.CreatedAt) {
			found = item
			ok = true
		}
	}
	return found, ok, nil
}

func (s *MemoryStore) UpdateProbeUpgradeTask(_ context.Context, task shared.ProbeUpgradeTask) (shared.ProbeUpgradeTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeUpgradeTasks[task.ID] = task
	return task, nil
}

func (s *MemoryStore) AddProbeVersionHistory(_ context.Context, item shared.ProbeVersionHistory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeVersionHistory[item.ID] = item
	return nil
}

func (s *MemoryStore) ListProbeVersionHistory(_ context.Context, tenantID, probeID string) ([]shared.ProbeVersionHistory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.ProbeVersionHistory, 0, len(s.probeVersionHistory))
	for _, item := range s.probeVersionHistory {
		if tenantID != "" && item.TenantID != tenantID {
			continue
		}
		if probeID != "" && item.ProbeID != probeID {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) AddProbeMetric(_ context.Context, metric shared.ProbeMetric) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeMetrics[metric.ID] = metric
	return nil
}

func (s *MemoryStore) ListProbeMetrics(_ context.Context, query shared.ProbeMetricQuery) ([]shared.ProbeMetric, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.ProbeMetric, 0)
	for _, metric := range s.probeMetrics {
		if query.TenantID != "" && metric.TenantID != query.TenantID {
			continue
		}
		if query.ProbeID != "" && metric.ProbeID != query.ProbeID {
			continue
		}
		if !query.Since.IsZero() && metric.CreatedAt.Before(query.Since) {
			continue
		}
		out = append(out, metric)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[:query.Limit]
	}
	return out, nil
}

func (s *MemoryStore) AddRawEvent(_ context.Context, event shared.RawEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawEvents[event.ID] = event
	return nil
}

func (s *MemoryStore) ListRawEvents(_ context.Context, tenantID string, since, until time.Time, probeIDs []string) ([]shared.RawEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.RawEvent, 0)
	for _, event := range s.rawEvents {
		if tenantID != "" && event.TenantID != tenantID {
			continue
		}
		if !since.IsZero() && event.EventTime.Before(since) {
			continue
		}
		if !until.IsZero() && event.EventTime.After(until) {
			continue
		}
		if len(probeIDs) > 0 && !containsString(probeIDs, event.ProbeID) {
			continue
		}
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].EventTime.After(out[j].EventTime)
	})
	return out, nil
}

func (s *MemoryStore) UpsertFlow(_ context.Context, flow shared.Flow) (shared.Flow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows[flow.FlowID] = flow
	return flow, nil
}

func (s *MemoryStore) ListFlowsByIDs(_ context.Context, tenantID string, flowIDs []string) ([]shared.Flow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Flow, 0)
	for _, flowID := range flowIDs {
		flow, ok := s.flows[flowID]
		if !ok {
			continue
		}
		if tenantID != "" && flow.TenantID != tenantID {
			continue
		}
		out = append(out, flow)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SeenAt.After(out[j].SeenAt)
	})
	return out, nil
}

func (s *MemoryStore) ListFlows(_ context.Context, query shared.FlowQuery) ([]shared.Flow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Flow, 0)
	for _, flow := range s.flows {
		if query.TenantID != "" && flow.TenantID != query.TenantID {
			continue
		}
		if query.SrcIP != "" && flow.SrcIP != query.SrcIP {
			continue
		}
		if query.DstIP != "" && flow.DstIP != query.DstIP {
			continue
		}
		if query.AppProto != "" && flow.AppProto != query.AppProto {
			continue
		}
		if !query.Since.IsZero() && flow.SeenAt.Before(query.Since) {
			continue
		}
		out = append(out, flow)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SeenAt.After(out[j].SeenAt) })
	return out, nil
}

func (s *MemoryStore) CreateAsset(_ context.Context, asset shared.Asset) (shared.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets[asset.ID] = asset
	return asset, nil
}

func (s *MemoryStore) ListAssets(_ context.Context, tenantID string) ([]shared.Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Asset, 0, len(s.assets))
	for _, asset := range s.assets {
		if tenantID != "" && asset.TenantID != tenantID {
			continue
		}
		out = append(out, asset)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) FindAssetByIP(_ context.Context, tenantID, ip string) (shared.Asset, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, asset := range s.assets {
		if asset.TenantID == tenantID && asset.IP == ip {
			return asset, true, nil
		}
	}
	return shared.Asset{}, false, nil
}

func (s *MemoryStore) CreateOrganization(_ context.Context, org shared.Organization) (shared.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.organizations[org.ID] = org
	return org, nil
}

func (s *MemoryStore) ListOrganizations(_ context.Context, tenantID string) ([]shared.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Organization, 0, len(s.organizations))
	for _, item := range s.organizations {
		if tenantID != "" && item.TenantID != tenantID {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) GetOrganization(_ context.Context, id string) (shared.Organization, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.organizations[id]
	return item, ok, nil
}

func (s *MemoryStore) CreateThreatIntel(_ context.Context, intel shared.ThreatIntel) (shared.ThreatIntel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.threatIntel[intel.ID] = intel
	return intel, nil
}

func (s *MemoryStore) ListThreatIntel(_ context.Context, tenantID string) ([]shared.ThreatIntel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.ThreatIntel, 0, len(s.threatIntel))
	for _, intel := range s.threatIntel {
		if tenantID != "" && intel.TenantID != tenantID {
			continue
		}
		out = append(out, intel)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) FindThreatIntelByValue(_ context.Context, tenantID, value string) ([]shared.ThreatIntel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.ThreatIntel, 0)
	for _, intel := range s.threatIntel {
		if intel.TenantID == tenantID && intel.Value == value {
			out = append(out, intel)
		}
	}
	return out, nil
}

func (s *MemoryStore) CreateSuppressionRule(_ context.Context, rule shared.SuppressionRule) (shared.SuppressionRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suppressionRules[rule.ID] = rule
	return rule, nil
}

func (s *MemoryStore) ListSuppressionRules(_ context.Context, tenantID string) ([]shared.SuppressionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.SuppressionRule, 0, len(s.suppressionRules))
	for _, rule := range s.suppressionRules {
		if tenantID != "" && rule.TenantID != tenantID {
			continue
		}
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateRiskPolicy(_ context.Context, policy shared.RiskPolicy) (shared.RiskPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.riskPolicies[policy.ID] = policy
	return policy, nil
}

func (s *MemoryStore) ListRiskPolicies(_ context.Context, tenantID string) ([]shared.RiskPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.RiskPolicy, 0, len(s.riskPolicies))
	for _, policy := range s.riskPolicies {
		if tenantID != "" && policy.TenantID != tenantID {
			continue
		}
		out = append(out, policy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateTicketAutomationPolicy(_ context.Context, policy shared.TicketAutomationPolicy) (shared.TicketAutomationPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ticketPolicies[policy.ID] = policy
	return policy, nil
}

func (s *MemoryStore) ListTicketAutomationPolicies(_ context.Context, tenantID string) ([]shared.TicketAutomationPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.TicketAutomationPolicy, 0, len(s.ticketPolicies))
	for _, item := range s.ticketPolicies {
		if tenantID != "" && item.TenantID != tenantID {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) UpsertAlertByFingerprint(_ context.Context, fp string, build func(existing *shared.Alert) shared.Alert) (shared.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.fingerprint[fp]; ok {
		current := s.alerts[id]
		updated := build(&current)
		s.alerts[id] = updated
		return updated, nil
	}
	alert := build(nil)
	s.alerts[alert.ID] = alert
	s.fingerprint[fp] = alert.ID
	return alert, nil
}

func (s *MemoryStore) GetAlert(_ context.Context, id string) (shared.Alert, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alert, ok := s.alerts[id]
	return alert, ok, nil
}

func (s *MemoryStore) UpdateAlertStatus(_ context.Context, id string, mutate func(alert shared.Alert) shared.Alert) (shared.Alert, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert, ok := s.alerts[id]
	if !ok {
		return shared.Alert{}, false, nil
	}
	alert = mutate(alert)
	s.alerts[id] = alert
	return alert, true, nil
}

func (s *MemoryStore) ListAlerts(_ context.Context, query shared.AlertQuery) ([]shared.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Alert, 0, len(s.alerts))
	for _, alert := range s.alerts {
		if query.TenantID != "" && alert.TenantID != query.TenantID {
			continue
		}
		if !query.Since.IsZero() && alert.LastSeenAt.Before(query.Since) {
			continue
		}
		if !matchAlertQuery(alert, query) {
			continue
		}
		out = append(out, alert)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	return out, nil
}

func matchAlertQuery(alert shared.Alert, query shared.AlertQuery) bool {
	conditions := make([]bool, 0, 10)
	if query.Status != "" {
		conditions = append(conditions, alert.Status == query.Status)
	}
	if query.SrcIP != "" {
		conditions = append(conditions, alert.SrcIP == query.SrcIP)
	}
	if query.DstIP != "" {
		conditions = append(conditions, alert.DstIP == query.DstIP)
	}
	if query.Signature != "" {
		conditions = append(conditions, strings.Contains(strings.ToLower(alert.Signature), strings.ToLower(query.Signature)))
	}
	if query.Category != "" {
		conditions = append(conditions, strings.Contains(strings.ToLower(alert.Category), strings.ToLower(query.Category)))
	}
	if query.Probe != "" {
		matched := false
		for _, probeID := range alert.ProbeIDs {
			if strings.Contains(strings.ToLower(probeID), strings.ToLower(query.Probe)) {
				matched = true
				break
			}
		}
		conditions = append(conditions, matched)
	}
	if query.Severity != 0 {
		conditions = append(conditions, alert.Severity == query.Severity)
	}
	if query.Assignee != "" {
		conditions = append(conditions, alert.Assignee == query.Assignee)
	}
	if query.AttackResult != "" {
		conditions = append(conditions, alert.AttackResult == query.AttackResult)
	}
	if query.MinProbeCount > 0 {
		conditions = append(conditions, alert.ProbeCount >= query.MinProbeCount)
	}
	if query.MaxProbeCount > 0 {
		conditions = append(conditions, alert.ProbeCount <= query.MaxProbeCount)
	}
	if query.MinWindowMins > 0 {
		conditions = append(conditions, alert.WindowMinutes >= query.MinWindowMins)
	}
	if query.MaxWindowMins > 0 {
		conditions = append(conditions, alert.WindowMinutes <= query.MaxWindowMins)
	}
	if len(conditions) == 0 {
		return true
	}
	if strings.EqualFold(query.MatchMode, "any") {
		for _, matched := range conditions {
			if matched {
				return true
			}
		}
		return false
	}
	for _, matched := range conditions {
		if !matched {
			return false
		}
	}
	return true
}

func (s *MemoryStore) CreateTicket(_ context.Context, ticket shared.Ticket) (shared.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickets[ticket.ID] = ticket
	return ticket, nil
}

func (s *MemoryStore) ListTickets(_ context.Context, tenantID string) ([]shared.Ticket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Ticket, 0, len(s.tickets))
	for _, ticket := range s.tickets {
		if tenantID != "" && ticket.TenantID != tenantID {
			continue
		}
		out = append(out, ticket)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) GetTicket(_ context.Context, id string) (shared.Ticket, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ticket, ok := s.tickets[id]
	return ticket, ok, nil
}

func (s *MemoryStore) UpdateTicketStatus(_ context.Context, id string, mutate func(ticket shared.Ticket) shared.Ticket) (shared.Ticket, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, ok := s.tickets[id]
	if !ok {
		return shared.Ticket{}, false, nil
	}
	ticket = mutate(ticket)
	s.tickets[id] = ticket
	return ticket, true, nil
}

func (s *MemoryStore) ListTicketsByAlert(_ context.Context, tenantID, alertID string) ([]shared.Ticket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Ticket, 0)
	for _, ticket := range s.tickets {
		if tenantID != "" && ticket.TenantID != tenantID {
			continue
		}
		if alertID != "" && ticket.AlertID != alertID {
			continue
		}
		out = append(out, ticket)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) CreateUser(_ context.Context, user shared.User) (shared.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	return user, nil
}

func (s *MemoryStore) ListUsers(_ context.Context, tenantID string) ([]shared.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.User, 0, len(s.users))
	for _, user := range s.users {
		if tenantID != "" && user.TenantID != tenantID {
			continue
		}
		out = append(out, user)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) FindUser(_ context.Context, tenantID, username string) (shared.User, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.TenantID == tenantID && user.Username == username {
			return user, true, nil
		}
	}
	return shared.User{}, false, nil
}

func (s *MemoryStore) GetUser(_ context.Context, id string) (shared.User, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	return user, ok, nil
}

func (s *MemoryStore) CreateRole(_ context.Context, role shared.Role) (shared.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[role.ID] = role
	return role, nil
}

func (s *MemoryStore) ListRoles(_ context.Context, tenantID string) ([]shared.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Role, 0, len(s.roles))
	for _, role := range s.roles {
		if tenantID != "" && role.TenantID != tenantID {
			continue
		}
		out = append(out, role)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) SaveToken(_ context.Context, token, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = userID
	return nil
}

func (s *MemoryStore) LookupToken(_ context.Context, token string) (shared.User, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userID, ok := s.tokens[token]
	if !ok {
		return shared.User{}, false, nil
	}
	user, ok := s.users[userID]
	return user, ok, nil
}

func (s *MemoryStore) AddAuditLog(_ context.Context, log shared.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs[log.ID] = log
	return nil
}

func (s *MemoryStore) ListAuditLogs(_ context.Context, tenantID string) ([]shared.AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.AuditLog, 0, len(s.auditLogs))
	for _, log := range s.auditLogs {
		if tenantID != "" && log.TenantID != tenantID {
			continue
		}
		out = append(out, log)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) AddActivity(_ context.Context, activity shared.Activity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activities[activity.ID] = activity
	return nil
}

func (s *MemoryStore) ListActivities(_ context.Context, tenantID, resourceType, resourceID string) ([]shared.Activity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Activity, 0, len(s.activities))
	for _, activity := range s.activities {
		if tenantID != "" && activity.TenantID != tenantID {
			continue
		}
		if resourceType != "" && activity.ResourceType != resourceType {
			continue
		}
		if resourceID != "" && activity.ResourceID != resourceID {
			continue
		}
		out = append(out, activity)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateExportTask(_ context.Context, task shared.ExportTask) (shared.ExportTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exportTasks[task.ID] = task
	return task, nil
}

func (s *MemoryStore) UpdateExportTask(_ context.Context, task shared.ExportTask) (shared.ExportTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exportTasks[task.ID] = task
	return task, nil
}

func (s *MemoryStore) GetExportTask(_ context.Context, id string) (shared.ExportTask, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	task, ok := s.exportTasks[id]
	return task, ok, nil
}

func (s *MemoryStore) ListExportTasks(_ context.Context, tenantID string) ([]shared.ExportTask, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.ExportTask, 0, len(s.exportTasks))
	for _, task := range s.exportTasks {
		if tenantID != "" && task.TenantID != tenantID {
			continue
		}
		out = append(out, task)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateNotificationChannel(_ context.Context, channel shared.NotificationChannel) (shared.NotificationChannel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notificationChannels[channel.ID] = channel
	return channel, nil
}

func (s *MemoryStore) CreateNotificationTemplate(_ context.Context, template shared.NotificationTemplate) (shared.NotificationTemplate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notificationTemplates[template.ID] = template
	return template, nil
}

func (s *MemoryStore) ListNotificationTemplates(_ context.Context, tenantID string) ([]shared.NotificationTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.NotificationTemplate, 0, len(s.notificationTemplates))
	for _, template := range s.notificationTemplates {
		if tenantID != "" && template.TenantID != tenantID {
			continue
		}
		out = append(out, template)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) ListNotificationChannels(_ context.Context, tenantID string) ([]shared.NotificationChannel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.NotificationChannel, 0, len(s.notificationChannels))
	for _, channel := range s.notificationChannels {
		if tenantID != "" && channel.TenantID != tenantID {
			continue
		}
		out = append(out, channel)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateNotificationRecord(_ context.Context, record shared.NotificationRecord) (shared.NotificationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notificationRecords[record.ID] = record
	return record, nil
}

func (s *MemoryStore) UpdateNotificationRecord(_ context.Context, record shared.NotificationRecord) (shared.NotificationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notificationRecords[record.ID] = record
	return record, nil
}

func (s *MemoryStore) ListNotificationRecords(_ context.Context, tenantID string) ([]shared.NotificationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.NotificationRecord, 0, len(s.notificationRecords))
	for _, record := range s.notificationRecords {
		if tenantID != "" && record.TenantID != tenantID {
			continue
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
