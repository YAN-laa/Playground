package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yan/ndr-platform/internal/server/pipeline"
	"github.com/yan/ndr-platform/internal/server/search"
	"github.com/yan/ndr-platform/internal/server/store"
	"github.com/yan/ndr-platform/internal/shared"
	"golang.org/x/crypto/bcrypt"
)

type AuthConfig struct {
	Mode      string
	JWTSecret string
	JWTTTL    time.Duration
}

type Service struct {
	store               store.Repository
	search              search.Engine
	indexer             search.Indexer
	pipeline            *pipeline.Processor
	queries             *queryStats
	exportDir           string
	packageDir          string
	exportTTL           time.Duration
	probeOfflineAfter   time.Duration
	authMode            string
	jwtSecret           []byte
	jwtTTL              time.Duration
	notifyRetryMax      int
	notifyRetryBackoff  time.Duration
	notifyRetryScanIntv time.Duration
	slaScanInterval     time.Duration
	slaByPriority       map[string]time.Duration
	httpClient          *http.Client
	counter             uint64
}

func New(store store.Repository, engine search.Engine, indexer search.Indexer, slowQueryThreshold time.Duration, exportDir string, exportTTL time.Duration, exportCleanupInterval time.Duration, authConfig AuthConfig) *Service {
	if engine == nil {
		engine = search.NewLocalEngine(store)
	}
	if indexer == nil {
		indexer = search.NoopIndexer{}
	}
	svc := &Service{
		store:               store,
		search:              engine,
		indexer:             indexer,
		pipeline:            pipeline.New(positiveDuration(envDuration("APP_ALERT_AGG_WINDOW", 30*time.Minute), 30*time.Minute)),
		queries:             newQueryStats(200, slowQueryThreshold),
		exportDir:           exportDir,
		packageDir:          strings.TrimSpace(os.Getenv("APP_PACKAGE_DIR")),
		exportTTL:           exportTTL,
		probeOfflineAfter:   positiveDuration(envDuration("APP_PROBE_OFFLINE_AFTER", 45*time.Second), 45*time.Second),
		authMode:            normalizeAuthMode(authConfig.Mode),
		jwtSecret:           []byte(strings.TrimSpace(authConfig.JWTSecret)),
		jwtTTL:              positiveDuration(authConfig.JWTTTL, 12*time.Hour),
		notifyRetryMax:      positiveInt(envInt("APP_NOTIFY_RETRY_MAX", 2), 2),
		notifyRetryBackoff:  positiveDuration(envDuration("APP_NOTIFY_RETRY_BACKOFF", 500*time.Millisecond), 500*time.Millisecond),
		notifyRetryScanIntv: positiveDuration(envDuration("APP_NOTIFY_RETRY_SCAN_INTERVAL", 30*time.Second), 30*time.Second),
		slaScanInterval:     positiveDuration(envDuration("APP_TICKET_SLA_SCAN_INTERVAL", time.Minute), time.Minute),
		slaByPriority: map[string]time.Duration{
			"critical": positiveDuration(envDuration("APP_SLA_CRITICAL", 30*time.Minute), 30*time.Minute),
			"high":     positiveDuration(envDuration("APP_SLA_HIGH", 4*time.Hour), 4*time.Hour),
			"medium":   positiveDuration(envDuration("APP_SLA_MEDIUM", 8*time.Hour), 8*time.Hour),
			"low":      positiveDuration(envDuration("APP_SLA_LOW", 24*time.Hour), 24*time.Hour),
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	if svc.exportDir == "" {
		svc.exportDir = filepath.Join(".", "exports")
	}
	if svc.packageDir == "" {
		svc.packageDir = filepath.Join(".", "packages")
	}
	if svc.exportTTL <= 0 {
		svc.exportTTL = 24 * time.Hour
	}
	_ = os.MkdirAll(svc.exportDir, 0o755)
	_ = os.MkdirAll(svc.packageDir, 0o755)
	svc.pipeline.SetResolvers(
		func(tenantID, ip string) (*shared.Asset, error) {
			asset, ok, err := svc.store.FindAssetByIP(context.Background(), tenantID, ip)
			if err != nil || !ok {
				return nil, err
			}
			return &asset, nil
		},
		func(tenantID, value string) ([]shared.ThreatIntel, error) {
			return svc.store.FindThreatIntelByValue(context.Background(), tenantID, value)
		},
		func(tenantID string) ([]shared.SuppressionRule, error) {
			return svc.store.ListSuppressionRules(context.Background(), tenantID)
		},
		func(tenantID string) (*shared.RiskPolicy, error) {
			policies, err := svc.store.ListRiskPolicies(context.Background(), tenantID)
			if err != nil {
				return nil, err
			}
			for _, policy := range policies {
				if policy.Enabled {
					return &policy, nil
				}
			}
			return nil, nil
		},
	)
	svc.bootstrap()
	go svc.startExportCleanupLoop(positiveDuration(exportCleanupInterval, time.Hour))
	go svc.startSLALoop()
	go svc.startNotificationRetryLoop()
	return svc
}

func (s *Service) nextID(prefix string) string {
	id := atomic.AddUint64(&s.counter, 1)
	return fmt.Sprintf("%s-%d-%06d", prefix, time.Now().UTC().UnixNano(), id)
}

func (s *Service) RegisterProbe(ctx context.Context, req shared.RegisterProbeRequest) (shared.Probe, error) {
	now := time.Now().UTC()
	probeID := s.nextID("probe")
	createdAt := now
	if existing, ok, err := s.store.FindProbeByCode(ctx, req.TenantID, req.ProbeCode); err != nil {
		return shared.Probe{}, err
	} else if ok {
		probeID = existing.ID
		createdAt = existing.CreatedAt
	}
	probe := shared.Probe{
		ID:              probeID,
		TenantID:        req.TenantID,
		ProbeCode:       req.ProbeCode,
		Name:            req.Name,
		Status:          "online",
		Version:         req.Version,
		RuleVersion:     req.RuleVersion,
		LastHeartbeatAt: now,
		CreatedAt:       createdAt,
	}
	created, err := s.store.UpsertProbe(ctx, probe)
	if err == nil {
		_ = s.addActivity(ctx, req.TenantID, "probe", created.ID, "register_probe", "", created.Name)
	}
	return created, err
}

func (s *Service) Heartbeat(ctx context.Context, req shared.HeartbeatRequest) (shared.Probe, bool, error) {
	probe, ok, err := s.store.GetProbe(ctx, req.ProbeID)
	if err != nil || !ok {
		return probe, ok, err
	}
	if !ok {
		return shared.Probe{}, false, nil
	}
	probe.Status = req.Status
	probe.CPUUsage = req.CPUUsage
	probe.MemUsage = req.MemUsage
	probe.DropRate = req.DropRate
	probe.LastHeartbeatAt = time.Now().UTC()
	updated, err := s.store.UpsertProbe(ctx, probe)
	if err == nil {
		_ = s.store.AddProbeMetric(ctx, shared.ProbeMetric{
			ID:        s.nextID("probe-metric"),
			TenantID:  probe.TenantID,
			ProbeID:   probe.ID,
			CPUUsage:  req.CPUUsage,
			MemUsage:  req.MemUsage,
			DropRate:  req.DropRate,
			CreatedAt: time.Now().UTC(),
		})
		_ = s.addActivity(ctx, probe.TenantID, "probe", probe.ID, "heartbeat", "", probe.Status)
	}
	return updated, true, err
}

func (s *Service) BatchApplyProbeBinding(ctx context.Context, req shared.BatchApplyProbeBindingRequest, operatorID string) (shared.BatchApplyProbeBindingResponse, error) {
	out := make([]shared.ProbeBinding, 0, len(req.ProbeIDs))
	for _, probeID := range req.ProbeIDs {
		binding, err := s.ApplyProbeBinding(ctx, shared.ApplyProbeBindingRequest{
			TenantID:      req.TenantID,
			ProbeID:       probeID,
			ProbeConfigID: req.ProbeConfigID,
			RuleBundleID:  req.RuleBundleID,
		}, operatorID)
		if err != nil {
			return shared.BatchApplyProbeBindingResponse{}, err
		}
		out = append(out, binding)
	}
	return shared.BatchApplyProbeBindingResponse{
		Requested: len(req.ProbeIDs),
		Applied:   len(out),
		Items:     out,
	}, nil
}

func (s *Service) Ingest(ctx context.Context, batch shared.EventBatch) ([]shared.Alert, error) {
	alerts := make([]shared.Alert, 0)
	flows := make([]shared.Flow, 0)
	for _, event := range batch.Events {
		eventTime := pipelineParseTime(event.Timestamp)
		rawEvent := shared.RawEvent{
			ID:         s.nextID("raw"),
			TenantID:   batch.TenantID,
			ProbeID:    batch.ProbeID,
			EventType:  event.EventType,
			EventTime:  eventTime,
			IngestTime: time.Now().UTC(),
			Payload:    event,
		}
		if err := s.store.AddRawEvent(ctx, rawEvent); err != nil {
			return nil, err
		}
		if event.FlowID != "" {
			flow, err := s.store.UpsertFlow(ctx, shared.Flow{
				ID:       s.nextID("flow"),
				TenantID: batch.TenantID,
				ProbeID:  batch.ProbeID,
				FlowID:   event.FlowID,
				SrcIP:    event.SrcIP,
				SrcPort:  event.SrcPort,
				DstIP:    event.DstIP,
				DstPort:  event.DstPort,
				Proto:    event.Proto,
				AppProto: event.AppProto,
				SeenAt:   eventTime,
			})
			if err != nil {
				return nil, err
			}
			flows = append(flows, flow)
		}
		projection, ok := s.pipeline.Process(batch.TenantID, batch.ProbeID, event)
		if !ok {
			continue
		}
		alert, err := s.store.UpsertAlertByFingerprint(ctx, projection.Fingerprint, func(existing *shared.Alert) shared.Alert {
			if existing == nil {
				base := projection.Alert
				base.ID = s.nextID("alert")
				base.Fingerprint = projection.Fingerprint
				base.ProbeCount = len(base.ProbeIDs)
				base.WindowMinutes = alertWindowMinutes(base.FirstSeenAt, base.LastSeenAt)
				return base
			}
			updated := *existing
			updated.LastSeenAt = projection.EventTime
			updated.EventCount++
			if !contains(updated.ProbeIDs, batch.ProbeID) {
				updated.ProbeIDs = append(updated.ProbeIDs, batch.ProbeID)
			}
			if projection.Alert.RiskScore > updated.RiskScore {
				updated.RiskScore = projection.Alert.RiskScore
			}
			if projection.Alert.Severity != 0 && (updated.Severity == 0 || projection.Alert.Severity < updated.Severity) {
				updated.Severity = projection.Alert.Severity
			}
			updated.AttackResult = mergeAttackResult(updated.AttackResult, projection.Alert.AttackResult)
			if updated.Status == "closed" {
				updated.Status = "new"
			}
			updated.ProbeCount = len(updated.ProbeIDs)
			updated.WindowMinutes = alertWindowMinutes(updated.FirstSeenAt, updated.LastSeenAt)
			return updated
		})
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	if batchIndexer, ok := s.indexer.(search.BatchIndexer); ok {
		if err := batchIndexer.IndexFlows(ctx, flows); err != nil {
			log.Printf("flow index failed: tenant=%s probe=%s err=%v", batch.TenantID, batch.ProbeID, err)
		}
		if err := batchIndexer.IndexAlerts(ctx, alerts); err != nil {
			log.Printf("alert index failed: tenant=%s probe=%s alerts=%d err=%v", batch.TenantID, batch.ProbeID, len(alerts), err)
		}
		return alerts, nil
	}
	for _, flow := range flows {
		if err := s.indexer.IndexFlow(ctx, flow); err != nil {
			log.Printf("flow index failed: tenant=%s probe=%s flow=%s err=%v", batch.TenantID, batch.ProbeID, flow.ID, err)
		}
	}
	for _, alert := range alerts {
		if err := s.indexer.IndexAlert(ctx, alert); err != nil {
			log.Printf("alert index failed: tenant=%s probe=%s alert=%s err=%v", batch.TenantID, batch.ProbeID, alert.ID, err)
		}
	}
	return alerts, nil
}

func (s *Service) GetAlertDetail(ctx context.Context, id string) (shared.AlertDetail, bool, error) {
	alert, ok, err := s.store.GetAlert(ctx, id)
	if err != nil || !ok {
		return shared.AlertDetail{}, ok, err
	}
	since, until := alertDetailScope(alert)
	rawEvents, err := s.store.ListRawEvents(ctx, alert.TenantID, since, until, alert.ProbeIDs)
	if err != nil {
		return shared.AlertDetail{}, false, err
	}
	events := make([]shared.RawEvent, 0)
	contextEvents := make([]shared.RawEvent, 0)
	flowIDs := make([]string, 0)
	for _, event := range rawEvents {
		payload := event.Payload
		if payload.EventType != "alert" || payload.Alert == nil {
			continue
		}
		if payload.SrcIP == alert.SrcIP &&
			payload.DstIP == alert.DstIP &&
			payload.DstPort == alert.DstPort &&
			payload.Proto == alert.Proto &&
			payload.Alert.SignatureID == alert.SignatureID {
			events = append(events, event)
			if payload.FlowID != "" && !contains(flowIDs, payload.FlowID) {
				flowIDs = append(flowIDs, payload.FlowID)
			}
		}
	}
	events = limitRawEvents(events, 16)
	flowIDs = limitStrings(flowIDs, 8)
	for _, event := range rawEvents {
		payload := event.Payload
		if payload.FlowID == "" || !contains(flowIDs, payload.FlowID) {
			continue
		}
		if payload.EventType == "alert" {
			continue
		}
		contextEvents = append(contextEvents, event)
	}
	contextEvents = limitRawEvents(contextEvents, 40)
	flows, err := s.store.ListFlowsByIDs(ctx, alert.TenantID, flowIDs)
	if err != nil {
		return shared.AlertDetail{}, false, err
	}
	flows = limitFlows(flows, 12)
	tickets, err := s.store.ListTicketsByAlert(ctx, alert.TenantID, alert.ID)
	if err != nil {
		return shared.AlertDetail{}, false, err
	}
	activities := make([]shared.Activity, 0)
	ticketIDs := make([]string, 0, len(tickets))
	for _, ticket := range tickets {
		ticketIDs = append(ticketIDs, ticket.ID)
	}
	alertActivities, err := s.store.ListActivities(ctx, alert.TenantID, "alert", alert.ID)
	if err != nil {
		return shared.AlertDetail{}, false, err
	}
	activities = append(activities, alertActivities...)
	for _, ticketID := range ticketIDs {
		items, err := s.store.ListActivities(ctx, alert.TenantID, "ticket", ticketID)
		if err != nil {
			return shared.AlertDetail{}, false, err
		}
		activities = append(activities, items...)
	}
	similarSource, err := s.findSimilarAlerts(ctx, alert, "source")
	if err != nil {
		return shared.AlertDetail{}, false, err
	}
	similarTarget, err := s.findSimilarAlerts(ctx, alert, "target")
	if err != nil {
		return shared.AlertDetail{}, false, err
	}
	decisionBasis := buildAlertDecisionBasis(alert, events, contextEvents)
	alert.AttackResult = decisionBasis.AttackResult
	packetEvidence := buildPacketEvidence(events, contextEvents)
	return shared.AlertDetail{
		Alert:               alert,
		Events:              events,
		ContextEvents:       contextEvents,
		Flows:               flows,
		Tickets:             tickets,
		Activities:          activities,
		DecisionBasis:       decisionBasis,
		PacketEvidence:      packetEvidence,
		SameSourceTimeline:  limitTimelineItems(buildRelatedAlertTimeline("source", alert, append([]shared.Alert{alert}, similarSource...), rawEvents), 30),
		SameTargetTimeline:  limitTimelineItems(buildRelatedAlertTimeline("target", alert, append([]shared.Alert{alert}, similarTarget...), rawEvents), 30),
		SameFlowTimeline:    limitTimelineItems(buildFlowTimeline(events, contextEvents), 40),
		SimilarSourceAlerts: similarSource,
		SimilarTargetAlerts: similarTarget,
	}, true, nil
}

func (s *Service) ListAlerts(ctx context.Context, tenantID, status string, since time.Time) ([]shared.Alert, error) {
	return s.store.ListAlerts(ctx, shared.AlertQuery{
		TenantID: tenantID,
		Status:   status,
		Since:    since,
	})
}

func (s *Service) SearchAlerts(ctx context.Context, query shared.AlertQuery) (shared.AlertListResponse, error) {
	return s.search.SearchAlerts(ctx, query)
}

func (s *Service) SearchAlertsForUser(ctx context.Context, user shared.User, query shared.AlertQuery) (shared.AlertListResponse, error) {
	if len(user.AllowedAssetIDs) > 0 || len(user.AllowedOrgIDs) > 0 {
		assetIDs, _, err := s.resolveScopeAssets(ctx, user, query.TenantID)
		if err != nil {
			return shared.AlertListResponse{}, err
		}
		query.AllowedAssetIDs = assetIDs
	}
	result, err := s.search.SearchAlerts(ctx, query)
	if err != nil {
		return shared.AlertListResponse{}, err
	}
	filtered := make([]shared.Alert, 0, len(result.Items))
	for _, item := range result.Items {
		if !s.CanAccessAlert(ctx, user, item) {
			continue
		}
		filtered = append(filtered, item)
	}
	result.Items = filtered
	result.Total = len(filtered)
	return result, nil
}

func (s *Service) SearchRawAlertsForUser(ctx context.Context, user shared.User, query shared.RawAlertQuery) (shared.RawAlertListResponse, error) {
	since := query.Since
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}
	probeIDs := []string(nil)
	if query.ProbeID != "" {
		probeIDs = []string{query.ProbeID}
	}
	if len(user.AllowedProbeIDs) > 0 && !containsString(user.Permissions, "*") {
		probeIDs = intersectStrings(probeIDs, user.AllowedProbeIDs)
		if query.ProbeID == "" {
			probeIDs = append([]string{}, user.AllowedProbeIDs...)
		} else if len(probeIDs) == 0 {
			page, pageSize := normalizePage(query.Page, query.PageSize)
			return shared.RawAlertListResponse{Items: []shared.RawAlertItem{}, Total: 0, Page: page, PageSize: pageSize}, nil
		}
	}
	rawEvents, err := s.store.ListRawEvents(ctx, query.TenantID, since, time.Time{}, probeIDs)
	if err != nil {
		return shared.RawAlertListResponse{}, err
	}
	items := make([]shared.RawAlertItem, 0)
	for _, event := range rawEvents {
		if event.Payload.EventType != "alert" || event.Payload.Alert == nil {
			continue
		}
		item := rawAlertItemFromEvent(event)
		if query.SrcIP != "" && item.SrcIP != query.SrcIP {
			continue
		}
		if query.DstIP != "" && item.DstIP != query.DstIP {
			continue
		}
		if query.Signature != "" && !strings.Contains(strings.ToLower(item.Signature), strings.ToLower(query.Signature)) {
			continue
		}
		if query.Severity != 0 && item.Severity != query.Severity {
			continue
		}
		if query.AttackResult != "" && item.AttackResult != query.AttackResult {
			continue
		}
		if !s.canAccessRawAlertItem(ctx, user, item) {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].EventTime.After(items[j].EventTime)
	})
	page, pageSize := normalizePage(query.Page, query.PageSize)
	total := len(items)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return shared.RawAlertListResponse{
		Items:    items[start:end],
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

func (s *Service) GetRawAlertDetail(ctx context.Context, user shared.User, id string) (shared.RawAlertDetail, bool, error) {
	rawEvents, err := s.store.ListRawEvents(ctx, "", time.Time{}, time.Time{}, nil)
	if err != nil {
		return shared.RawAlertDetail{}, false, err
	}
	var target shared.RawEvent
	found := false
	for _, event := range rawEvents {
		if event.ID != id {
			continue
		}
		target = event
		found = true
		break
	}
	if !found || target.Payload.EventType != "alert" || target.Payload.Alert == nil {
		return shared.RawAlertDetail{}, false, nil
	}
	item := rawAlertItemFromEvent(target)
	if !s.CanAccessTenant(user, item.TenantID) || !s.canAccessRawAlertItem(ctx, user, item) {
		return shared.RawAlertDetail{}, false, nil
	}
	contextEvents := make([]shared.RawEvent, 0)
	if target.Payload.FlowID != "" {
		for _, event := range rawEvents {
			if event.Payload.FlowID == target.Payload.FlowID && event.ID != target.ID {
				contextEvents = append(contextEvents, event)
			}
		}
	}
	flows, err := s.store.ListFlowsByIDs(ctx, target.TenantID, []string{target.Payload.FlowID})
	if err != nil {
		return shared.RawAlertDetail{}, false, err
	}
	alerts, err := s.store.ListAlerts(ctx, shared.AlertQuery{
		TenantID:  target.TenantID,
		SrcIP:     target.Payload.SrcIP,
		DstIP:     target.Payload.DstIP,
		Signature: target.Payload.Alert.Signature,
	})
	if err != nil {
		return shared.RawAlertDetail{}, false, err
	}
	filteredAlerts := make([]shared.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if s.CanAccessAlert(ctx, user, alert) {
			filteredAlerts = append(filteredAlerts, alert)
		}
	}
	return shared.RawAlertDetail{
		Item:            item,
		Event:           target,
		ContextEvents:   contextEvents,
		Flows:           flows,
		PacketEvidence:  buildPacketEvidence([]shared.RawEvent{target}, contextEvents),
		AggregateAlerts: filteredAlerts,
	}, true, nil
}

func (s *Service) ListFlowsForUser(ctx context.Context, user shared.User, query shared.FlowQuery) ([]shared.Flow, error) {
	if len(user.AllowedAssetIDs) > 0 || len(user.AllowedOrgIDs) > 0 {
		_, ips, err := s.resolveScopeAssets(ctx, user, query.TenantID)
		if err != nil {
			return nil, err
		}
		query.AllowedIPs = ips
	}
	items, err := s.ListFlows(ctx, query)
	if err != nil {
		return nil, err
	}
	filtered := make([]shared.Flow, 0, len(items))
	for _, item := range items {
		if s.CanAccessFlow(ctx, user, item) {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func (s *Service) GetAlert(ctx context.Context, id string) (shared.Alert, bool, error) {
	return s.store.GetAlert(ctx, id)
}

func (s *Service) UpdateAlertStatus(ctx context.Context, id string, req shared.UpdateAlertStatusRequest) (shared.Alert, bool, error) {
	alert, ok, err := s.store.UpdateAlertStatus(ctx, id, func(alert shared.Alert) shared.Alert {
		if req.Status != "" {
			alert.Status = req.Status
		}
		if req.Assignee != "" {
			alert.Assignee = req.Assignee
		}
		return alert
	})
	if err != nil || !ok {
		return alert, ok, err
	}
	if ok {
		if err := s.addAuditLog(ctx, alert.TenantID, req.Assignee, "update_alert_status", "alert", alert.ID, "success"); err != nil {
			return shared.Alert{}, false, err
		}
		_ = s.addActivity(ctx, alert.TenantID, "alert", alert.ID, "update_alert_status", req.Assignee, alert.Status)
		if err := s.indexer.IndexAlert(ctx, alert); err != nil {
			log.Printf("alert reindex failed: tenant=%s alert=%s err=%v", alert.TenantID, alert.ID, err)
		}
		s.dispatchNotification(ctx, alert.TenantID, "alert.updated", "alert", alert.ID, alert)
	}
	return alert, ok, nil
}

func (s *Service) BatchUpdateAlertStatus(ctx context.Context, req shared.BatchUpdateAlertStatusRequest) (shared.BatchUpdateAlertStatusResponse, error) {
	items := make([]shared.Alert, 0, len(req.AlertIDs))
	for _, alertID := range uniqueStrings(req.AlertIDs) {
		alert, ok, err := s.UpdateAlertStatus(ctx, alertID, shared.UpdateAlertStatusRequest{
			Status:   req.Status,
			Assignee: req.Assignee,
		})
		if err != nil {
			return shared.BatchUpdateAlertStatusResponse{}, err
		}
		if !ok {
			continue
		}
		if req.TenantID != "" && alert.TenantID != req.TenantID {
			continue
		}
		items = append(items, alert)
	}
	return shared.BatchUpdateAlertStatusResponse{
		Requested: len(uniqueStrings(req.AlertIDs)),
		Updated:   len(items),
		Items:     items,
	}, nil
}

func (s *Service) CreateTicket(ctx context.Context, req shared.CreateTicketRequest) (shared.Ticket, bool, error) {
	alert, ok, err := s.store.GetAlert(ctx, req.AlertID)
	if err != nil || !ok {
		return shared.Ticket{}, ok, err
	}
	if !ok {
		return shared.Ticket{}, false, nil
	}
	now := time.Now().UTC()
	ticket := shared.Ticket{
		ID:          s.nextID("ticket"),
		TenantID:    req.TenantID,
		AlertID:     req.AlertID,
		Title:       req.Title,
		Description: req.Description,
		Priority:    req.Priority,
		Status:      "open",
		Assignee:    req.Assignee,
		SLADeadline: now.Add(s.slaDuration(req.Priority)),
		SLAStatus:   "active",
		CreatedAt:   now,
	}
	if _, err := s.store.CreateTicket(ctx, ticket); err != nil {
		return shared.Ticket{}, false, err
	}
	if _, _, err := s.store.UpdateAlertStatus(ctx, alert.ID, func(a shared.Alert) shared.Alert {
		a.Status = "in_progress"
		if req.Assignee != "" {
			a.Assignee = req.Assignee
		}
		return a
	}); err != nil {
		return shared.Ticket{}, false, err
	}
	if updatedAlert, ok, err := s.store.GetAlert(ctx, alert.ID); err == nil && ok {
		if err := s.indexer.IndexAlert(ctx, updatedAlert); err != nil {
			log.Printf("alert reindex failed after ticket creation: tenant=%s alert=%s err=%v", updatedAlert.TenantID, updatedAlert.ID, err)
		}
	}
	if err := s.addAuditLog(ctx, req.TenantID, req.Assignee, "create_ticket", "ticket", ticket.ID, "success"); err != nil {
		return shared.Ticket{}, false, err
	}
	_ = s.addActivity(ctx, req.TenantID, "ticket", ticket.ID, "create_ticket", req.Assignee, ticket.Title)
	s.dispatchNotification(ctx, req.TenantID, "ticket.created", "ticket", ticket.ID, ticket)
	return ticket, true, nil
}

func (s *Service) BatchCreateTickets(ctx context.Context, req shared.BatchCreateTicketRequest) (shared.BatchCreateTicketResponse, error) {
	items := make([]shared.Ticket, 0, len(req.AlertIDs))
	for _, alertID := range uniqueStrings(req.AlertIDs) {
		titlePrefix := strings.TrimSpace(req.TitlePrefix)
		if titlePrefix == "" {
			titlePrefix = "批量处置工单"
		}
		ticket, ok, err := s.CreateTicket(ctx, shared.CreateTicketRequest{
			TenantID:    req.TenantID,
			AlertID:     alertID,
			Title:       fmt.Sprintf("%s - %s", titlePrefix, alertID),
			Description: req.Description,
			Priority:    req.Priority,
			Assignee:    req.Assignee,
		})
		if err != nil {
			return shared.BatchCreateTicketResponse{}, err
		}
		if ok {
			items = append(items, ticket)
		}
	}
	return shared.BatchCreateTicketResponse{
		Requested: len(uniqueStrings(req.AlertIDs)),
		Created:   len(items),
		Items:     items,
	}, nil
}

func (s *Service) ListTickets(ctx context.Context, query shared.TicketQuery) (shared.TicketListResponse, error) {
	items, err := s.store.ListTickets(ctx, query.TenantID)
	if err != nil {
		return shared.TicketListResponse{}, err
	}
	filtered := make([]shared.Ticket, 0, len(items))
	for _, ticket := range items {
		if query.Status != "" && ticket.Status != query.Status {
			continue
		}
		if !query.Since.IsZero() && ticket.CreatedAt.Before(query.Since) {
			continue
		}
		filtered = append(filtered, ticket)
	}
	sortTickets(filtered, query.SortBy, query.SortOrder)
	page, pageSize := normalizePage(query.Page, query.PageSize)
	return shared.TicketListResponse{
		Items:    paginateTickets(filtered, page, pageSize),
		Total:    len(filtered),
		Page:     page,
		PageSize: pageSize,
	}, nil
}

func (s *Service) ListTicketsForUser(ctx context.Context, user shared.User, query shared.TicketQuery) (shared.TicketListResponse, error) {
	result, err := s.ListTickets(ctx, query)
	if err != nil {
		return shared.TicketListResponse{}, err
	}
	filtered := make([]shared.Ticket, 0, len(result.Items))
	for _, item := range result.Items {
		if s.CanAccessTicket(ctx, user, item) {
			filtered = append(filtered, item)
		}
	}
	result.Items = filtered
	result.Total = len(filtered)
	return result, nil
}

func (s *Service) GetTicketDetail(ctx context.Context, id string) (shared.TicketDetail, bool, error) {
	ticket, ok, err := s.store.GetTicket(ctx, id)
	if err != nil || !ok {
		return shared.TicketDetail{}, ok, err
	}
	var alert *shared.Alert
	if ticket.AlertID != "" {
		value, ok, err := s.store.GetAlert(ctx, ticket.AlertID)
		if err != nil {
			return shared.TicketDetail{}, false, err
		}
		if ok {
			alert = &value
		}
	}
	activities, err := s.store.ListActivities(ctx, ticket.TenantID, "ticket", ticket.ID)
	if err != nil {
		return shared.TicketDetail{}, false, err
	}
	return shared.TicketDetail{Ticket: ticket, Alert: alert, Activities: activities}, true, nil
}

func (s *Service) CanAccessTicket(ctx context.Context, user shared.User, ticket shared.Ticket) bool {
	if contains(user.Permissions, "*") {
		return true
	}
	if ticket.AlertID == "" {
		return true
	}
	alert, ok, err := s.store.GetAlert(ctx, ticket.AlertID)
	if err != nil || !ok {
		return false
	}
	return s.CanAccessAlert(ctx, user, alert)
}

func (s *Service) UpdateTicketStatus(ctx context.Context, id string, req shared.UpdateTicketStatusRequest) (shared.Ticket, bool, error) {
	ticket, ok, err := s.store.UpdateTicketStatus(ctx, id, func(ticket shared.Ticket) shared.Ticket {
		if req.Status != "" {
			ticket.Status = req.Status
			if req.Status == "closed" {
				ticket.SLAStatus = "closed"
			}
		}
		if req.Assignee != "" {
			ticket.Assignee = req.Assignee
		}
		return ticket
	})
	if err != nil || !ok {
		return ticket, ok, err
	}
	if err := s.addAuditLog(ctx, ticket.TenantID, req.Assignee, "update_ticket_status", "ticket", ticket.ID, "success"); err != nil {
		return shared.Ticket{}, false, err
	}
	_ = s.addActivity(ctx, ticket.TenantID, "ticket", ticket.ID, "update_ticket_status", req.Assignee, ticket.Status)
	s.dispatchNotification(ctx, ticket.TenantID, "ticket.updated", "ticket", ticket.ID, ticket)
	return ticket, true, nil
}

func (s *Service) BatchUpdateTicketStatus(ctx context.Context, req shared.BatchUpdateTicketStatusRequest) (shared.BatchUpdateTicketStatusResponse, error) {
	items := make([]shared.Ticket, 0, len(req.TicketIDs))
	for _, ticketID := range req.TicketIDs {
		ticket, ok, err := s.UpdateTicketStatus(ctx, ticketID, shared.UpdateTicketStatusRequest{
			Status:   req.Status,
			Assignee: req.Assignee,
		})
		if err != nil {
			return shared.BatchUpdateTicketStatusResponse{}, err
		}
		if ok {
			items = append(items, ticket)
		}
	}
	return shared.BatchUpdateTicketStatusResponse{
		Requested: len(req.TicketIDs),
		Updated:   len(items),
		Items:     items,
	}, nil
}

func (s *Service) CreateUser(ctx context.Context, req shared.CreateUserRequest, operatorID string) (shared.User, error) {
	if len(req.Roles) == 0 {
		return shared.User{}, fmt.Errorf("at least one role is required")
	}
	roles, err := s.store.ListRoles(ctx, req.TenantID)
	if err != nil {
		return shared.User{}, err
	}
	roleSet := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		roleSet[role.Name] = struct{}{}
	}
	for _, role := range req.Roles {
		if _, ok := roleSet[role]; !ok {
			return shared.User{}, fmt.Errorf("role %s not found", role)
		}
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return shared.User{}, err
	}
	user := shared.User{
		ID:              s.nextID("user"),
		TenantID:        req.TenantID,
		Username:        req.Username,
		DisplayName:     req.DisplayName,
		Password:        string(passwordHash),
		Status:          "active",
		Roles:           req.Roles,
		AllowedTenants:  normalizeScopeTenants(req.TenantID, req.AllowedTenants),
		AllowedProbeIDs: uniqueStrings(req.AllowedProbeIDs),
		AllowedAssetIDs: uniqueStrings(req.AllowedAssetIDs),
		AllowedOrgIDs:   uniqueStrings(req.AllowedOrgIDs),
		CreatedAt:       time.Now().UTC(),
	}
	created, err := s.store.CreateUser(ctx, user)
	if err != nil {
		return shared.User{}, err
	}
	if err := s.addAuditLog(ctx, req.TenantID, operatorID, "create_user", "user", created.ID, "success"); err != nil {
		return shared.User{}, err
	}
	_ = s.addActivity(ctx, req.TenantID, "user", created.ID, "create_user", operatorID, created.Username)
	return created, nil
}

func (s *Service) ListUsers(ctx context.Context, tenantID string) ([]shared.User, error) {
	return s.store.ListUsers(ctx, tenantID)
}

func (s *Service) CreateRole(ctx context.Context, req shared.CreateRoleRequest, operatorID string) (shared.Role, error) {
	role := shared.Role{
		ID:          s.nextID("role"),
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		CreatedAt:   time.Now().UTC(),
	}
	created, err := s.store.CreateRole(ctx, role)
	if err != nil {
		return shared.Role{}, err
	}
	if err := s.addAuditLog(ctx, req.TenantID, operatorID, "create_role", "role", created.ID, "success"); err != nil {
		return shared.Role{}, err
	}
	_ = s.addActivity(ctx, req.TenantID, "role", created.ID, "create_role", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListRoles(ctx context.Context, tenantID string) ([]shared.Role, error) {
	return s.store.ListRoles(ctx, tenantID)
}

func (s *Service) ListRoleTemplates(_ context.Context) []shared.RoleTemplate {
	return roleTemplates()
}

func (s *Service) DashboardWorkbench(ctx context.Context, user shared.User) (shared.DashboardWorkbench, error) {
	stats, err := s.DashboardStatsForUser(ctx, user, user.TenantID)
	if err != nil {
		return shared.DashboardWorkbench{}, err
	}
	template := shared.RoleTemplate{
		Name:        "custom",
		Label:       "未分类角色",
		Description: "未命中预置角色模板，默认展示全部模块。",
	}
	for _, role := range user.Roles {
		for _, item := range roleTemplates() {
			if item.Name == role {
				template = item
				break
			}
		}
		if template.Name != "custom" {
			break
		}
	}
	return shared.DashboardWorkbench{
		RoleTemplate: template,
		Stats:        stats,
		Recommended:  recommendedWorkbenchItems(template.Name),
	}, nil
}

func (s *Service) Login(ctx context.Context, req shared.LoginRequest) (shared.LoginResponse, bool, error) {
	user, ok, err := s.store.FindUser(ctx, req.TenantID, req.Username)
	if err != nil {
		return shared.LoginResponse{}, false, err
	}
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)) != nil || user.Status != "active" {
		_ = s.addAuditLog(ctx, req.TenantID, "", "login", "user", req.Username, "failed")
		return shared.LoginResponse{}, false, nil
	}
	token, err := s.issueToken(ctx, user)
	if err != nil {
		return shared.LoginResponse{}, false, err
	}
	permissions, err := s.permissionsForUser(ctx, user)
	if err != nil {
		return shared.LoginResponse{}, false, err
	}
	user.Permissions = permissions
	if err := s.addAuditLog(ctx, req.TenantID, user.ID, "login", "user", user.ID, "success"); err != nil {
		return shared.LoginResponse{}, false, err
	}
	return shared.LoginResponse{Token: token, User: user}, true, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (shared.User, bool, error) {
	var (
		user shared.User
		ok   bool
		err  error
	)
	if s.authMode == "jwt" {
		user, ok, err = s.authenticateJWT(ctx, token)
	} else {
		user, ok, err = s.store.LookupToken(ctx, token)
	}
	if err != nil || !ok {
		return user, ok, err
	}
	permissions, err := s.permissionsForUser(ctx, user)
	if err != nil {
		return shared.User{}, false, err
	}
	user.Permissions = permissions
	return user, true, nil
}

func (s *Service) issueToken(ctx context.Context, user shared.User) (string, error) {
	if s.authMode == "jwt" {
		return s.issueJWT(user)
	}
	token := s.nextID("token")
	if err := s.store.SaveToken(ctx, token, user.ID); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) issueJWT(user shared.User) (string, error) {
	if len(s.jwtSecret) == 0 {
		return "", fmt.Errorf("jwt secret is empty")
	}
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"sub":       user.ID,
		"tenant_id": user.TenantID,
		"username":  user.Username,
		"exp":       time.Now().UTC().Add(s.jwtTTL).Unix(),
	})
	if err != nil {
		return "", err
	}
	encodedHeader := jwtBase64(header)
	encodedClaims := jwtBase64(claims)
	signingInput := encodedHeader + "." + encodedClaims
	signature := signJWT(signingInput, s.jwtSecret)
	return signingInput + "." + signature, nil
}

func (s *Service) authenticateJWT(ctx context.Context, token string) (shared.User, bool, error) {
	if len(s.jwtSecret) == 0 {
		return shared.User{}, false, fmt.Errorf("jwt secret is empty")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return shared.User{}, false, nil
	}
	signingInput := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(signJWT(signingInput, s.jwtSecret))) {
		return shared.User{}, false, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return shared.User{}, false, nil
	}
	var claims struct {
		Subject  string `json:"sub"`
		TenantID string `json:"tenant_id"`
		Username string `json:"username"`
		Exp      int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return shared.User{}, false, nil
	}
	if claims.Subject == "" || time.Now().UTC().Unix() > claims.Exp {
		return shared.User{}, false, nil
	}
	user, ok, err := s.store.GetUser(ctx, claims.Subject)
	if err != nil || !ok {
		return user, ok, err
	}
	if claims.TenantID != "" && user.TenantID != claims.TenantID {
		return shared.User{}, false, nil
	}
	return user, true, nil
}

func jwtBase64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func signJWT(input string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(input))
	return jwtBase64(mac.Sum(nil))
}

func normalizeAuthMode(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "jwt") {
		return "jwt"
	}
	return "simple"
}

func (s *Service) CurrentUser(ctx context.Context, token string) (shared.User, bool, error) {
	return s.Authenticate(ctx, token)
}

func (s *Service) ListAuditLogs(ctx context.Context, tenantID string) ([]shared.AuditLog, error) {
	return s.store.ListAuditLogs(ctx, tenantID)
}

func (s *Service) ListProbes(ctx context.Context, tenantID string) ([]shared.Probe, error) {
	probes, err := s.store.ListProbes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for idx := range probes {
		probes[idx] = s.runtimeProbeStatus(probes[idx], now)
	}
	return probes, nil
}

func (s *Service) GetProbeDetail(ctx context.Context, probeID string) (shared.ProbeDetail, bool, error) {
	probe, ok, err := s.store.GetProbe(ctx, probeID)
	if err != nil || !ok {
		return shared.ProbeDetail{}, ok, err
	}
	probe = s.runtimeProbeStatus(probe, time.Now().UTC())
	var binding *shared.ProbeBinding
	value, ok, err := s.store.GetProbeBindingByProbeID(ctx, probeID)
	if err != nil {
		return shared.ProbeDetail{}, false, err
	}
	if ok {
		binding = &value
	}
	var upgradeTask *shared.ProbeUpgradeTask
	if value, ok, err := s.store.GetPendingProbeUpgradeTask(ctx, probeID); err != nil {
		return shared.ProbeDetail{}, false, err
	} else if ok {
		upgradeTask = &value
	}
	items, err := s.store.ListDeploymentRecords(ctx, probe.TenantID)
	if err != nil {
		return shared.ProbeDetail{}, false, err
	}
	metrics, err := s.store.ListProbeMetrics(ctx, shared.ProbeMetricQuery{
		TenantID: probe.TenantID,
		ProbeID:  probeID,
		Limit:    20,
	})
	if err != nil {
		return shared.ProbeDetail{}, false, err
	}
	versionHistory, err := s.store.ListProbeVersionHistory(ctx, probe.TenantID, probeID)
	if err != nil {
		return shared.ProbeDetail{}, false, err
	}
	deployments := make([]shared.DeploymentRecord, 0)
	for _, item := range items {
		if item.ProbeID == probeID {
			deployments = append(deployments, item)
		}
	}
	return shared.ProbeDetail{
		Probe:          probe,
		Binding:        binding,
		UpgradeTask:    upgradeTask,
		VersionHistory: versionHistory,
		Deployments:    deployments,
		Metrics:        metrics,
	}, true, nil
}

func (s *Service) CreateUpgradePackage(ctx context.Context, req shared.CreateUpgradePackageRequest, operatorID string) (shared.UpgradePackage, error) {
	pkg := shared.UpgradePackage{
		ID:         s.nextID("upgrade-pkg"),
		TenantID:   req.TenantID,
		Version:    strings.TrimSpace(req.Version),
		PackageURL: strings.TrimSpace(req.PackageURL),
		Checksum:   strings.TrimSpace(req.Checksum),
		Notes:      strings.TrimSpace(req.Notes),
		Enabled:    req.Enabled,
		CreatedAt:  time.Now().UTC(),
	}
	created, err := s.store.CreateUpgradePackage(ctx, pkg)
	if err != nil {
		return shared.UpgradePackage{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_upgrade_package", "upgrade_package", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "upgrade_package", created.ID, "create_upgrade_package", operatorID, created.Version)
	return created, nil
}

func (s *Service) UploadUpgradePackage(ctx context.Context, tenantID, version, notes, fileName string, enabled bool, content []byte, operatorID string) (shared.UpgradePackage, error) {
	if strings.TrimSpace(version) == "" {
		return shared.UpgradePackage{}, fmt.Errorf("version is required")
	}
	if len(content) == 0 {
		return shared.UpgradePackage{}, fmt.Errorf("package content is empty")
	}
	cleanName := filepath.Base(strings.TrimSpace(fileName))
	if cleanName == "." || cleanName == "" {
		cleanName = fmt.Sprintf("%s.bin", version)
	}
	sum := sha256.Sum256(content)
	pkgID := s.nextID("pkg")
	storageName := fmt.Sprintf("%s-%s", pkgID, cleanName)
	storagePath := filepath.Join(s.packageDir, storageName)
	if err := os.WriteFile(storagePath, content, 0o644); err != nil {
		return shared.UpgradePackage{}, err
	}
	pkg := shared.UpgradePackage{
		ID:         pkgID,
		TenantID:   tenantID,
		Version:    version,
		PackageURL: fmt.Sprintf("/api/v1/upgrade-packages/%s/download", pkgID),
		FileName:   cleanName,
		FileSize:   int64(len(content)),
		Checksum:   fmt.Sprintf("sha256:%x", sum),
		Notes:      notes,
		Enabled:    enabled,
		CreatedAt:  time.Now().UTC(),
	}
	created, err := s.store.CreateUpgradePackage(ctx, pkg)
	if err != nil {
		_ = os.Remove(storagePath)
		return shared.UpgradePackage{}, err
	}
	if err := s.addAuditLog(ctx, tenantID, operatorID, "upload_upgrade_package", "upgrade_package", created.ID, "success"); err != nil {
		return shared.UpgradePackage{}, err
	}
	_ = s.addActivity(ctx, tenantID, "upgrade_package", created.ID, "upload_upgrade_package", operatorID, created.Version)
	return created, nil
}

func (s *Service) ListUpgradePackages(ctx context.Context, tenantID string) ([]shared.UpgradePackage, error) {
	return s.store.ListUpgradePackages(ctx, tenantID)
}

func (s *Service) GetUpgradePackage(ctx context.Context, tenantID, id string) (shared.UpgradePackage, bool, error) {
	return s.store.FindUpgradePackageByID(ctx, tenantID, id)
}

func (s *Service) UpgradePackagePath(pkg shared.UpgradePackage) string {
	return filepath.Join(s.packageDir, fmt.Sprintf("%s-%s", pkg.ID, filepath.Base(pkg.FileName)))
}

func (s *Service) ListProbeMetrics(ctx context.Context, query shared.ProbeMetricQuery) ([]shared.ProbeMetric, error) {
	return s.store.ListProbeMetrics(ctx, query)
}

func (s *Service) CreateAsset(ctx context.Context, req shared.CreateAssetRequest, operatorID string) (shared.Asset, error) {
	var orgName string
	if req.OrgID != "" {
		org, ok, err := s.store.GetOrganization(ctx, req.OrgID)
		if err != nil {
			return shared.Asset{}, err
		}
		if !ok || org.TenantID != req.TenantID {
			return shared.Asset{}, fmt.Errorf("organization not found")
		}
		orgName = org.Name
	}
	asset := shared.Asset{
		ID:              s.nextID("asset"),
		TenantID:        req.TenantID,
		Name:            req.Name,
		IP:              req.IP,
		OrgID:           strings.TrimSpace(req.OrgID),
		OrgName:         orgName,
		AssetType:       req.AssetType,
		ImportanceLevel: req.ImportanceLevel,
		Owner:           req.Owner,
		Tags:            uniqueStrings(req.Tags),
		CreatedAt:       time.Now().UTC(),
	}
	created, err := s.store.CreateAsset(ctx, asset)
	if err != nil {
		return shared.Asset{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_asset", "asset", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "asset", created.ID, "create_asset", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListAssets(ctx context.Context, tenantID string) ([]shared.Asset, error) {
	return s.store.ListAssets(ctx, tenantID)
}

func (s *Service) ListAssetsForUser(ctx context.Context, user shared.User, tenantID string) ([]shared.Asset, error) {
	items, err := s.store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]shared.Asset, 0, len(items))
	for _, item := range items {
		if s.CanAccessAsset(user, item) {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *Service) CreateOrganization(ctx context.Context, req shared.CreateOrganizationRequest, operatorID string) (shared.Organization, error) {
	level := 1
	path := []string{}
	if req.ParentID != "" {
		parent, ok, err := s.store.GetOrganization(ctx, req.ParentID)
		if err != nil {
			return shared.Organization{}, err
		}
		if !ok || parent.TenantID != req.TenantID {
			return shared.Organization{}, fmt.Errorf("parent organization not found")
		}
		level = parent.Level + 1
		path = append(path, parent.Path...)
		path = append(path, parent.ID)
	}
	item := shared.Organization{
		ID:        s.nextID("org"),
		TenantID:  req.TenantID,
		Name:      strings.TrimSpace(req.Name),
		Code:      strings.TrimSpace(req.Code),
		ParentID:  strings.TrimSpace(req.ParentID),
		Level:     level,
		Path:      path,
		CreatedAt: time.Now().UTC(),
	}
	created, err := s.store.CreateOrganization(ctx, item)
	if err != nil {
		return shared.Organization{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_organization", "organization", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "organization", created.ID, "create_organization", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListOrganizations(ctx context.Context, tenantID string) ([]shared.Organization, error) {
	return s.store.ListOrganizations(ctx, tenantID)
}

func (s *Service) ListOrganizationsForUser(ctx context.Context, user shared.User, tenantID string) ([]shared.Organization, error) {
	items, err := s.store.ListOrganizations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]shared.Organization, 0, len(items))
	for _, item := range items {
		if s.CanAccessOrganization(user, item) {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *Service) resolveScopeAssets(ctx context.Context, user shared.User, tenantID string) ([]string, []string, error) {
	items, err := s.store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	assetIDs := make([]string, 0)
	ips := make([]string, 0)
	for _, item := range items {
		if !s.CanAccessAsset(user, item) {
			continue
		}
		assetIDs = append(assetIDs, item.ID)
		if item.IP != "" {
			ips = append(ips, item.IP)
		}
	}
	return uniqueStrings(assetIDs), uniqueStrings(ips), nil
}

func (s *Service) CreateThreatIntel(ctx context.Context, req shared.CreateThreatIntelRequest, operatorID string) (shared.ThreatIntel, error) {
	intel := shared.ThreatIntel{
		ID:        s.nextID("intel"),
		TenantID:  req.TenantID,
		Type:      strings.ToLower(strings.TrimSpace(req.Type)),
		Value:     strings.TrimSpace(req.Value),
		Severity:  strings.TrimSpace(req.Severity),
		Source:    strings.TrimSpace(req.Source),
		Tags:      uniqueStrings(req.Tags),
		CreatedAt: time.Now().UTC(),
	}
	created, err := s.store.CreateThreatIntel(ctx, intel)
	if err != nil {
		return shared.ThreatIntel{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_threat_intel", "threat_intel", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "threat_intel", created.ID, "create_threat_intel", operatorID, created.Value)
	return created, nil
}

func (s *Service) ListThreatIntel(ctx context.Context, tenantID string) ([]shared.ThreatIntel, error) {
	return s.store.ListThreatIntel(ctx, tenantID)
}

func (s *Service) CreateSuppressionRule(ctx context.Context, req shared.CreateSuppressionRuleRequest, operatorID string) (shared.SuppressionRule, error) {
	rule := shared.SuppressionRule{
		ID:          s.nextID("suppress"),
		TenantID:    req.TenantID,
		Name:        req.Name,
		SrcIP:       strings.TrimSpace(req.SrcIP),
		DstIP:       strings.TrimSpace(req.DstIP),
		SignatureID: req.SignatureID,
		Signature:   strings.TrimSpace(req.Signature),
		Enabled:     req.Enabled,
		CreatedAt:   time.Now().UTC(),
	}
	created, err := s.store.CreateSuppressionRule(ctx, rule)
	if err != nil {
		return shared.SuppressionRule{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_suppression_rule", "suppression_rule", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "suppression_rule", created.ID, "create_suppression_rule", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListSuppressionRules(ctx context.Context, tenantID string) ([]shared.SuppressionRule, error) {
	return s.store.ListSuppressionRules(ctx, tenantID)
}

func (s *Service) CreateRiskPolicy(ctx context.Context, req shared.CreateRiskPolicyRequest, operatorID string) (shared.RiskPolicy, error) {
	policy := shared.RiskPolicy{
		ID:                 s.nextID("risk-policy"),
		TenantID:           req.TenantID,
		Name:               req.Name,
		Severity1Score:     req.Severity1Score,
		Severity2Score:     req.Severity2Score,
		Severity3Score:     req.Severity3Score,
		DefaultScore:       req.DefaultScore,
		IntelHitBonus:      req.IntelHitBonus,
		CriticalAssetBonus: req.CriticalAssetBonus,
		Enabled:            req.Enabled,
		CreatedAt:          time.Now().UTC(),
	}
	created, err := s.store.CreateRiskPolicy(ctx, policy)
	if err != nil {
		return shared.RiskPolicy{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_risk_policy", "risk_policy", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "risk_policy", created.ID, "create_risk_policy", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListRiskPolicies(ctx context.Context, tenantID string) ([]shared.RiskPolicy, error) {
	return s.store.ListRiskPolicies(ctx, tenantID)
}

func (s *Service) CreateTicketAutomationPolicy(ctx context.Context, req shared.CreateTicketAutomationPolicyRequest, operatorID string) (shared.TicketAutomationPolicy, error) {
	policy := shared.TicketAutomationPolicy{
		ID:                  s.nextID("ticket-policy"),
		TenantID:            req.TenantID,
		Name:                strings.TrimSpace(req.Name),
		ReminderBeforeMins:  req.ReminderBeforeMins,
		EscalationAfterMins: req.EscalationAfterMins,
		EscalationAssignee:  strings.TrimSpace(req.EscalationAssignee),
		EscalationStatus:    normalizeEscalationStatus(req.EscalationStatus),
		Enabled:             req.Enabled,
		CreatedAt:           time.Now().UTC(),
	}
	created, err := s.store.CreateTicketAutomationPolicy(ctx, policy)
	if err != nil {
		return shared.TicketAutomationPolicy{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_ticket_automation_policy", "ticket_automation_policy", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "ticket_automation_policy", created.ID, "create_ticket_automation_policy", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListTicketAutomationPolicies(ctx context.Context, tenantID string) ([]shared.TicketAutomationPolicy, error) {
	return s.store.ListTicketAutomationPolicies(ctx, tenantID)
}

func (s *Service) ListFlows(ctx context.Context, query shared.FlowQuery) ([]shared.Flow, error) {
	return s.search.SearchFlows(ctx, query)
}

func (s *Service) CreateProbeConfig(ctx context.Context, req shared.CreateProbeConfigRequest, operatorID string) (shared.ProbeConfig, error) {
	config := shared.ProbeConfig{
		ID:          s.nextID("probe-config"),
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Filters:     req.Filters,
		OutputTypes: req.OutputTypes,
		CreatedAt:   time.Now().UTC(),
	}
	created, err := s.store.CreateProbeConfig(ctx, config)
	if err != nil {
		return shared.ProbeConfig{}, err
	}
	_ = s.addActivity(ctx, req.TenantID, "probe_config", created.ID, "create_probe_config", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListProbeConfigs(ctx context.Context, tenantID string) ([]shared.ProbeConfig, error) {
	return s.store.ListProbeConfigs(ctx, tenantID)
}

func (s *Service) CreateRuleBundle(ctx context.Context, req shared.CreateRuleBundleRequest, operatorID string) (shared.RuleBundle, error) {
	bundle := shared.RuleBundle{
		ID:          s.nextID("rule-bundle"),
		TenantID:    req.TenantID,
		Version:     req.Version,
		Description: req.Description,
		Enabled:     req.Enabled,
		CreatedAt:   time.Now().UTC(),
	}
	created, err := s.store.CreateRuleBundle(ctx, bundle)
	if err != nil {
		return shared.RuleBundle{}, err
	}
	_ = s.addActivity(ctx, req.TenantID, "rule_bundle", created.ID, "create_rule_bundle", operatorID, created.Version)
	return created, nil
}

func (s *Service) ListRuleBundles(ctx context.Context, tenantID string) ([]shared.RuleBundle, error) {
	return s.store.ListRuleBundles(ctx, tenantID)
}

func (s *Service) ApplyProbeBinding(ctx context.Context, req shared.ApplyProbeBindingRequest, operatorID string) (shared.ProbeBinding, error) {
	probe, ok, err := s.store.GetProbe(ctx, req.ProbeID)
	if err != nil {
		return shared.ProbeBinding{}, err
	}
	if !ok {
		return shared.ProbeBinding{}, fmt.Errorf("probe not found")
	}
	binding := shared.ProbeBinding{
		ID:            s.nextID("probe-binding"),
		TenantID:      req.TenantID,
		ProbeID:       req.ProbeID,
		ProbeName:     probe.Name,
		ProbeConfigID: req.ProbeConfigID,
		RuleBundleID:  req.RuleBundleID,
		UpdatedAt:     time.Now().UTC(),
	}
	created, err := s.store.UpsertProbeBinding(ctx, binding)
	if err != nil {
		return shared.ProbeBinding{}, err
	}
	record := shared.DeploymentRecord{
		ID:            s.nextID("deployment"),
		TenantID:      req.TenantID,
		ProbeID:       req.ProbeID,
		ProbeName:     probe.Name,
		ProbeConfigID: req.ProbeConfigID,
		RuleBundleID:  req.RuleBundleID,
		Status:        "pending",
		Message:       "binding queued for probe pull",
		CreatedAt:     time.Now().UTC(),
	}
	if _, err := s.store.CreateDeploymentRecord(ctx, record); err != nil {
		return shared.ProbeBinding{}, err
	}
	_ = s.addActivity(ctx, req.TenantID, "probe_binding", created.ID, "apply_probe_binding", operatorID, probe.Name)
	_ = s.addActivity(ctx, req.TenantID, "deployment", record.ID, "create_deployment_record", operatorID, record.Status)
	return created, nil
}

func (s *Service) ListProbeBindings(ctx context.Context, tenantID string) ([]shared.ProbeBinding, error) {
	return s.store.ListProbeBindings(ctx, tenantID)
}

func (s *Service) ListDeploymentRecords(ctx context.Context, query shared.DeploymentQuery) ([]shared.DeploymentRecord, error) {
	items, err := s.store.ListDeploymentRecords(ctx, query.TenantID)
	if err != nil {
		return nil, err
	}
	filtered := make([]shared.DeploymentRecord, 0, len(items))
	for _, item := range items {
		if query.ProbeID != "" && item.ProbeID != query.ProbeID {
			continue
		}
		if query.Status != "" && item.Status != query.Status {
			continue
		}
		if !query.Since.IsZero() && item.CreatedAt.Before(query.Since) {
			continue
		}
		filtered = append(filtered, item)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
	})
	if query.Limit > 0 && len(filtered) > query.Limit {
		filtered = filtered[:query.Limit]
	}
	return filtered, nil
}

func (s *Service) GetProbeBindingDetail(ctx context.Context, probeID string) (shared.ProbeBindingDetail, bool, error) {
	binding, ok, err := s.store.GetProbeBindingByProbeID(ctx, probeID)
	if err != nil || !ok {
		return shared.ProbeBindingDetail{}, ok, err
	}
	config, ok, err := s.store.GetProbeConfig(ctx, binding.ProbeConfigID)
	if err != nil || !ok {
		return shared.ProbeBindingDetail{}, ok, err
	}
	bundle, ok, err := s.store.GetRuleBundle(ctx, binding.RuleBundleID)
	if err != nil || !ok {
		return shared.ProbeBindingDetail{}, ok, err
	}
	return shared.ProbeBindingDetail{
		Binding:     binding,
		ProbeConfig: config,
		RuleBundle:  bundle,
	}, true, nil
}

func (s *Service) CreateProbeUpgradeTask(ctx context.Context, req shared.CreateProbeUpgradeTaskRequest, operatorID string) (shared.ProbeUpgradeTask, error) {
	probe, ok, err := s.store.GetProbe(ctx, req.ProbeID)
	if err != nil {
		return shared.ProbeUpgradeTask{}, err
	}
	if !ok {
		return shared.ProbeUpgradeTask{}, fmt.Errorf("probe not found")
	}
	action := normalizeProbeUpgradeAction(req.Action)
	var pkgID string
	targetVersion := strings.TrimSpace(req.TargetVersion)
	if action == "upgrade" {
		if targetVersion == "" {
			return shared.ProbeUpgradeTask{}, fmt.Errorf("target version is required")
		}
		pkg, ok, err := s.store.FindUpgradePackageByVersion(ctx, req.TenantID, targetVersion)
		if err != nil {
			return shared.ProbeUpgradeTask{}, err
		}
		if !ok || !pkg.Enabled {
			return shared.ProbeUpgradeTask{}, fmt.Errorf("upgrade package not found")
		}
		pkgID = pkg.ID
	}
	task := shared.ProbeUpgradeTask{
		ID:              s.nextID("probe-upgrade"),
		TenantID:        req.TenantID,
		ProbeID:         req.ProbeID,
		ProbeName:       probe.Name,
		PackageID:       pkgID,
		Action:          action,
		PreviousVersion: probe.Version,
		TargetVersion:   targetVersion,
		Status:          "pending",
		RetryCount:      0,
		MaxRetries:      positiveInt(req.MaxRetries, 1),
		Message:         "upgrade task queued for probe pull",
		CreatedAt:       time.Now().UTC(),
	}
	created, err := s.store.CreateProbeUpgradeTask(ctx, task)
	if err != nil {
		return shared.ProbeUpgradeTask{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_probe_upgrade_task", "probe_upgrade_task", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "probe_upgrade_task", created.ID, "create_probe_upgrade_task", operatorID, created.Action+" "+created.TargetVersion)
	return created, nil
}

func (s *Service) BatchCreateProbeUpgradeTasks(ctx context.Context, req shared.BatchCreateProbeUpgradeTaskRequest, operatorID string) (shared.BatchCreateProbeUpgradeTaskResponse, error) {
	items := make([]shared.ProbeUpgradeTask, 0, len(req.ProbeIDs))
	for _, probeID := range uniqueStrings(req.ProbeIDs) {
		task, err := s.CreateProbeUpgradeTask(ctx, shared.CreateProbeUpgradeTaskRequest{
			TenantID:      req.TenantID,
			ProbeID:       probeID,
			Action:        req.Action,
			TargetVersion: req.TargetVersion,
			MaxRetries:    req.MaxRetries,
		}, operatorID)
		if err != nil {
			return shared.BatchCreateProbeUpgradeTaskResponse{}, err
		}
		items = append(items, task)
	}
	return shared.BatchCreateProbeUpgradeTaskResponse{
		Requested: len(uniqueStrings(req.ProbeIDs)),
		Applied:   len(items),
		Items:     items,
	}, nil
}

func (s *Service) ListProbeUpgradeTasks(ctx context.Context, tenantID string) ([]shared.ProbeUpgradeTask, error) {
	return s.store.ListProbeUpgradeTasks(ctx, tenantID)
}

func (s *Service) GetPendingProbeUpgradeTask(ctx context.Context, probeID string) (shared.ProbeUpgradeTask, bool, error) {
	return s.store.GetPendingProbeUpgradeTask(ctx, probeID)
}

func (s *Service) AcknowledgeProbeUpgradeTask(ctx context.Context, req shared.ProbeUpgradeAckRequest) (shared.ProbeUpgradeTask, error) {
	task, ok, err := s.store.GetPendingProbeUpgradeTask(ctx, req.ProbeID)
	if err != nil {
		return shared.ProbeUpgradeTask{}, err
	}
	if !ok {
		return shared.ProbeUpgradeTask{}, fmt.Errorf("pending upgrade task not found")
	}
	resultStatus := normalizeProbeUpgradeStatus(req.Status)
	task.Message = strings.TrimSpace(req.Message)
	if task.Message == "" {
		task.Message = "probe upgrade acknowledged"
	}
	now := time.Now().UTC()
	if resultStatus == "failed" {
		task.RetryCount++
		if task.RetryCount <= task.MaxRetries {
			task.Status = "pending"
			task.CompletedAt = time.Time{}
			task.Message = fmt.Sprintf("retry scheduled after failure: %s", task.Message)
		} else {
			task.Status = "failed"
			task.CompletedAt = now
		}
	} else {
		task.Status = "applied"
		task.CompletedAt = now
	}
	updated, err := s.store.UpdateProbeUpgradeTask(ctx, task)
	if err != nil {
		return shared.ProbeUpgradeTask{}, err
	}
	probe, ok, err := s.store.GetProbe(ctx, req.ProbeID)
	if err == nil && ok && updated.Status == "applied" {
		probe.Version = req.TargetVersion
		probe.LastDeployStatus = updated.Status
		probe.LastDeployMessage = updated.Message
		probe.LastDeployAt = updated.CompletedAt
		_, _ = s.store.UpsertProbe(ctx, probe)
	}
	if err == nil && ok && (updated.Status == "applied" || updated.Status == "failed") {
		_ = s.store.AddProbeVersionHistory(ctx, shared.ProbeVersionHistory{
			ID:          s.nextID("probe-version"),
			TenantID:    updated.TenantID,
			ProbeID:     updated.ProbeID,
			ProbeName:   updated.ProbeName,
			Action:      updated.Action,
			FromVersion: updated.PreviousVersion,
			ToVersion:   updated.TargetVersion,
			Result:      updated.Status,
			Message:     updated.Message,
			CreatedAt:   now,
		})
	}
	_ = s.addActivity(ctx, updated.TenantID, "probe_upgrade_task", updated.ID, "ack_probe_upgrade_task", req.ProbeID, updated.Status)
	return updated, nil
}

func (s *Service) AcknowledgeDeployment(ctx context.Context, req shared.DeploymentAckRequest) (shared.DeploymentRecord, error) {
	probe, ok, err := s.store.GetProbe(ctx, req.ProbeID)
	if err != nil {
		return shared.DeploymentRecord{}, err
	}
	if !ok {
		return shared.DeploymentRecord{}, fmt.Errorf("probe not found")
	}
	status := req.Status
	if status == "" {
		status = "applied"
	}
	message := req.Message
	if message == "" {
		message = "probe acknowledged deployment"
	}
	record := shared.DeploymentRecord{
		ID:            s.nextID("deployment"),
		TenantID:      req.TenantID,
		ProbeID:       req.ProbeID,
		ProbeName:     probe.Name,
		ProbeConfigID: req.ProbeConfigID,
		RuleBundleID:  req.RuleBundleID,
		Status:        status,
		Message:       message,
		CreatedAt:     time.Now().UTC(),
	}
	created, err := s.store.CreateDeploymentRecord(ctx, record)
	if err != nil {
		return shared.DeploymentRecord{}, err
	}
	probe.LastDeployStatus = created.Status
	probe.LastDeployMessage = created.Message
	probe.LastDeployAt = created.CreatedAt
	if created.Status == "applied" {
		probe.AppliedConfigID = req.ProbeConfigID
		probe.AppliedRuleID = req.RuleBundleID
	}
	if _, err := s.store.UpsertProbe(ctx, probe); err != nil {
		return shared.DeploymentRecord{}, err
	}
	_ = s.addActivity(ctx, req.TenantID, "deployment", created.ID, "ack_deployment", req.ProbeID, created.Status)
	return created, nil
}

func (s *Service) DashboardStats(ctx context.Context, tenantID string) (shared.DashboardStats, error) {
	alerts, err := s.store.ListAlerts(ctx, shared.AlertQuery{TenantID: tenantID})
	if err != nil {
		return shared.DashboardStats{}, err
	}
	probes, err := s.store.ListProbes(ctx, tenantID)
	if err != nil {
		return shared.DashboardStats{}, err
	}
	tickets, err := s.store.ListTickets(ctx, tenantID)
	if err != nil {
		return shared.DashboardStats{}, err
	}
	flows, err := s.store.ListFlows(ctx, shared.FlowQuery{TenantID: tenantID})
	if err != nil {
		return shared.DashboardStats{}, err
	}
	stats := shared.DashboardStats{FlowsObserved: len(flows)}
	now := time.Now().UTC()
	for _, alert := range alerts {
		if alert.Status == "closed" {
			stats.AlertsClosed++
		} else {
			stats.AlertsOpen++
		}
	}
	for _, probe := range probes {
		probe = s.runtimeProbeStatus(probe, now)
		if probe.Status == "online" {
			stats.ProbesOnline++
		}
	}
	for _, ticket := range tickets {
		if ticket.Status != "closed" {
			stats.TicketsOpen++
		}
	}
	return stats, nil
}

func (s *Service) DashboardStatsForUser(ctx context.Context, user shared.User, tenantID string) (shared.DashboardStats, error) {
	stats, err := s.DashboardStats(ctx, tenantID)
	if err != nil {
		return shared.DashboardStats{}, err
	}
	if contains(user.Permissions, "*") && len(user.AllowedAssetIDs) == 0 && len(user.AllowedOrgIDs) == 0 {
		return stats, nil
	}
	alerts, err := s.store.ListAlerts(ctx, shared.AlertQuery{TenantID: tenantID})
	if err != nil {
		return shared.DashboardStats{}, err
	}
	tickets, err := s.store.ListTickets(ctx, tenantID)
	if err != nil {
		return shared.DashboardStats{}, err
	}
	flows, err := s.store.ListFlows(ctx, shared.FlowQuery{TenantID: tenantID})
	if err != nil {
		return shared.DashboardStats{}, err
	}
	stats.AlertsOpen = 0
	stats.AlertsClosed = 0
	stats.TicketsOpen = 0
	stats.FlowsObserved = 0
	for _, alert := range alerts {
		if !s.CanAccessAlert(ctx, user, alert) {
			continue
		}
		if alert.Status == "closed" {
			stats.AlertsClosed++
		} else {
			stats.AlertsOpen++
		}
	}
	for _, ticket := range tickets {
		if s.CanAccessTicket(ctx, user, ticket) && ticket.Status != "closed" {
			stats.TicketsOpen++
		}
	}
	for _, flow := range flows {
		if s.CanAccessFlow(ctx, user, flow) {
			stats.FlowsObserved++
		}
	}
	return stats, nil
}

func (s *Service) runtimeProbeStatus(probe shared.Probe, now time.Time) shared.Probe {
	if strings.EqualFold(probe.Status, "offline") {
		return probe
	}
	if s.probeOfflineAfter <= 0 || probe.LastHeartbeatAt.IsZero() {
		return probe
	}
	if now.Sub(probe.LastHeartbeatAt) > s.probeOfflineAfter {
		probe.Status = "offline"
	}
	return probe
}

func (s *Service) ReportSummary(ctx context.Context, tenantID string, since time.Time) (shared.ReportSummary, error) {
	alerts, err := s.store.ListAlerts(ctx, shared.AlertQuery{TenantID: tenantID})
	if err != nil {
		return shared.ReportSummary{}, err
	}
	tickets, err := s.store.ListTickets(ctx, tenantID)
	if err != nil {
		return shared.ReportSummary{}, err
	}

	alertTrendMap := map[string]int{}
	ticketTrendMap := map[string]int{}
	signatureMap := map[string]int{}
	sourceMap := map[string]int{}

	for _, alert := range alerts {
		if !since.IsZero() && alert.LastSeenAt.Before(since) {
			continue
		}
		day := alert.LastSeenAt.Format("2006-01-02")
		alertTrendMap[day]++
		signatureMap[alert.Signature] += alert.EventCount
		sourceMap[alert.SrcIP] += alert.EventCount
	}
	for _, ticket := range tickets {
		if !since.IsZero() && ticket.CreatedAt.Before(since) {
			continue
		}
		day := ticket.CreatedAt.Format("2006-01-02")
		ticketTrendMap[day]++
	}

	return shared.ReportSummary{
		AlertTrend:    topTrend(alertTrendMap, 7),
		TicketTrend:   topTrend(ticketTrendMap, 7),
		TopSignatures: topTrend(signatureMap, 5),
		TopSourceIPs:  topTrend(sourceMap, 5),
	}, nil
}

func (s *Service) ReportSummaryForUser(ctx context.Context, user shared.User, tenantID string, since time.Time) (shared.ReportSummary, error) {
	if contains(user.Permissions, "*") && len(user.AllowedAssetIDs) == 0 && len(user.AllowedOrgIDs) == 0 {
		return s.ReportSummary(ctx, tenantID, since)
	}
	alerts, err := s.store.ListAlerts(ctx, shared.AlertQuery{TenantID: tenantID})
	if err != nil {
		return shared.ReportSummary{}, err
	}
	tickets, err := s.store.ListTickets(ctx, tenantID)
	if err != nil {
		return shared.ReportSummary{}, err
	}
	alertTrendMap := map[string]int{}
	ticketTrendMap := map[string]int{}
	signatureMap := map[string]int{}
	sourceMap := map[string]int{}
	for _, alert := range alerts {
		if !s.CanAccessAlert(ctx, user, alert) {
			continue
		}
		if !since.IsZero() && alert.LastSeenAt.Before(since) {
			continue
		}
		day := alert.LastSeenAt.Format("2006-01-02")
		alertTrendMap[day]++
		signatureMap[alert.Signature] += alert.EventCount
		sourceMap[alert.SrcIP] += alert.EventCount
	}
	for _, ticket := range tickets {
		if !s.CanAccessTicket(ctx, user, ticket) {
			continue
		}
		if !since.IsZero() && ticket.CreatedAt.Before(since) {
			continue
		}
		day := ticket.CreatedAt.Format("2006-01-02")
		ticketTrendMap[day]++
	}
	return shared.ReportSummary{
		AlertTrend:    topTrend(alertTrendMap, 7),
		TicketTrend:   topTrend(ticketTrendMap, 7),
		TopSignatures: topTrend(signatureMap, 5),
		TopSourceIPs:  topTrend(sourceMap, 5),
	}, nil
}

func (s *Service) Authorize(ctx context.Context, user shared.User, permission string) (bool, error) {
	if permission == "" {
		return true, nil
	}
	permissions, err := s.permissionsForUser(ctx, user)
	if err != nil {
		return false, err
	}
	for _, perm := range permissions {
		if perm == "*" || perm == permission {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) permissionsForUser(ctx context.Context, user shared.User) ([]string, error) {
	roles, err := s.store.ListRoles(ctx, user.TenantID)
	if err != nil {
		return nil, err
	}
	roleMap := make(map[string]shared.Role, len(roles))
	for _, role := range roles {
		roleMap[role.Name] = role
	}
	permissions := make([]string, 0)
	seen := make(map[string]struct{})
	for _, roleName := range user.Roles {
		role, ok := roleMap[roleName]
		if !ok {
			continue
		}
		for _, perm := range role.Permissions {
			if _, ok := seen[perm]; ok {
				continue
			}
			seen[perm] = struct{}{}
			permissions = append(permissions, perm)
		}
	}
	return permissions, nil
}

func (s *Service) CanAccessTenant(user shared.User, tenantID string) bool {
	if tenantID == "" {
		return true
	}
	for _, perm := range user.Permissions {
		if perm == "*" {
			return true
		}
	}
	if user.TenantID == tenantID {
		return true
	}
	for _, allowed := range user.AllowedTenants {
		if allowed == tenantID {
			return true
		}
	}
	return false
}

func (s *Service) CanAccessOrganization(user shared.User, org shared.Organization) bool {
	if contains(user.Permissions, "*") || len(user.AllowedOrgIDs) == 0 {
		return true
	}
	if contains(user.AllowedOrgIDs, org.ID) {
		return true
	}
	for _, parentID := range org.Path {
		if contains(user.AllowedOrgIDs, parentID) {
			return true
		}
	}
	return false
}

func (s *Service) CanAccessAsset(user shared.User, asset shared.Asset) bool {
	if contains(user.Permissions, "*") {
		return true
	}
	if len(user.AllowedAssetIDs) == 0 && len(user.AllowedOrgIDs) == 0 {
		return true
	}
	if len(user.AllowedAssetIDs) > 0 && contains(user.AllowedAssetIDs, asset.ID) {
		return true
	}
	if len(user.AllowedOrgIDs) > 0 && asset.OrgID != "" && contains(user.AllowedOrgIDs, asset.OrgID) {
		return true
	}
	return false
}

func (s *Service) CanAccessAlert(ctx context.Context, user shared.User, alert shared.Alert) bool {
	if contains(user.Permissions, "*") {
		return true
	}
	if len(user.AllowedProbeIDs) > 0 {
		probeOK := false
		for _, id := range alert.ProbeIDs {
			if contains(user.AllowedProbeIDs, id) {
				probeOK = true
				break
			}
		}
		if !probeOK {
			return false
		}
	}
	if len(user.AllowedAssetIDs) == 0 && len(user.AllowedOrgIDs) == 0 {
		return true
	}
	if alert.SourceAssetID != "" && contains(user.AllowedAssetIDs, alert.SourceAssetID) {
		return true
	}
	if alert.TargetAssetID != "" && contains(user.AllowedAssetIDs, alert.TargetAssetID) {
		return true
	}
	if len(user.AllowedOrgIDs) > 0 {
		assets, err := s.store.ListAssets(ctx, alert.TenantID)
		if err == nil {
			for _, asset := range assets {
				if asset.ID == alert.SourceAssetID || asset.ID == alert.TargetAssetID {
					if s.CanAccessAsset(user, asset) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (s *Service) CanAccessFlow(ctx context.Context, user shared.User, flow shared.Flow) bool {
	if contains(user.Permissions, "*") {
		return true
	}
	if len(user.AllowedAssetIDs) == 0 && len(user.AllowedOrgIDs) == 0 {
		return true
	}
	assets, err := s.store.ListAssets(ctx, flow.TenantID)
	if err != nil {
		return false
	}
	for _, asset := range assets {
		if asset.IP != flow.SrcIP && asset.IP != flow.DstIP {
			continue
		}
		if s.CanAccessAsset(user, asset) {
			return true
		}
	}
	return false
}

func (s *Service) FilterProbeIDs(user shared.User, probeIDs []string) []string {
	for _, perm := range user.Permissions {
		if perm == "*" || len(user.AllowedProbeIDs) == 0 {
			return probeIDs
		}
	}
	if len(user.AllowedProbeIDs) == 0 {
		return probeIDs
	}
	allowed := make(map[string]struct{}, len(user.AllowedProbeIDs))
	for _, id := range user.AllowedProbeIDs {
		allowed[id] = struct{}{}
	}
	out := make([]string, 0, len(probeIDs))
	for _, id := range probeIDs {
		if _, ok := allowed[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

func (s *Service) startSLALoop() {
	interval := positiveDuration(s.slaScanInterval, time.Minute)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.processSLA(context.Background())
	}
}

func (s *Service) processSLA(ctx context.Context) {
	items, err := s.store.ListTickets(ctx, "")
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, ticket := range items {
		if ticket.Status == "closed" || ticket.SLADeadline.IsZero() {
			continue
		}
		policy, ok, err := s.activeTicketAutomationPolicy(ctx, ticket.TenantID)
		if err != nil {
			continue
		}
		if ok && policy.ReminderBeforeMins > 0 && ticket.RemindedAt.IsZero() {
			remindAt := ticket.SLADeadline.Add(-time.Duration(policy.ReminderBeforeMins) * time.Minute)
			if !now.Before(remindAt) {
				updated, updatedOK, updateErr := s.store.UpdateTicketStatus(ctx, ticket.ID, func(current shared.Ticket) shared.Ticket {
					if current.Status == "closed" || !current.RemindedAt.IsZero() {
						return current
					}
					current.RemindedAt = now
					return current
				})
				if updateErr == nil && updatedOK && !updated.RemindedAt.IsZero() {
					_ = s.addActivity(ctx, updated.TenantID, "ticket", updated.ID, "ticket_reminder", "system", updated.Priority)
					s.dispatchNotification(ctx, updated.TenantID, "ticket.reminder", "ticket", updated.ID, updated)
					ticket = updated
				}
			}
		}
		if now.Before(ticket.SLADeadline) {
			continue
		}
		updated, updatedOK, updateErr := s.store.UpdateTicketStatus(ctx, ticket.ID, func(current shared.Ticket) shared.Ticket {
			if current.Status == "closed" {
				return current
			}
			if current.SLAStatus != "breached" {
				current.SLAStatus = "breached"
			}
			return current
		})
		if updateErr == nil && updatedOK && updated.SLAStatus == "breached" && ticket.SLAStatus != "breached" {
			_ = s.addActivity(ctx, updated.TenantID, "ticket", updated.ID, "sla_breach", "system", updated.Priority)
			s.dispatchNotification(ctx, updated.TenantID, "ticket.sla_breach", "ticket", updated.ID, updated)
			ticket = updated
		}
		if !ok || policy.EscalationAfterMins < 0 || !ticket.EscalatedAt.IsZero() {
			continue
		}
		escalateAt := ticket.SLADeadline.Add(time.Duration(policy.EscalationAfterMins) * time.Minute)
		if now.Before(escalateAt) {
			continue
		}
		updated, updatedOK, updateErr = s.store.UpdateTicketStatus(ctx, ticket.ID, func(current shared.Ticket) shared.Ticket {
			if current.Status == "closed" || !current.EscalatedAt.IsZero() {
				return current
			}
			current.EscalatedAt = now
			current.SLAStatus = "breached"
			if policy.EscalationAssignee != "" {
				current.Assignee = policy.EscalationAssignee
			}
			current.Status = policy.EscalationStatus
			return current
		})
		if updateErr != nil || !updatedOK || updated.EscalatedAt.IsZero() {
			continue
		}
		_ = s.addActivity(ctx, updated.TenantID, "ticket", updated.ID, "ticket_escalated", "system", updated.Assignee)
		s.dispatchNotification(ctx, updated.TenantID, "ticket.escalated", "ticket", updated.ID, updated)
	}
}

func (s *Service) slaDuration(priority string) time.Duration {
	key := strings.ToLower(strings.TrimSpace(priority))
	if value, ok := s.slaByPriority[key]; ok {
		return value
	}
	return s.slaByPriority["medium"]
}

func (s *Service) activeTicketAutomationPolicy(ctx context.Context, tenantID string) (shared.TicketAutomationPolicy, bool, error) {
	items, err := s.store.ListTicketAutomationPolicies(ctx, tenantID)
	if err != nil {
		return shared.TicketAutomationPolicy{}, false, err
	}
	for _, item := range items {
		if item.Enabled {
			return item, true, nil
		}
	}
	return shared.TicketAutomationPolicy{}, false, nil
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	var value int
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil {
		return fallback
	}
	return value
}

func positiveInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func normalizeScopeTenants(primary string, values []string) []string {
	items := uniqueStrings(values)
	if primary != "" && !contains(items, primary) {
		items = append(items, primary)
	}
	return items
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func (s *Service) addAuditLog(ctx context.Context, tenantID, userID, action, resourceType, resourceID, result string) error {
	return s.store.AddAuditLog(ctx, shared.AuditLog{
		ID:           s.nextID("audit"),
		TenantID:     tenantID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Result:       result,
		CreatedAt:    time.Now().UTC(),
	})
}

func (s *Service) RecordQueryAudit(ctx context.Context, tenantID, userID, resourceType, resourceID, result string) error {
	return s.addAuditLog(ctx, tenantID, userID, "query", resourceType, resourceID, result)
}

func (s *Service) RecordQueryStat(stat shared.QueryStat) shared.QueryStat {
	return s.queries.record(stat)
}

func (s *Service) ListQueryStats(tenantID string, slowOnly bool) []shared.QueryStat {
	items := s.queries.list()
	out := make([]shared.QueryStat, 0, len(items))
	for _, item := range items {
		if tenantID != "" && item.TenantID != tenantID {
			continue
		}
		if slowOnly && !item.Slow {
			continue
		}
		out = append(out, item)
	}
	return out
}

func (s *Service) CreateExportTask(ctx context.Context, req shared.ExportTaskRequest, userID string) (shared.ExportTask, error) {
	task := shared.ExportTask{
		ID:           s.nextID("export"),
		TenantID:     req.TenantID,
		UserID:       userID,
		ResourceType: req.ResourceType,
		Format:       normalizeExportFormat(req.Format),
		Status:       "pending",
		QuerySummary: summarizeExportRequest(req),
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(s.exportTTL),
	}
	created, err := s.store.CreateExportTask(ctx, task)
	if err != nil {
		return shared.ExportTask{}, err
	}
	go s.runExportTask(created, req)
	return created, nil
}

func (s *Service) GetExportTask(ctx context.Context, id string) (shared.ExportTask, bool, error) {
	return s.store.GetExportTask(ctx, id)
}

func (s *Service) ListExportTasks(ctx context.Context, tenantID string) ([]shared.ExportTask, error) {
	return s.store.ListExportTasks(ctx, tenantID)
}

func (s *Service) ListExportTasksForUser(ctx context.Context, user shared.User, tenantID string) ([]shared.ExportTask, error) {
	items, err := s.store.ListExportTasks(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if contains(user.Permissions, "*") {
		return items, nil
	}
	out := make([]shared.ExportTask, 0, len(items))
	for _, item := range items {
		if item.UserID == user.ID {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *Service) runExportTask(task shared.ExportTask, req shared.ExportTaskRequest) {
	ctx := context.Background()
	task.Status = "running"
	_, _ = s.store.UpdateExportTask(ctx, task)
	user, _, _ := s.store.GetUser(ctx, task.UserID)

	filePath := filepath.Join(s.exportDir, task.ID+"."+task.Format)
	var payload any
	switch task.ResourceType {
	case "alerts":
		query := req.AlertQuery
		query.TenantID = task.TenantID
		query.Page = 1
		query.PageSize = 1000
		result, err := s.SearchAlertsForUser(ctx, user, query)
		if err != nil {
			s.failExportTask(ctx, task, err)
			return
		}
		payload = result.Items
	case "flows":
		query := req.FlowQuery
		query.TenantID = task.TenantID
		items, err := s.search.SearchFlows(ctx, query)
		if err != nil {
			s.failExportTask(ctx, task, err)
			return
		}
		filtered := make([]shared.Flow, 0, len(items))
		for _, item := range items {
			if s.CanAccessFlow(ctx, user, item) {
				filtered = append(filtered, item)
			}
		}
		payload = filtered
	default:
		s.failExportTask(ctx, task, fmt.Errorf("unsupported export resource type: %s", task.ResourceType))
		return
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	switch task.Format {
	case "csv":
		data, err = encodeExportCSV(task.ResourceType, payload)
	default:
		data, err = json.MarshalIndent(payload, "", "  ")
	}
	if err != nil {
		s.failExportTask(ctx, task, err)
		return
	}
	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		s.failExportTask(ctx, task, err)
		return
	}

	task.Status = "completed"
	task.FilePath = filePath
	task.CompletedAt = time.Now().UTC()
	task.ExpiresAt = task.CompletedAt.Add(s.exportTTL)
	task.ErrorMessage = ""
	_, _ = s.store.UpdateExportTask(ctx, task)
	_ = s.addActivity(ctx, task.TenantID, "export_task", task.ID, "complete_export", task.UserID, task.ResourceType)
}

func (s *Service) failExportTask(ctx context.Context, task shared.ExportTask, err error) {
	task.Status = "failed"
	task.ErrorMessage = err.Error()
	task.CompletedAt = time.Now().UTC()
	task.ExpiresAt = task.CompletedAt.Add(s.exportTTL)
	_, _ = s.store.UpdateExportTask(ctx, task)
	_ = s.addActivity(ctx, task.TenantID, "export_task", task.ID, "fail_export", task.UserID, err.Error())
}

func summarizeExportRequest(req shared.ExportTaskRequest) string {
	switch req.ResourceType {
	case "alerts":
		return fmt.Sprintf("alerts tenant=%s conditions=%d match_mode=%s", req.TenantID, len(req.AlertQuery.EffectiveConditions()), req.AlertQuery.MatchMode)
	case "flows":
		return fmt.Sprintf("flows tenant=%s src=%s dst=%s app_proto=%s", req.TenantID, req.FlowQuery.SrcIP, req.FlowQuery.DstIP, req.FlowQuery.AppProto)
	default:
		return req.ResourceType
	}
}

func normalizeExportFormat(format string) string {
	switch format {
	case "", "json":
		return "json"
	case "csv":
		return "csv"
	default:
		return "json"
	}
}

func (s *Service) startExportCleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.cleanupExpiredExports(context.Background())
	}
}

func (s *Service) cleanupExpiredExports(ctx context.Context) {
	tasks, err := s.store.ListExportTasks(ctx, "")
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, task := range tasks {
		if task.ExpiresAt.IsZero() || task.ExpiresAt.After(now) {
			continue
		}
		if task.FilePath != "" {
			_ = os.Remove(task.FilePath)
		}
		if task.Status == "completed" {
			task.Status = "expired"
			task.FilePath = ""
			_, _ = s.store.UpdateExportTask(ctx, task)
			_ = s.addActivity(ctx, task.TenantID, "export_task", task.ID, "expire_export", "", task.ResourceType)
		}
	}
}

func positiveDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func encodeExportCSV(resourceType string, payload any) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	switch resourceType {
	case "alerts":
		items, _ := payload.([]shared.Alert)
		if err := writer.Write([]string{"id", "tenant_id", "signature", "src_ip", "dst_ip", "dst_port", "severity", "risk_score", "attack_result", "status", "assignee", "first_seen_at", "last_seen_at", "event_count"}); err != nil {
			return nil, err
		}
		for _, item := range items {
			if err := writer.Write([]string{
				item.ID,
				item.TenantID,
				item.Signature,
				item.SrcIP,
				item.DstIP,
				fmt.Sprintf("%d", item.DstPort),
				fmt.Sprintf("%d", item.Severity),
				fmt.Sprintf("%d", item.RiskScore),
				item.AttackResult,
				item.Status,
				item.Assignee,
				item.FirstSeenAt.Format(time.RFC3339),
				item.LastSeenAt.Format(time.RFC3339),
				fmt.Sprintf("%d", item.EventCount),
			}); err != nil {
				return nil, err
			}
		}
	case "flows":
		items, _ := payload.([]shared.Flow)
		if err := writer.Write([]string{"id", "tenant_id", "probe_id", "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "app_proto", "seen_at"}); err != nil {
			return nil, err
		}
		for _, item := range items {
			if err := writer.Write([]string{
				item.ID,
				item.TenantID,
				item.ProbeID,
				item.FlowID,
				item.SrcIP,
				fmt.Sprintf("%d", item.SrcPort),
				item.DstIP,
				fmt.Sprintf("%d", item.DstPort),
				item.Proto,
				item.AppProto,
				item.SeenAt.Format(time.RFC3339),
			}); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unsupported csv export resource type: %s", resourceType)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (s *Service) addActivity(ctx context.Context, tenantID, resourceType, resourceID, action, operator, detail string) error {
	return s.store.AddActivity(ctx, shared.Activity{
		ID:           s.nextID("activity"),
		TenantID:     tenantID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       action,
		Operator:     operator,
		Detail:       detail,
		CreatedAt:    time.Now().UTC(),
	})
}

func (s *Service) CreateNotificationChannel(ctx context.Context, req shared.CreateNotificationChannelRequest, operatorID string) (shared.NotificationChannel, error) {
	channel := shared.NotificationChannel{
		ID:        s.nextID("notify-channel"),
		TenantID:  req.TenantID,
		Name:      req.Name,
		Type:      normalizeNotificationType(req.Type),
		Target:    strings.TrimSpace(req.Target),
		Enabled:   req.Enabled,
		Events:    normalizeNotificationEvents(req.Events),
		CreatedAt: time.Now().UTC(),
	}
	created, err := s.store.CreateNotificationChannel(ctx, channel)
	if err != nil {
		return shared.NotificationChannel{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_notification_channel", "notification_channel", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "notification_channel", created.ID, "create_notification_channel", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListNotificationChannels(ctx context.Context, tenantID string) ([]shared.NotificationChannel, error) {
	return s.store.ListNotificationChannels(ctx, tenantID)
}

func (s *Service) CreateNotificationTemplate(ctx context.Context, req shared.CreateNotificationTemplateRequest, operatorID string) (shared.NotificationTemplate, error) {
	template := shared.NotificationTemplate{
		ID:            s.nextID("notify-template"),
		TenantID:      req.TenantID,
		Name:          req.Name,
		EventType:     strings.ToLower(strings.TrimSpace(req.EventType)),
		TitleTemplate: req.TitleTemplate,
		BodyTemplate:  req.BodyTemplate,
		CreatedAt:     time.Now().UTC(),
	}
	created, err := s.store.CreateNotificationTemplate(ctx, template)
	if err != nil {
		return shared.NotificationTemplate{}, err
	}
	_ = s.addAuditLog(ctx, req.TenantID, operatorID, "create_notification_template", "notification_template", created.ID, "success")
	_ = s.addActivity(ctx, req.TenantID, "notification_template", created.ID, "create_notification_template", operatorID, created.Name)
	return created, nil
}

func (s *Service) ListNotificationTemplates(ctx context.Context, tenantID string) ([]shared.NotificationTemplate, error) {
	return s.store.ListNotificationTemplates(ctx, tenantID)
}

func (s *Service) ListNotificationRecords(ctx context.Context, tenantID string) ([]shared.NotificationRecord, error) {
	return s.store.ListNotificationRecords(ctx, tenantID)
}

func (s *Service) dispatchNotification(ctx context.Context, tenantID, eventType, resourceType, resourceID string, payload any) {
	channels, err := s.store.ListNotificationChannels(ctx, tenantID)
	if err != nil {
		return
	}
	summary := s.renderNotificationSummary(ctx, tenantID, eventType, resourceType, resourceID, payload)
	for _, channel := range channels {
		if !channel.Enabled || !notificationEventEnabled(channel.Events, eventType) {
			continue
		}
		record := shared.NotificationRecord{
			ID:           s.nextID("notify-record"),
			TenantID:     tenantID,
			ChannelID:    channel.ID,
			ChannelName:  channel.Name,
			ChannelType:  channel.Type,
			Target:       channel.Target,
			EventType:    eventType,
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Status:       "sent",
			Summary:      summary,
			CreatedAt:    time.Now().UTC(),
			DeliveredAt:  time.Now().UTC(),
		}
		if err := s.deliverNotificationWithRetry(ctx, channel, eventType, resourceType, resourceID, payload, summary); err != nil {
			record.Status = "failed"
			record.ErrorMessage = err.Error()
			record.DeliveredAt = time.Time{}
			record.RetryCount = 0
			record.NextRetryAt = time.Now().UTC().Add(s.notifyRetryScanIntv)
		}
		_, _ = s.store.CreateNotificationRecord(ctx, record)
	}
}

func (s *Service) deliverNotificationWithRetry(ctx context.Context, channel shared.NotificationChannel, eventType, resourceType, resourceID string, payload any, summary string) error {
	var lastErr error
	for attempt := 0; attempt <= s.notifyRetryMax; attempt++ {
		if attempt > 0 {
			time.Sleep(s.notifyRetryBackoff)
		}
		if err := s.deliverNotification(ctx, channel, eventType, resourceType, resourceID, payload, summary); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func (s *Service) deliverNotification(ctx context.Context, channel shared.NotificationChannel, eventType, resourceType, resourceID string, payload any, summary string) error {
	switch channel.Type {
	case "console":
		return nil
	case "webhook":
		if channel.Target == "" {
			return fmt.Errorf("webhook target is empty")
		}
		body, err := json.Marshal(map[string]any{
			"event_type":    eventType,
			"resource_type": resourceType,
			"resource_id":   resourceID,
			"summary":       summary,
			"payload":       payload,
			"sent_at":       time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, channel.Target, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("webhook status %d", resp.StatusCode)
		}
		return nil
	default:
		return fmt.Errorf("unsupported notification channel type: %s", channel.Type)
	}
}

func (s *Service) renderNotificationSummary(ctx context.Context, tenantID, eventType, resourceType, resourceID string, payload any) string {
	templates, err := s.store.ListNotificationTemplates(ctx, tenantID)
	if err != nil {
		return summarizeNotificationPayload(payload)
	}
	for _, template := range templates {
		if strings.EqualFold(template.EventType, eventType) {
			return applyNotificationTemplate(template, eventType, resourceType, resourceID, payload)
		}
	}
	return summarizeNotificationPayload(payload)
}

func applyNotificationTemplate(template shared.NotificationTemplate, eventType, resourceType, resourceID string, payload any) string {
	values := map[string]string{
		"event_type":    eventType,
		"resource_type": resourceType,
		"resource_id":   resourceID,
	}
	data, _ := json.Marshal(payload)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	for key, value := range raw {
		values[key] = fmt.Sprint(value)
	}
	title := template.TitleTemplate
	body := template.BodyTemplate
	for key, value := range values {
		title = strings.ReplaceAll(title, "{{"+key+"}}", value)
		body = strings.ReplaceAll(body, "{{"+key+"}}", value)
	}
	if strings.TrimSpace(title) == "" && strings.TrimSpace(body) == "" {
		return summarizeNotificationPayload(payload)
	}
	if strings.TrimSpace(title) == "" {
		return body
	}
	if strings.TrimSpace(body) == "" {
		return title
	}
	return title + " | " + body
}

func (s *Service) startNotificationRetryLoop() {
	ticker := time.NewTicker(positiveDuration(s.notifyRetryScanIntv, 30*time.Second))
	defer ticker.Stop()
	for range ticker.C {
		s.retryNotificationRecords(context.Background())
	}
}

func (s *Service) retryNotificationRecords(ctx context.Context) {
	records, err := s.store.ListNotificationRecords(ctx, "")
	if err != nil {
		return
	}
	channels, err := s.store.ListNotificationChannels(ctx, "")
	if err != nil {
		return
	}
	channelMap := make(map[string]shared.NotificationChannel, len(channels))
	for _, channel := range channels {
		channelMap[channel.ID] = channel
	}
	now := time.Now().UTC()
	for _, record := range records {
		if record.Status != "failed" || record.RetryCount >= s.notifyRetryMax {
			continue
		}
		if !record.NextRetryAt.IsZero() && now.Before(record.NextRetryAt) {
			continue
		}
		channel, ok := channelMap[record.ChannelID]
		if !ok || !channel.Enabled {
			continue
		}
		err := s.deliverNotification(ctx, channel, record.EventType, record.ResourceType, record.ResourceID, map[string]any{"retry": true}, record.Summary)
		record.RetryCount++
		if err != nil {
			record.ErrorMessage = err.Error()
			record.NextRetryAt = now.Add(s.notifyRetryScanIntv)
		} else {
			record.Status = "sent"
			record.ErrorMessage = ""
			record.DeliveredAt = now
			record.NextRetryAt = time.Time{}
		}
		_, _ = s.store.UpdateNotificationRecord(ctx, record)
	}
}

func normalizeNotificationType(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "webhook") {
		return "webhook"
	}
	return "console"
}

func normalizeNotificationEvents(events []string) []string {
	if len(events) == 0 {
		return []string{"ticket.created", "ticket.updated", "alert.updated"}
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(events))
	for _, event := range events {
		item := strings.TrimSpace(strings.ToLower(event))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	if len(out) == 0 {
		return []string{"ticket.created", "ticket.updated", "alert.updated"}
	}
	return out
}

func normalizeEscalationStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "open", "in_progress", "escalated", "closed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "escalated"
	}
}

func normalizeProbeUpgradeAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "upgrade", "rollback":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "upgrade"
	}
}

func normalizeProbeUpgradeStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "applied", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "applied"
	}
}

func notificationEventEnabled(events []string, target string) bool {
	for _, event := range events {
		if event == "*" || strings.EqualFold(event, target) {
			return true
		}
	}
	return false
}

func summarizeNotificationPayload(payload any) string {
	data, err := json.Marshal(payload)
	if err != nil {
		return "payload_unavailable"
	}
	const limit = 240
	if len(data) <= limit {
		return string(data)
	}
	return string(data[:limit]) + "..."
}

func (s *Service) bootstrap() {
	ctx := context.Background()
	now := time.Now().UTC()
	existingRoles, err := s.store.ListRoles(ctx, "demo-tenant")
	if err != nil {
		return
	}
	existingRoleNames := make(map[string]struct{}, len(existingRoles))
	for _, role := range existingRoles {
		existingRoleNames[role.Name] = struct{}{}
	}
	templates := bootstrapRoles(now, s.nextID)
	for _, role := range templates {
		if _, ok := existingRoleNames[role.Name]; ok {
			continue
		}
		if _, err := s.store.CreateRole(ctx, role); err != nil {
			return
		}
	}
	adminUser, _, err := s.store.FindUser(ctx, "demo-tenant", "admin")
	if err == nil && adminUser.ID != "" {
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	_, _ = s.store.CreateUser(ctx, shared.User{
		ID:          s.nextID("user"),
		TenantID:    "demo-tenant",
		Username:    "admin",
		DisplayName: "System Admin",
		Password:    string(passwordHash),
		Status:      "active",
		Roles:       []string{"admin", "system_admin"},
		CreatedAt:   now,
	})
}

func roleTemplates() []shared.RoleTemplate {
	return []shared.RoleTemplate{
		{
			Name:        "system_admin",
			Label:       "系统管理员",
			Description: "负责平台运行、探针、配置、用户权限、审计和系统治理。",
			Permissions: []string{"probe.read", "probe.write", "user.read", "user.write", "role.read", "role.write", "notify.read", "notify.write", "policy.read", "policy.write", "audit.read", "alert.read", "ticket.read", "asset.read", "intel.read"},
			Modules:     []string{"overview", "probes", "policies", "notifications", "users", "roles", "audit", "query-stats", "reports"},
		},
		{
			Name:        "security_operator",
			Label:       "安全运营人员",
			Description: "负责告警确认、关闭、转工单和处置闭环。",
			Permissions: []string{"alert.read", "alert.write", "ticket.read", "ticket.write", "notify.read"},
			Modules:     []string{"overview", "alerts", "tickets", "reports", "exports", "notifications"},
		},
		{
			Name:        "security_analyst",
			Label:       "安全分析人员",
			Description: "负责告警研判、流量分析、资产和情报联动。",
			Permissions: []string{"alert.read", "ticket.read", "asset.read", "intel.read"},
			Modules:     []string{"overview", "alerts", "flows", "assets", "intel", "reports", "exports"},
		},
		{
			Name:        "auditor",
			Label:       "审计人员",
			Description: "负责审计、查询统计和运营监督，不直接参与处置。",
			Permissions: []string{"audit.read"},
			Modules:     []string{"overview", "reports", "audit", "query-stats"},
		},
	}
}

func recommendedWorkbenchItems(role string) []string {
	switch role {
	case "system_admin":
		return []string{"优先检查探针在线率、版本和下发失败记录。", "查看审计日志和查询统计，确认平台运行稳定。", "变更配置、规则和升级前先核对租户与范围。"}
	case "security_operator":
		return []string{"优先处理高风险、未关闭和重复命中的告警。", "将需要跟进的告警及时转工单并确认责任人。", "重点关注超时工单和批量处置结果。"}
	case "security_analyst":
		return []string{"先看高风险告警的协议上下文、资产命中和情报标签。", "结合流量检索回溯同流量、同目标的上下文事件。", "研判后补充情报或资产标签，方便运营闭环。"}
	case "auditor":
		return []string{"查看审计日志、查询统计和导出记录。", "关注异常查询、批量操作和配置变更。", "按报表结果监督告警闭环和工单时效。"}
	default:
		return []string{"根据权限选择需要的模块。"}
	}
}

func bootstrapRoles(now time.Time, nextID func(string) string) []shared.Role {
	out := []shared.Role{
		{
			ID:          nextID("role"),
			TenantID:    "demo-tenant",
			Name:        "admin",
			Description: "默认超级管理员",
			Permissions: []string{"*"},
			CreatedAt:   now,
		},
	}
	for _, template := range roleTemplates() {
		out = append(out, shared.Role{
			ID:          nextID("role"),
			TenantID:    "demo-tenant",
			Name:        template.Name,
			Description: template.Description,
			Permissions: template.Permissions,
			CreatedAt:   now,
		})
	}
	return out
}

func pipelineParseTime(value string) time.Time { return pipelineParse(value) }

func pipelineParse(value string) time.Time {
	if value == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Now().UTC()
	}
	return t.UTC()
}

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
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

func intersectStrings(left, right []string) []string {
	if len(left) == 0 {
		return []string{}
	}
	allowed := make(map[string]struct{}, len(right))
	for _, item := range right {
		allowed[item] = struct{}{}
	}
	out := make([]string, 0, len(left))
	for _, item := range left {
		if _, ok := allowed[item]; ok {
			out = append(out, item)
		}
	}
	return out
}

func alertWindowMinutes(firstSeenAt, lastSeenAt time.Time) int {
	if firstSeenAt.IsZero() || lastSeenAt.IsZero() || lastSeenAt.Before(firstSeenAt) {
		return 0
	}
	duration := lastSeenAt.Sub(firstSeenAt)
	minutes := int(duration.Minutes())
	if duration > 0 && minutes == 0 {
		return 1
	}
	if minutes < 0 {
		return 0
	}
	return minutes
}

func (s *Service) findSimilarAlerts(ctx context.Context, alert shared.Alert, mode string) ([]shared.Alert, error) {
	items, err := s.store.ListAlerts(ctx, shared.AlertQuery{TenantID: alert.TenantID})
	if err != nil {
		return nil, err
	}
	out := make([]shared.Alert, 0, 20)
	for _, item := range items {
		if item.ID == alert.ID {
			continue
		}
		switch mode {
		case "source":
			if item.SrcIP != alert.SrcIP {
				continue
			}
		case "target":
			if item.DstIP != alert.DstIP {
				continue
			}
		default:
			continue
		}
		out = append(out, item)
		if len(out) == 20 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeenAt.Before(out[j].LastSeenAt)
	})
	return out, nil
}

func buildAlertDecisionBasis(alert shared.Alert, events []shared.RawEvent, contextEvents []shared.RawEvent) shared.AlertDecisionBasis {
	attackResult, reason, snippet := inferAttackResultReason(events, contextEvents, alert.AttackResult)
	aggregation := []string{
		fmt.Sprintf("按源地址 %s、目的地址 %s、端口 %d、协议 %s、规则 %d 聚合", alert.SrcIP, alert.DstIP, alert.DstPort, alert.Proto, alert.SignatureID),
		fmt.Sprintf("当前聚合窗口 %d 分钟，累计命中 %d 次", maxInt(alert.WindowMinutes, 1), alert.EventCount),
		fmt.Sprintf("跨 %d 个探针合并", maxInt(alert.ProbeCount, len(alert.ProbeIDs))),
	}
	risk := []string{
		fmt.Sprintf("基础严重级别为 %s", formatSeverityText(alert.Severity)),
	}
	if len(alert.ThreatIntelHits) > 0 {
		risk = append(risk, fmt.Sprintf("命中情报 %d 项", len(alert.ThreatIntelHits)))
	}
	if alert.TargetAssetName != "" {
		risk = append(risk, fmt.Sprintf("目标资产 %s 纳入风险加权", alert.TargetAssetName))
	}
	risk = append(risk, fmt.Sprintf("当前风险分 %d", alert.RiskScore))
	return shared.AlertDecisionBasis{
		AttackResult:       attackResult,
		AttackResultReason: reason,
		ResponseSnippet:    snippet,
		AggregationReason:  aggregation,
		RiskReason:         risk,
	}
}

func inferAttackResultReason(events []shared.RawEvent, contextEvents []shared.RawEvent, attackResult string) (string, string, string) {
	all := append([]shared.RawEvent{}, contextEvents...)
	all = append(all, events...)
	successStatus := 0
	successSnippet := ""
	failedStatus := 0
	failedSnippet := ""
	attemptedStatus := 0
	attemptedSnippet := ""
	for _, event := range all {
		status := extractHTTPStatus(event.Payload)
		if status == 0 {
			continue
		}
		snippet := responseSnippet(event.Payload, status)
		switch {
		case status >= 200 && status < 300:
			if successStatus == 0 {
				successStatus = status
				successSnippet = snippet
			}
		case status >= 300 && status < 400:
			if attemptedStatus == 0 {
				attemptedStatus = status
				attemptedSnippet = snippet
			}
		case status >= 400:
			if failedStatus == 0 {
				failedStatus = status
				failedSnippet = snippet
			}
		}
	}
	switch {
	case successStatus != 0:
		return "success", fmt.Sprintf("依据 HTTP 响应状态码 %d 判定为攻击成功", successStatus), successSnippet
	case failedStatus != 0:
		return "failed", fmt.Sprintf("依据 HTTP 响应状态码 %d 判定为攻击失败", failedStatus), failedSnippet
	case attemptedStatus != 0:
		return "attempted", fmt.Sprintf("依据 HTTP 重定向状态码 %d 判定为攻击尝试", attemptedStatus), attemptedSnippet
	}
	for _, event := range all {
		method := extractHTTPMethod(event.Payload)
		url := extractHTTPURL(event.Payload)
		if method != "" || url != "" {
			derived := strongerAttackResult(attackResult, "attempted")
			return derived, fmt.Sprintf("观察到请求 %s %s，但缺少可靠成功响应，判定为%s", blankAs(method, "HTTP"), blankAs(url, "目标资源"), formatAttackResultText(derived)), ""
		}
	}
	normalized := normalizeAttackResult(attackResult)
	return normalized, fmt.Sprintf("缺少可用于判定的响应包，当前结果为%s", formatAttackResultText(normalized)), ""
}

func buildRelatedAlertTimeline(relation string, current shared.Alert, alerts []shared.Alert, rawEvents []shared.RawEvent) []shared.AlertTimelineItem {
	items := make([]shared.AlertTimelineItem, 0, len(alerts)+len(rawEvents))
	seen := make(map[string]struct{}, len(alerts)+len(rawEvents))
	for _, alert := range alerts {
		if _, ok := seen[alert.ID]; ok {
			continue
		}
		seen[alert.ID] = struct{}{}
		items = append(items, shared.AlertTimelineItem{
			Timestamp:    alert.LastSeenAt,
			Relation:     relation,
			ItemKind:     "aggregate",
			EventType:    "alert",
			Title:        alert.Signature,
			Summary:      fmt.Sprintf("%s -> %s:%d · %s · %s · %d 次", alert.SrcIP, alert.DstIP, alert.DstPort, formatAttackResultText(alert.AttackResult), formatSeverityText(alert.Severity), alert.EventCount),
			AlertID:      alert.ID,
			SrcIP:        alert.SrcIP,
			DstIP:        alert.DstIP,
			AttackResult: alert.AttackResult,
		})
	}
	for _, event := range rawEvents {
		switch relation {
		case "source":
			if event.Payload.SrcIP != current.SrcIP {
				continue
			}
		case "target":
			if event.Payload.DstIP != current.DstIP {
				continue
			}
		default:
			continue
		}
		item := shared.AlertTimelineItem{
			Timestamp:  event.EventTime,
			Relation:   relation,
			ItemKind:   "protocol",
			EventType:  event.Payload.EventType,
			Title:      flowTimelineTitle(event),
			Summary:    flowTimelineSummary(event),
			RawEventID: event.ID,
			FlowID:     event.Payload.FlowID,
			ProbeID:    event.ProbeID,
			SrcIP:      event.Payload.SrcIP,
			DstIP:      event.Payload.DstIP,
		}
		if strings.EqualFold(event.Payload.EventType, "alert") {
			item.ItemKind = "raw"
			item.AttackResult = rawAlertItemFromEvent(event).AttackResult
		}
		key := "raw:" + event.ID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})
	return items
}

func buildFlowTimeline(events []shared.RawEvent, contextEvents []shared.RawEvent) []shared.AlertTimelineItem {
	all := append([]shared.RawEvent{}, events...)
	all = append(all, contextEvents...)
	items := make([]shared.AlertTimelineItem, 0, len(all))
	seen := make(map[string]struct{}, len(all))
	for _, event := range all {
		key := event.ID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, shared.AlertTimelineItem{
			Timestamp:  event.EventTime,
			Relation:   "flow",
			ItemKind:   "protocol",
			EventType:  event.Payload.EventType,
			Title:      flowTimelineTitle(event),
			Summary:    flowTimelineSummary(event),
			RawEventID: event.ID,
			FlowID:     event.Payload.FlowID,
			ProbeID:    event.ProbeID,
			SrcIP:      event.Payload.SrcIP,
			DstIP:      event.Payload.DstIP,
		})
		if strings.EqualFold(event.Payload.EventType, "alert") {
			items[len(items)-1].ItemKind = "raw"
			items[len(items)-1].AttackResult = rawAlertItemFromEvent(event).AttackResult
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})
	return items
}

func flowTimelineTitle(event shared.RawEvent) string {
	switch strings.ToLower(strings.TrimSpace(event.Payload.EventType)) {
	case "alert":
		if event.Payload.Alert != nil && event.Payload.Alert.Signature != "" {
			return event.Payload.Alert.Signature
		}
	case "http":
		method := extractHTTPMethod(event.Payload)
		url := extractHTTPURL(event.Payload)
		if method != "" || url != "" {
			return strings.TrimSpace(method + " " + url)
		}
	case "dns":
		if value := extractDNSName(event.Payload); value != "" {
			return value
		}
	case "tls":
		if value := extractTLSSNI(event.Payload); value != "" {
			return value
		}
	}
	return fmt.Sprintf("%s 事件", strings.ToUpper(blankAs(event.Payload.EventType, "raw")))
}

func flowTimelineSummary(event shared.RawEvent) string {
	switch strings.ToLower(strings.TrimSpace(event.Payload.EventType)) {
	case "alert":
		if event.Payload.Alert != nil {
			return fmt.Sprintf("%s · %s", event.Payload.Alert.Category, formatAttackResultText(rawAlertItemFromEvent(event).AttackResult))
		}
	case "http":
		status := extractHTTPStatus(event.Payload)
		host := extractHTTPHost(event.Payload)
		if status != 0 || host != "" {
			return fmt.Sprintf("主机 %s · HTTP %s", blankAs(host, "-"), blankAs(fmt.Sprintf("%d", status), "-"))
		}
	case "dns":
		return fmt.Sprintf("DNS 查询 %s", blankAs(extractDNSName(event.Payload), "-"))
	case "tls":
		return fmt.Sprintf("TLS SNI %s", blankAs(extractTLSSNI(event.Payload), "-"))
	}
	return fmt.Sprintf("%s:%d -> %s:%d · %s", event.Payload.SrcIP, event.Payload.SrcPort, event.Payload.DstIP, event.Payload.DstPort, strings.ToUpper(blankAs(event.Payload.AppProto, event.Payload.Proto)))
}

func extractHTTPStatus(event shared.SuricataEvent) int {
	httpPayload, _ := event.Payload["http"].(map[string]any)
	for _, value := range []any{
		httpPayload["status"],
		event.Payload["status"],
		event.Payload["http_status"],
	} {
		switch typed := value.(type) {
		case int:
			return typed
		case int32:
			return int(typed)
		case int64:
			return int(typed)
		case float64:
			return int(typed)
		case string:
			var parsed int
			if _, err := fmt.Sscanf(strings.TrimSpace(typed), "%d", &parsed); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func extractHTTPMethod(event shared.SuricataEvent) string {
	httpPayload, _ := event.Payload["http"].(map[string]any)
	return firstNonEmptyString(httpPayload["http_method"], event.Payload["http_method"], event.Payload["method"])
}

func extractHTTPURL(event shared.SuricataEvent) string {
	httpPayload, _ := event.Payload["http"].(map[string]any)
	return firstNonEmptyString(httpPayload["url"], event.Payload["url"], event.Payload["uri"])
}

func extractHTTPHost(event shared.SuricataEvent) string {
	httpPayload, _ := event.Payload["http"].(map[string]any)
	return firstNonEmptyString(httpPayload["hostname"], httpPayload["host"], event.Payload["hostname"], event.Payload["host"])
}

func extractDNSName(event shared.SuricataEvent) string {
	dnsPayload, _ := event.Payload["dns"].(map[string]any)
	return firstNonEmptyString(dnsPayload["rrname"], dnsPayload["query"], event.Payload["rrname"])
}

func extractTLSSNI(event shared.SuricataEvent) string {
	tlsPayload, _ := event.Payload["tls"].(map[string]any)
	return firstNonEmptyString(tlsPayload["sni"], event.Payload["sni"])
}

func firstNonEmptyString(values ...any) string {
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return typed
			}
		case fmt.Stringer:
			rendered := strings.TrimSpace(typed.String())
			if rendered != "" {
				return rendered
			}
		}
	}
	return ""
}

func blankAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func formatSeverityText(severity int) string {
	switch severity {
	case 1:
		return "高危"
	case 2:
		return "中危"
	case 3:
		return "低危"
	default:
		return "未知"
	}
}

func formatAttackResultText(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "success":
		return "攻击成功"
	case "failed":
		return "攻击失败"
	case "attempted":
		return "攻击尝试"
	default:
		return "攻击结果未知"
	}
}

func responseSnippet(event shared.SuricataEvent, status int) string {
	body := firstNonEmptyString(
		event.Payload["http_response_body"],
		nestedObjectValue(event.Payload, "http", "http_response_body"),
		event.Payload["response_body"],
	)
	body = summarizeForSnippet(body)
	if body != "" {
		return fmt.Sprintf("HTTP %d · %s", status, body)
	}
	return fmt.Sprintf("HTTP %d", status)
}

func buildPacketEvidence(events []shared.RawEvent, contextEvents []shared.RawEvent) *shared.HTTPPacketEvidence {
	all := collectHTTPPacketRelevantEvents(events, contextEvents)
	if len(all) == 0 {
		return nil
	}
	builder := httpPacketBuilder{}
	for _, event := range all {
		builder.mergePacketSource(event.Payload)
		builder.mergeHTTPContext(event.Payload)
	}
	evidence := builder.build()
	if evidence == nil {
		return nil
	}
	return evidence
}

type httpPacketBuilder struct {
	source          string
	method          string
	url             string
	host            string
	status          int
	requestPacket   string
	responsePacket  string
	requestHeaders  []sharedHeader
	responseHeaders []sharedHeader
	requestBody     string
	responseBody    string
}

type sharedHeader struct {
	Name  string
	Value string
}

func collectHTTPPacketRelevantEvents(events []shared.RawEvent, contextEvents []shared.RawEvent) []shared.RawEvent {
	all := append([]shared.RawEvent{}, events...)
	all = append(all, contextEvents...)
	out := make([]shared.RawEvent, 0, len(all))
	primaryFlow := ""
	primaryTxID := ""
	if len(events) > 0 {
		primaryFlow = events[0].Payload.FlowID
		primaryTxID = extractPayloadTXID(events[0].Payload.Payload)
	}
	for _, event := range all {
		payload := event.Payload.Payload
		if !hasHTTPPacketContext(event.Payload) {
			continue
		}
		if primaryFlow != "" && event.Payload.FlowID != "" && event.Payload.FlowID != primaryFlow {
			continue
		}
		if primaryTxID != "" {
			txID := extractPayloadTXID(payload)
			if txID != "" && txID != primaryTxID {
				continue
			}
		}
		out = append(out, event)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].EventTime.Before(out[j].EventTime)
	})
	return out
}

func hasHTTPPacketContext(event shared.SuricataEvent) bool {
	if packetMap := extractPacketMap(event.Payload); len(packetMap) > 0 {
		return true
	}
	if strings.EqualFold(event.AppProto, "http") || strings.EqualFold(event.EventType, "http") {
		return true
	}
	if _, ok := event.Payload["http"].(map[string]any); ok {
		return true
	}
	if firstNonEmptyString(
		event.Payload["payload_printable"],
		event.Payload["http_request_body"],
		event.Payload["http_response_body_printable"],
		event.Payload["http_response_body"],
	) != "" {
		return true
	}
	return false
}

func (b *httpPacketBuilder) mergePacketSource(event shared.SuricataEvent) {
	packetMap := extractPacketMap(event.Payload)
	if len(packetMap) == 0 {
		return
	}
	if requestPacket := truncatePacketEvidence(firstNonEmptyString(packetMap["request_packet"])); requestPacket != "" {
		if len(requestPacket) >= len(b.requestPacket) {
			b.requestPacket = requestPacket
		}
	}
	if responsePacket := truncatePacketEvidence(firstNonEmptyString(packetMap["response_packet"])); responsePacket != "" {
		if len(responsePacket) >= len(b.responsePacket) {
			b.responsePacket = responsePacket
		}
	}
	if source := firstNonEmptyString(packetMap["source"]); source != "" {
		b.source = source
	}
}

func (b *httpPacketBuilder) mergeHTTPContext(event shared.SuricataEvent) {
	payload := event.Payload
	if method := extractHTTPMethod(event); method != "" {
		b.method = method
	}
	if url := extractHTTPURL(event); url != "" {
		b.url = url
	}
	if host := extractHTTPHost(event); host != "" {
		b.host = host
	}
	if status := extractHTTPStatus(event); status != 0 {
		b.status = status
	}
	if requestPacket := extractReadableHTTPRequest(event); requestPacket != "" && len(requestPacket) >= len(b.requestPacket) {
		b.requestPacket = truncatePacketEvidence(requestPacket)
	}
	if responsePacket := extractReadableHTTPResponse(event); responsePacket != "" && len(responsePacket) >= len(b.responsePacket) {
		b.responsePacket = truncatePacketEvidence(responsePacket)
	}
	b.requestHeaders = mergeHeaders(b.requestHeaders, extractHeaders(event, "request_headers"))
	b.responseHeaders = mergeHeaders(b.responseHeaders, extractHeaders(event, "response_headers"))
	if body := selectPacketBody(
		decodeEvidenceBody(firstNonEmptyString(payload["http_request_body"], nestedObjectValue(payload, "http", "http_request_body"), payload["request_body"])),
		decodeEvidenceBody(firstNonEmptyString(payload["http_request_body_printable"], nestedObjectValue(payload, "http", "http_request_body_printable"))),
	); len(body) >= len(b.requestBody) {
		b.requestBody = truncatePacketEvidence(body)
	}
	if body := selectPacketBody(
		firstNonEmptyString(payload["http_response_body_printable"], nestedObjectValue(payload, "http", "http_response_body_printable")),
		decodeEvidenceBody(firstNonEmptyString(payload["http_response_body"], nestedObjectValue(payload, "http", "http_response_body"), payload["response_body"])),
	); len(body) >= len(b.responseBody) {
		b.responseBody = truncatePacketEvidence(body)
	}
}

func (b *httpPacketBuilder) build() *shared.HTTPPacketEvidence {
	requestPacket := strings.TrimSpace(b.requestPacket)
	if requestPacket == "" {
		requestPacket = buildHTTPRequestPacket(b.method, b.url, b.host, b.requestHeaders, b.requestBody)
	}
	responsePacket := strings.TrimSpace(b.responsePacket)
	if responsePacket == "" {
		responsePacket = buildHTTPResponsePacket(b.status, b.responseHeaders, b.responseBody)
	}
	if requestPacket == "" && responsePacket == "" {
		return nil
	}
	source := b.source
	if source == "" {
		source = "eve.json"
	}
	return &shared.HTTPPacketEvidence{
		Source:         source,
		Method:         b.method,
		URL:            b.url,
		Host:           b.host,
		Status:         b.status,
		RequestPacket:  truncatePacketEvidence(requestPacket),
		ResponsePacket: truncatePacketEvidence(responsePacket),
	}
}

func extractPacketMap(payload map[string]any) map[string]any {
	if payload == nil {
		return nil
	}
	packetMap, _ := payload["_ndr_http_packets"].(map[string]any)
	return packetMap
}

func extractReadableHTTPRequest(event shared.SuricataEvent) string {
	for _, value := range []string{
		firstNonEmptyString(event.Payload["payload_printable"]),
		decodeEvidenceBody(firstNonEmptyString(event.Payload["payload"])),
	} {
		trimmed := strings.TrimSpace(value)
		if looksLikeHTTPRequest(trimmed) {
			return trimmed
		}
	}
	return ""
}

func extractReadableHTTPResponse(event shared.SuricataEvent) string {
	for _, value := range []string{
		firstNonEmptyString(event.Payload["http_response_body_printable"], nestedObjectValue(event.Payload, "http", "http_response_body_printable")),
		decodeEvidenceBody(firstNonEmptyString(event.Payload["http_response_body"], nestedObjectValue(event.Payload, "http", "http_response_body"), event.Payload["response_body"])),
		decodeEvidenceBody(firstNonEmptyString(event.Payload["payload"])),
	} {
		trimmed := strings.TrimSpace(value)
		if looksLikeHTTPResponse(trimmed) {
			return trimmed
		}
	}
	return ""
}

func extractHeaders(event shared.SuricataEvent, key string) []sharedHeader {
	httpPayload, _ := event.Payload["http"].(map[string]any)
	values, _ := httpPayload[key].([]any)
	headers := make([]sharedHeader, 0, len(values))
	for _, value := range values {
		item, _ := value.(map[string]any)
		name := firstNonEmptyString(item["name"])
		headerValue := firstNonEmptyString(item["value"])
		if name == "" || headerValue == "" {
			continue
		}
		headers = append(headers, sharedHeader{Name: name, Value: headerValue})
	}
	return headers
}

func mergeHeaders(base []sharedHeader, incoming []sharedHeader) []sharedHeader {
	if len(incoming) == 0 {
		return base
	}
	index := make(map[string]int, len(base))
	out := append([]sharedHeader{}, base...)
	for i, header := range out {
		index[strings.ToLower(header.Name)] = i
	}
	for _, header := range incoming {
		key := strings.ToLower(header.Name)
		if pos, ok := index[key]; ok {
			out[pos] = header
			continue
		}
		index[key] = len(out)
		out = append(out, header)
	}
	return out
}

func buildHTTPRequestPacket(method, url, host string, headers []sharedHeader, body string) string {
	if method == "" && url == "" && host == "" && body == "" && len(headers) == 0 {
		return ""
	}
	startLine := strings.TrimSpace(fmt.Sprintf("%s %s HTTP/1.1", blankAs(method, "GET"), blankAs(url, "/")))
	headerLines := make([]string, 0, len(headers)+1)
	merged := mergeHeaders(headers, []sharedHeader{{Name: "Host", Value: host}})
	for _, header := range merged {
		if strings.TrimSpace(header.Name) == "" || strings.TrimSpace(header.Value) == "" {
			continue
		}
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", header.Name, header.Value))
	}
	parts := []string{startLine}
	parts = append(parts, headerLines...)
	parts = append(parts, "")
	if strings.TrimSpace(body) != "" {
		parts = append(parts, body)
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func buildHTTPResponsePacket(status int, headers []sharedHeader, body string) string {
	if status == 0 && len(headers) == 0 && strings.TrimSpace(body) == "" {
		return ""
	}
	reason := http.StatusText(status)
	startLine := strings.TrimSpace(fmt.Sprintf("HTTP/1.1 %d %s", maxInt(status, 200), reason))
	headerLines := make([]string, 0, len(headers))
	for _, header := range headers {
		if strings.TrimSpace(header.Name) == "" || strings.TrimSpace(header.Value) == "" {
			continue
		}
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", header.Name, header.Value))
	}
	parts := []string{startLine}
	parts = append(parts, headerLines...)
	parts = append(parts, "")
	if strings.TrimSpace(body) != "" {
		parts = append(parts, body)
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func decodeEvidenceBody(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) > 32768 {
		return ""
	}
	if !base64Like(trimmed) {
		return trimmed
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(trimmed, "\n", ""))
	if err != nil {
		return trimmed
	}
	if !isMostlyReadable(decoded) {
		return ""
	}
	return strings.TrimSpace(string(decoded))
}

func base64Like(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '=' || r == '\n' || r == '\r':
		default:
			return false
		}
	}
	return true
}

func isMostlyReadable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 32 && b <= 126) {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) >= 0.8
}

func selectPacketBody(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func looksLikeHTTPRequest(value string) bool {
	upper := strings.ToUpper(strings.TrimSpace(value))
	for _, prefix := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func looksLikeHTTPResponse(value string) bool {
	upper := strings.ToUpper(strings.TrimSpace(value))
	return strings.HasPrefix(upper, "HTTP/1.0 ") || strings.HasPrefix(upper, "HTTP/1.1 ") || strings.HasPrefix(upper, "HTTP/2 ")
}

func extractPayloadTXID(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	switch value := payload["tx_id"].(type) {
	case string:
		return strings.TrimSpace(value)
	case float64:
		return fmt.Sprintf("%.0f", value)
	case int:
		return fmt.Sprintf("%d", value)
	default:
		return ""
	}
}

func truncatePacketEvidence(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 20000 {
		return trimmed
	}
	return trimmed[:20000] + "\n\n... 已截断，避免页面加载过慢 ..."
}

func nestedObjectValue(root map[string]any, key string, nested string) any {
	if root == nil {
		return nil
	}
	child, _ := root[key].(map[string]any)
	if child == nil {
		return nil
	}
	return child[nested]
}

func summarizeForSnippet(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(trimmed, "\n", "")); err == nil {
		decodedText := strings.TrimSpace(string(decoded))
		if decodedText != "" {
			trimmed = decodedText
		}
	}
	if len(trimmed) > 180 {
		return trimmed[:180] + " ..."
	}
	return trimmed
}

func alertDetailScope(alert shared.Alert) (time.Time, time.Time) {
	window := time.Duration(maxInt(alert.WindowMinutes, 10)) * time.Minute
	if window > 2*time.Hour {
		window = 2 * time.Hour
	}
	if window < 10*time.Minute {
		window = 10 * time.Minute
	}
	since := alert.FirstSeenAt.Add(-window)
	until := alert.LastSeenAt.Add(window)
	return since, until
}

func limitRawEvents(items []shared.RawEvent, limit int) []shared.RawEvent {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitStrings(items []string, limit int) []string {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitFlows(items []shared.Flow, limit int) []shared.Flow {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitTimelineItems(items []shared.AlertTimelineItem, limit int) []shared.AlertTimelineItem {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[len(items)-limit:]
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func (s *Service) canAccessRawAlertItem(ctx context.Context, user shared.User, item shared.RawAlertItem) bool {
	if len(user.AllowedProbeIDs) > 0 && !containsString(user.Permissions, "*") && !contains(user.AllowedProbeIDs, item.ProbeID) {
		return false
	}
	assetIDs, _, err := s.resolveScopeAssets(ctx, user, item.TenantID)
	if err != nil {
		return false
	}
	if len(assetIDs) == 0 {
		return true
	}
	srcAsset, srcOK, err := s.store.FindAssetByIP(ctx, item.TenantID, item.SrcIP)
	if err == nil && srcOK && contains(assetIDs, srcAsset.ID) {
		return true
	}
	dstAsset, dstOK, err := s.store.FindAssetByIP(ctx, item.TenantID, item.DstIP)
	if err == nil && dstOK && contains(assetIDs, dstAsset.ID) {
		return true
	}
	return false
}

func rawAlertItemFromEvent(event shared.RawEvent) shared.RawAlertItem {
	return shared.RawAlertItem{
		ID:           event.ID,
		TenantID:     event.TenantID,
		ProbeID:      event.ProbeID,
		EventTime:    event.EventTime,
		SrcIP:        event.Payload.SrcIP,
		SrcPort:      event.Payload.SrcPort,
		DstIP:        event.Payload.DstIP,
		DstPort:      event.Payload.DstPort,
		Proto:        event.Payload.Proto,
		AppProto:     event.Payload.AppProto,
		FlowID:       event.Payload.FlowID,
		SignatureID:  event.Payload.Alert.SignatureID,
		Signature:    event.Payload.Alert.Signature,
		Category:     event.Payload.Alert.Category,
		Severity:     event.Payload.Alert.Severity,
		AttackResult: pipeline.DeriveAttackResult(event.Payload),
	}
}

func mergeAttackResult(current, next string) string {
	rank := map[string]int{
		"unknown":   0,
		"attempted": 1,
		"failed":    2,
		"success":   3,
	}
	current = strings.ToLower(strings.TrimSpace(current))
	next = strings.ToLower(strings.TrimSpace(next))
	if current == "" {
		current = "unknown"
	}
	if next == "" {
		next = "unknown"
	}
	if rank[next] > rank[current] {
		return next
	}
	return current
}

func strongerAttackResult(current, next string) string {
	return mergeAttackResult(current, next)
}

func normalizeAttackResult(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "success", "failed", "attempted":
		return normalized
	default:
		return "unknown"
	}
}

func topTrend(values map[string]int, limit int) []shared.TrendPoint {
	points := make([]shared.TrendPoint, 0, len(values))
	for key, value := range values {
		points = append(points, shared.TrendPoint{Date: key, Count: value})
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].Count == points[j].Count {
			return points[i].Date > points[j].Date
		}
		return points[i].Count > points[j].Count
	})
	if len(points) > limit {
		points = points[:limit]
	}
	return points
}

func sortAlerts(items []shared.Alert, sortBy, sortOrder string) {
	desc := sortOrder != "asc"
	sort.Slice(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		switch sortBy {
		case "severity":
			if left.Severity == right.Severity {
				if desc {
					return left.LastSeenAt.After(right.LastSeenAt)
				}
				return left.LastSeenAt.Before(right.LastSeenAt)
			}
			if desc {
				return left.Severity > right.Severity
			}
			return left.Severity < right.Severity
		case "risk_score":
			if left.RiskScore == right.RiskScore {
				if desc {
					return left.LastSeenAt.After(right.LastSeenAt)
				}
				return left.LastSeenAt.Before(right.LastSeenAt)
			}
			if desc {
				return left.RiskScore > right.RiskScore
			}
			return left.RiskScore < right.RiskScore
		default:
			if desc {
				return left.LastSeenAt.After(right.LastSeenAt)
			}
			return left.LastSeenAt.Before(right.LastSeenAt)
		}
	})
}

func sortTickets(items []shared.Ticket, sortBy, sortOrder string) {
	desc := sortOrder != "asc"
	sort.Slice(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		switch sortBy {
		case "priority":
			lp := priorityRank(left.Priority)
			rp := priorityRank(right.Priority)
			if lp == rp {
				if desc {
					return left.CreatedAt.After(right.CreatedAt)
				}
				return left.CreatedAt.Before(right.CreatedAt)
			}
			if desc {
				return lp > rp
			}
			return lp < rp
		default:
			if desc {
				return left.CreatedAt.After(right.CreatedAt)
			}
			return left.CreatedAt.Before(right.CreatedAt)
		}
	})
}

func priorityRank(value string) int {
	switch value {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func normalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func paginateAlerts(items []shared.Alert, page, pageSize int) []shared.Alert {
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []shared.Alert{}
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func paginateTickets(items []shared.Ticket, page, pageSize int) []shared.Ticket {
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []shared.Ticket{}
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}
