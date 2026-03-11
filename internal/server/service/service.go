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
		pipeline:            pipeline.New(),
		queries:             newQueryStats(200, slowQueryThreshold),
		exportDir:           exportDir,
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
	if svc.exportTTL <= 0 {
		svc.exportTTL = 24 * time.Hour
	}
	_ = os.MkdirAll(svc.exportDir, 0o755)
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
				return base
			}
			updated := *existing
			updated.LastSeenAt = projection.EventTime
			updated.EventCount++
			if !contains(updated.ProbeIDs, batch.ProbeID) {
				updated.ProbeIDs = append(updated.ProbeIDs, batch.ProbeID)
			}
			updated.RiskScore = projection.Alert.RiskScore
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
	rawEvents, err := s.store.ListRawEvents(ctx, alert.TenantID, alert.FirstSeenAt.Add(-24*time.Hour), alert.LastSeenAt.Add(24*time.Hour), alert.ProbeIDs)
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
	flows, err := s.store.ListFlowsByIDs(ctx, alert.TenantID, flowIDs)
	if err != nil {
		return shared.AlertDetail{}, false, err
	}
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
	return shared.AlertDetail{
		Alert:         alert,
		Events:        events,
		ContextEvents: contextEvents,
		Flows:         flows,
		Tickets:       tickets,
		Activities:    activities,
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

func (s *Service) CreateUser(ctx context.Context, req shared.CreateUserRequest, operatorID string) (shared.User, error) {
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

func (s *Service) ListUpgradePackages(ctx context.Context, tenantID string) ([]shared.UpgradePackage, error) {
	return s.store.ListUpgradePackages(ctx, tenantID)
}

func (s *Service) ListProbeMetrics(ctx context.Context, query shared.ProbeMetricQuery) ([]shared.ProbeMetric, error) {
	return s.store.ListProbeMetrics(ctx, query)
}

func (s *Service) CreateAsset(ctx context.Context, req shared.CreateAssetRequest, operatorID string) (shared.Asset, error) {
	asset := shared.Asset{
		ID:              s.nextID("asset"),
		TenantID:        req.TenantID,
		Name:            req.Name,
		IP:              req.IP,
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

func (s *Service) runExportTask(task shared.ExportTask, req shared.ExportTaskRequest) {
	ctx := context.Background()
	task.Status = "running"
	_, _ = s.store.UpdateExportTask(ctx, task)

	filePath := filepath.Join(s.exportDir, task.ID+"."+task.Format)
	var payload any
	switch task.ResourceType {
	case "alerts":
		query := req.AlertQuery
		query.TenantID = task.TenantID
		query.Page = 1
		query.PageSize = 1000
		result, err := s.search.SearchAlerts(ctx, query)
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
		payload = items
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
		return fmt.Sprintf("alerts tenant=%s src=%s dst=%s signature=%s status=%s", req.TenantID, req.AlertQuery.SrcIP, req.AlertQuery.DstIP, req.AlertQuery.Signature, req.AlertQuery.Status)
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
		if err := writer.Write([]string{"id", "tenant_id", "signature", "src_ip", "dst_ip", "dst_port", "severity", "risk_score", "status", "assignee", "first_seen_at", "last_seen_at", "event_count"}); err != nil {
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
	adminRole, _, err := s.store.FindUser(ctx, "demo-tenant", "admin")
	if err == nil && adminRole.ID != "" {
		return
	}
	role, err := s.store.CreateRole(ctx, shared.Role{
		ID:          s.nextID("role"),
		TenantID:    "demo-tenant",
		Name:        "admin",
		Description: "Default administrator role",
		Permissions: []string{"*"},
		CreatedAt:   time.Now().UTC(),
	})
	if err != nil {
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
		Roles:       []string{role.Name},
		CreatedAt:   time.Now().UTC(),
	})
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
