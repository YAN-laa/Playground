package pipeline

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

type AssetResolver func(tenantID, ip string) (*shared.Asset, error)
type ThreatIntelResolver func(tenantID, value string) ([]shared.ThreatIntel, error)
type SuppressionResolver func(tenantID string) ([]shared.SuppressionRule, error)
type RiskPolicyResolver func(tenantID string) (*shared.RiskPolicy, error)

type Processor struct {
	normalizer          StageNormalizer
	enricher            StageEnricher
	suppressor          StageSuppressor
	scorer              StageScorer
	projector           StageProjector
	aggregationWindow   time.Duration
	assetResolver       AssetResolver
	intelResolver       ThreatIntelResolver
	suppressionResolver SuppressionResolver
	riskPolicyResolver  RiskPolicyResolver
}

type StageContext struct {
	TenantID  string
	ProbeID   string
	Event     shared.SuricataEvent
	EventTime time.Time
	Alert     shared.Alert
}

type AlertProjection struct {
	TenantID    string
	ProbeID     string
	Fingerprint string
	EventTime   time.Time
	Alert       shared.Alert
}

type StageNormalizer interface {
	Normalize(ctx StageContext) (StageContext, bool)
}

type StageEnricher interface {
	Enrich(ctx StageContext, assetResolver AssetResolver, intelResolver ThreatIntelResolver) StageContext
}

type StageSuppressor interface {
	Allow(ctx StageContext, suppressionResolver SuppressionResolver) bool
}

type StageScorer interface {
	Score(ctx StageContext, riskPolicyResolver RiskPolicyResolver) StageContext
}

type StageProjector interface {
	Project(ctx StageContext) AlertProjection
}

func New(aggregationWindow time.Duration) *Processor {
	if aggregationWindow <= 0 {
		aggregationWindow = 30 * time.Minute
	}
	return &Processor{
		normalizer:        defaultNormalizer{},
		enricher:          defaultEnricher{},
		suppressor:        defaultSuppressor{},
		scorer:            defaultScorer{},
		projector:         defaultProjector{},
		aggregationWindow: aggregationWindow,
	}
}

func (p *Processor) SetResolvers(assetResolver AssetResolver, intelResolver ThreatIntelResolver, suppressionResolver SuppressionResolver, riskPolicyResolver RiskPolicyResolver) {
	p.assetResolver = assetResolver
	p.intelResolver = intelResolver
	p.suppressionResolver = suppressionResolver
	p.riskPolicyResolver = riskPolicyResolver
}

func (p *Processor) Process(tenantID, probeID string, event shared.SuricataEvent) (AlertProjection, bool) {
	ctx, ok := p.normalizer.Normalize(StageContext{TenantID: tenantID, ProbeID: probeID, Event: event})
	if !ok {
		return AlertProjection{}, false
	}
	ctx = p.enricher.Enrich(ctx, p.assetResolver, p.intelResolver)
	if !p.suppressor.Allow(ctx, p.suppressionResolver) {
		return AlertProjection{}, false
	}
	ctx = p.scorer.Score(ctx, p.riskPolicyResolver)
	projection := p.projector.Project(ctx)
	projection.Fingerprint = fingerprint(ctx.TenantID, ctx.EventTime, p.aggregationWindow, ctx.Event)
	return projection, true
}

type defaultNormalizer struct{}
type defaultEnricher struct{}
type defaultSuppressor struct{}
type defaultScorer struct{}
type defaultProjector struct{}

func (defaultNormalizer) Normalize(ctx StageContext) (StageContext, bool) {
	ctx.EventTime = parseTime(ctx.Event.Timestamp)
	if ctx.Event.EventType != "alert" || ctx.Event.Alert == nil {
		return StageContext{}, false
	}
	ctx.Alert = shared.Alert{
		TenantID:     ctx.TenantID,
		FirstSeenAt:  ctx.EventTime,
		LastSeenAt:   ctx.EventTime,
		EventCount:   1,
		ProbeIDs:     []string{ctx.ProbeID},
		SrcIP:        ctx.Event.SrcIP,
		DstIP:        ctx.Event.DstIP,
		DstPort:      ctx.Event.DstPort,
		Proto:        ctx.Event.Proto,
		SignatureID:  ctx.Event.Alert.SignatureID,
		Signature:    ctx.Event.Alert.Signature,
		Category:     ctx.Event.Alert.Category,
		Severity:     ctx.Event.Alert.Severity,
		Status:       "new",
		AttackResult: inferAttackResult(ctx.Event),
	}
	return ctx, true
}

func (defaultEnricher) Enrich(ctx StageContext, assetResolver AssetResolver, intelResolver ThreatIntelResolver) StageContext {
	if assetResolver != nil {
		if asset, err := assetResolver(ctx.TenantID, ctx.Event.SrcIP); err == nil && asset != nil {
			ctx.Alert.SourceAssetID = asset.ID
			ctx.Alert.SourceAssetName = asset.Name
		}
		if asset, err := assetResolver(ctx.TenantID, ctx.Event.DstIP); err == nil && asset != nil {
			ctx.Alert.TargetAssetID = asset.ID
			ctx.Alert.TargetAssetName = asset.Name
		}
	}
	if intelResolver != nil {
		tags := make(map[string]struct{})
		hits := make([]string, 0)
		for _, value := range []string{ctx.Event.SrcIP, ctx.Event.DstIP} {
			items, err := intelResolver(ctx.TenantID, value)
			if err != nil {
				continue
			}
			for _, item := range items {
				hits = append(hits, fmt.Sprintf("%s:%s", item.Type, item.Value))
				for _, tag := range item.Tags {
					tags[tag] = struct{}{}
				}
			}
		}
		ctx.Alert.ThreatIntelHits = uniqueSortedStrings(hits)
		ctx.Alert.ThreatIntelTags = mapKeys(tags)
	}
	return ctx
}

func (defaultSuppressor) Allow(ctx StageContext, suppressionResolver SuppressionResolver) bool {
	if ctx.Event.Alert == nil {
		return false
	}
	if suppressionResolver == nil {
		return true
	}
	rules, err := suppressionResolver(ctx.TenantID)
	if err != nil {
		return true
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if ruleMatches(rule, ctx.Event) {
			return false
		}
	}
	return true
}

func (defaultScorer) Score(ctx StageContext, riskPolicyResolver RiskPolicyResolver) StageContext {
	policy := defaultRiskPolicy()
	if riskPolicyResolver != nil {
		if value, err := riskPolicyResolver(ctx.TenantID); err == nil && value != nil {
			policy = *value
		}
	}
	ctx.Alert.RiskScore = riskScoreWithPolicy(ctx.Event.Alert.Severity, policy)
	if len(ctx.Alert.ThreatIntelHits) > 0 {
		ctx.Alert.RiskScore += policy.IntelHitBonus
	}
	if ctx.Alert.TargetAssetID != "" {
		ctx.Alert.RiskScore += policy.CriticalAssetBonus
	}
	if ctx.Alert.RiskScore > 100 {
		ctx.Alert.RiskScore = 100
	}
	return ctx
}

func (defaultProjector) Project(ctx StageContext) AlertProjection {
	return AlertProjection{
		TenantID:  ctx.TenantID,
		ProbeID:   ctx.ProbeID,
		EventTime: ctx.EventTime,
		Alert:     ctx.Alert,
	}
}

func ruleMatches(rule shared.SuppressionRule, event shared.SuricataEvent) bool {
	if rule.SrcIP != "" && rule.SrcIP != event.SrcIP {
		return false
	}
	if rule.DstIP != "" && rule.DstIP != event.DstIP {
		return false
	}
	if rule.SignatureID != 0 {
		if event.Alert == nil || rule.SignatureID != event.Alert.SignatureID {
			return false
		}
	}
	if rule.Signature != "" {
		if event.Alert == nil || rule.Signature != event.Alert.Signature {
			return false
		}
	}
	return true
}

func defaultRiskPolicy() shared.RiskPolicy {
	return shared.RiskPolicy{
		Severity1Score:     90,
		Severity2Score:     75,
		Severity3Score:     60,
		DefaultScore:       40,
		IntelHitBonus:      10,
		CriticalAssetBonus: 10,
	}
}

func riskScoreWithPolicy(severity int, policy shared.RiskPolicy) int {
	switch severity {
	case 1:
		return policy.Severity1Score
	case 2:
		return policy.Severity2Score
	case 3:
		return policy.Severity3Score
	default:
		return policy.DefaultScore
	}
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok || value == "" {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func mapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func inferAttackResult(event shared.SuricataEvent) string {
	payload := event.Payload
	httpPayload, _ := payload["http"].(map[string]any)
	appProto := strings.ToLower(firstString(payload["app_proto"], event.AppProto, payload["proto"]))
	if appProto != "http" && len(httpPayload) == 0 {
		return "unknown"
	}

	status := firstInt(
		nestedValue(httpPayload, "status"),
		payload["status"],
		payload["http_status"],
	)
	responseBody := strings.ToLower(decodeBody(firstString(
		payload["http_response_body"],
		payload["response_body"],
		nestedValue(httpPayload, "http_response_body"),
	)))

	switch {
	case status >= 200 && status < 300:
		return "success"
	case status >= 300 && status < 400:
		return "attempted"
	case status >= 400:
		return "failed"
	}

	switch {
	case containsAny(responseBody, []string{`"ok":true`, `"ok": true`, `"success":true`, `"success": true`, `"created":true`}):
		return "success"
	case containsAny(responseBody, []string{"404 not found", "not found", "forbidden", "unauthorized", "denied", `"error"`, "failed"}):
		return "failed"
	}

	if firstString(
		nestedValue(httpPayload, "http_method"),
		payload["http_method"],
		payload["method"],
		nestedValue(httpPayload, "url"),
		payload["url"],
		payload["payload_printable"],
	) != "" {
		return "attempted"
	}

	return "unknown"
}

func firstString(values ...any) string {
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

func firstInt(values ...any) int {
	for _, value := range values {
		switch typed := value.(type) {
		case int:
			return typed
		case int32:
			return int(typed)
		case int64:
			return int(typed)
		case float64:
			return int(typed)
		case json.Number:
			if parsed, err := strconv.Atoi(string(typed)); err == nil {
				return parsed
			}
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func nestedValue(values map[string]any, key string) any {
	if len(values) == 0 {
		return nil
	}
	return values[key]
}

func decodeBody(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
		return string(decoded)
	}
	return trimmed
}

func containsAny(value string, items []string) bool {
	for _, item := range items {
		if item != "" && strings.Contains(value, item) {
			return true
		}
	}
	return false
}

func DeriveAttackResult(event shared.SuricataEvent) string {
	return inferAttackResult(event)
}
