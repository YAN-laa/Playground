package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

type OpenSearchConfig struct {
	BaseURL      string
	Username     string
	Password     string
	AlertIndex   string
	FlowIndex    string
	Timeout      time.Duration
	RetryMax     int
	RetryBackoff time.Duration
	DLQFile      string
}

type OpenSearchEngine struct {
	baseURL    string
	username   string
	password   string
	alertIndex string
	flowIndex  string
	client     *http.Client
	retryMax   int
	backoff    time.Duration
	dlqFile    string
}

func NewOpenSearchEngine(cfg OpenSearchConfig) *OpenSearchEngine {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &OpenSearchEngine{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		username:   cfg.Username,
		password:   cfg.Password,
		alertIndex: defaultString(cfg.AlertIndex, "ndr-alerts"),
		flowIndex:  defaultString(cfg.FlowIndex, "ndr-flows"),
		client:     &http.Client{Timeout: timeout},
		retryMax:   max(cfg.RetryMax, 0),
		backoff:    positiveDuration(cfg.RetryBackoff, 500*time.Millisecond),
		dlqFile:    cfg.DLQFile,
	}
}

func (e *OpenSearchEngine) SearchAlerts(ctx context.Context, query shared.AlertQuery) (shared.AlertListResponse, error) {
	page, pageSize := normalizePage(query.Page, query.PageSize)
	body := map[string]any{
		"size": normalizeLimit(pageSize, 100),
		"from": max((page-1)*normalizeLimit(pageSize, 100), 0),
		"sort": []map[string]any{{defaultString(query.SortBy, "last_seen_at"): map[string]string{"order": defaultString(query.SortOrder, "desc")}}},
		"query": map[string]any{
			"bool": map[string]any{
				"filter": buildAlertFilters(query),
			},
		},
	}
	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source shared.Alert `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := e.search(ctx, e.alertIndex, body, &result); err != nil {
		return shared.AlertListResponse{}, err
	}
	out := make([]shared.Alert, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		out = append(out, hit.Source)
	}
	return shared.AlertListResponse{
		Items:    out,
		Total:    result.Hits.Total.Value,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

func (e *OpenSearchEngine) SearchFlows(ctx context.Context, query shared.FlowQuery) ([]shared.Flow, error) {
	body := map[string]any{
		"size": 200,
		"sort": []map[string]any{{"seen_at": map[string]string{"order": "desc"}}},
		"query": map[string]any{
			"bool": map[string]any{
				"filter": buildFlowFilters(query),
			},
		},
	}
	var result struct {
		Hits struct {
			Hits []struct {
				Source shared.Flow `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := e.search(ctx, e.flowIndex, body, &result); err != nil {
		return nil, err
	}
	out := make([]shared.Flow, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		out = append(out, hit.Source)
	}
	return out, nil
}

func (e *OpenSearchEngine) EnsureReady(ctx context.Context) error {
	if err := e.ensureIndex(ctx, e.alertIndex, alertIndexMapping()); err != nil {
		return err
	}
	return e.ensureIndex(ctx, e.flowIndex, flowIndexMapping())
}

func (e *OpenSearchEngine) IndexAlert(ctx context.Context, alert shared.Alert) error {
	return e.indexWithRetry(ctx, e.alertIndex, alert.ID, alert)
}

func (e *OpenSearchEngine) IndexFlow(ctx context.Context, flow shared.Flow) error {
	return e.indexWithRetry(ctx, e.flowIndex, flow.ID, flow)
}

func (e *OpenSearchEngine) IndexAlerts(ctx context.Context, alerts []shared.Alert) error {
	docs := make([]bulkDocument, 0, len(alerts))
	for _, alert := range alerts {
		docs = append(docs, bulkDocument{ID: alert.ID, Body: alert})
	}
	return e.bulkIndexWithRetry(ctx, e.alertIndex, docs)
}

func (e *OpenSearchEngine) IndexFlows(ctx context.Context, flows []shared.Flow) error {
	docs := make([]bulkDocument, 0, len(flows))
	for _, flow := range flows {
		docs = append(docs, bulkDocument{ID: flow.ID, Body: flow})
	}
	return e.bulkIndexWithRetry(ctx, e.flowIndex, docs)
}

func (e *OpenSearchEngine) search(ctx context.Context, index string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/"+index+"/_search", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	e.applyAuth(req)
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("opensearch search failed: status=%d body=%s", resp.StatusCode, string(data))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (e *OpenSearchEngine) index(ctx context.Context, index, id string, doc any) error {
	payload, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, e.baseURL+"/"+index+"/_doc/"+id, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	e.applyAuth(req)
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("opensearch index failed: status=%d body=%s", resp.StatusCode, string(data))
	}
	return nil
}

type bulkDocument struct {
	ID   string
	Body any
}

func (e *OpenSearchEngine) bulkIndex(ctx context.Context, index string, docs []bulkDocument) error {
	if len(docs) == 0 {
		return nil
	}
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	for _, doc := range docs {
		if err := encoder.Encode(map[string]any{"index": map[string]any{"_index": index, "_id": doc.ID}}); err != nil {
			return err
		}
		if err := encoder.Encode(doc.Body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/_bulk", &payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	e.applyAuth(req)
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("opensearch bulk failed: status=%d body=%s", resp.StatusCode, string(data))
	}
	var result struct {
		Errors bool `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if result.Errors {
		return fmt.Errorf("opensearch bulk failed: partial errors returned")
	}
	return nil
}

func (e *OpenSearchEngine) indexWithRetry(ctx context.Context, index, id string, doc any) error {
	var err error
	for attempt := 0; attempt <= e.retryMax; attempt++ {
		err = e.index(ctx, index, id, doc)
		if err == nil {
			return nil
		}
		if attempt < e.retryMax {
			time.Sleep(e.backoff)
		}
	}
	_ = e.writeDLQ("single", index, []bulkDocument{{ID: id, Body: doc}}, err)
	return err
}

func (e *OpenSearchEngine) bulkIndexWithRetry(ctx context.Context, index string, docs []bulkDocument) error {
	var err error
	for attempt := 0; attempt <= e.retryMax; attempt++ {
		err = e.bulkIndex(ctx, index, docs)
		if err == nil {
			return nil
		}
		if attempt < e.retryMax {
			time.Sleep(e.backoff)
		}
	}
	_ = e.writeDLQ("bulk", index, docs, err)
	return err
}

func (e *OpenSearchEngine) writeDLQ(mode, index string, docs []bulkDocument, cause error) error {
	if e.dlqFile == "" || len(docs) == 0 {
		return nil
	}
	file, err := os.OpenFile(e.dlqFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, doc := range docs {
		entry := map[string]any{
			"ts":    time.Now().UTC().Format(time.RFC3339),
			"mode":  mode,
			"index": index,
			"id":    doc.ID,
			"error": errorString(cause),
			"body":  doc.Body,
		}
		if err := encoder.Encode(entry); err != nil {
			return err
		}
	}
	return nil
}

func (e *OpenSearchEngine) ensureIndex(ctx context.Context, index string, mapping any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, e.baseURL+"/"+index, nil)
	if err != nil {
		return err
	}
	e.applyAuth(req)
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("opensearch head index failed: index=%s status=%d", index, resp.StatusCode)
	}
	payload, err := json.Marshal(mapping)
	if err != nil {
		return err
	}
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPut, e.baseURL+"/"+index, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	createReq.Header.Set("Content-Type", "application/json")
	e.applyAuth(createReq)
	createResp, err := e.client.Do(createReq)
	if err != nil {
		return err
	}
	defer createResp.Body.Close()
	if createResp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(createResp.Body, 4096))
		return fmt.Errorf("opensearch create index failed: index=%s status=%d body=%s", index, createResp.StatusCode, string(data))
	}
	return nil
}

func (e *OpenSearchEngine) applyAuth(req *http.Request) {
	if e.username != "" {
		req.SetBasicAuth(e.username, e.password)
	}
}

func buildAlertFilters(query shared.AlertQuery) []map[string]any {
	filters := []map[string]any{
		{"term": map[string]any{"tenant_id.keyword": query.TenantID}},
	}
	if query.Status != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"status.keyword": query.Status}})
	}
	if query.SrcIP != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"src_ip.keyword": query.SrcIP}})
	}
	if query.DstIP != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"dst_ip.keyword": query.DstIP}})
	}
	if query.Signature != "" {
		filters = append(filters, map[string]any{"match": map[string]any{"signature": query.Signature}})
	}
	if query.Assignee != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"assignee.keyword": query.Assignee}})
	}
	if query.Severity > 0 {
		filters = append(filters, map[string]any{"term": map[string]any{"severity": query.Severity}})
	}
	if query.AttackResult != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"attack_result.keyword": query.AttackResult}})
	}
	if !query.Since.IsZero() {
		filters = append(filters, map[string]any{"range": map[string]any{"last_seen_at": map[string]any{"gte": query.Since.Format(time.RFC3339)}}})
	}
	if query.MinProbeCount > 0 || query.MaxProbeCount > 0 {
		rangeBody := map[string]any{}
		if query.MinProbeCount > 0 {
			rangeBody["gte"] = query.MinProbeCount
		}
		if query.MaxProbeCount > 0 {
			rangeBody["lte"] = query.MaxProbeCount
		}
		filters = append(filters, map[string]any{"range": map[string]any{"probe_count": rangeBody}})
	}
	if query.MinWindowMins > 0 || query.MaxWindowMins > 0 {
		rangeBody := map[string]any{}
		if query.MinWindowMins > 0 {
			rangeBody["gte"] = query.MinWindowMins
		}
		if query.MaxWindowMins > 0 {
			rangeBody["lte"] = query.MaxWindowMins
		}
		filters = append(filters, map[string]any{"range": map[string]any{"window_minutes": rangeBody}})
	}
	if len(query.AllowedAssetIDs) > 0 {
		should := make([]map[string]any, 0, len(query.AllowedAssetIDs)*2)
		for _, id := range query.AllowedAssetIDs {
			should = append(should,
				map[string]any{"term": map[string]any{"source_asset_id.keyword": id}},
				map[string]any{"term": map[string]any{"target_asset_id.keyword": id}},
			)
		}
		filters = append(filters, map[string]any{
			"bool": map[string]any{
				"should":               should,
				"minimum_should_match": 1,
			},
		})
	}
	return filters
}

func buildFlowFilters(query shared.FlowQuery) []map[string]any {
	filters := []map[string]any{
		{"term": map[string]any{"tenant_id.keyword": query.TenantID}},
	}
	if query.SrcIP != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"src_ip.keyword": query.SrcIP}})
	}
	if query.DstIP != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"dst_ip.keyword": query.DstIP}})
	}
	if query.AppProto != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"app_proto.keyword": query.AppProto}})
	}
	if !query.Since.IsZero() {
		filters = append(filters, map[string]any{"range": map[string]any{"seen_at": map[string]any{"gte": query.Since.Format(time.RFC3339)}}})
	}
	if len(query.AllowedIPs) > 0 {
		should := make([]map[string]any, 0, len(query.AllowedIPs)*2)
		for _, ip := range query.AllowedIPs {
			should = append(should,
				map[string]any{"term": map[string]any{"src_ip.keyword": ip}},
				map[string]any{"term": map[string]any{"dst_ip.keyword": ip}},
			)
		}
		filters = append(filters, map[string]any{
			"bool": map[string]any{
				"should":               should,
				"minimum_should_match": 1,
			},
		})
	}
	return filters
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func normalizeLimit(limit, fallback int) int {
	if limit <= 0 {
		return fallback
	}
	if limit > 500 {
		return 500
	}
	return limit
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func positiveDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func alertIndexMapping() map[string]any {
	return map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"id":             map[string]any{"type": "keyword"},
				"tenant_id":      map[string]any{"type": "keyword"},
				"fingerprint":    map[string]any{"type": "keyword"},
				"first_seen_at":  map[string]any{"type": "date"},
				"last_seen_at":   map[string]any{"type": "date"},
				"probe_ids":      map[string]any{"type": "keyword"},
				"probe_count":    map[string]any{"type": "integer"},
				"src_ip":         map[string]any{"type": "ip"},
				"dst_ip":         map[string]any{"type": "ip"},
				"dst_port":       map[string]any{"type": "integer"},
				"proto":          map[string]any{"type": "keyword"},
				"signature_id":   map[string]any{"type": "integer"},
				"signature":      map[string]any{"type": "text", "fields": map[string]any{"keyword": map[string]any{"type": "keyword"}}},
				"category":       map[string]any{"type": "keyword"},
				"severity":       map[string]any{"type": "integer"},
				"risk_score":     map[string]any{"type": "integer"},
				"attack_result":  map[string]any{"type": "keyword"},
				"window_minutes": map[string]any{"type": "integer"},
				"status":         map[string]any{"type": "keyword"},
				"assignee":       map[string]any{"type": "keyword"},
			},
		},
	}
}

func flowIndexMapping() map[string]any {
	return map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"id":        map[string]any{"type": "keyword"},
				"tenant_id": map[string]any{"type": "keyword"},
				"probe_id":  map[string]any{"type": "keyword"},
				"flow_id":   map[string]any{"type": "keyword"},
				"src_ip":    map[string]any{"type": "ip"},
				"src_port":  map[string]any{"type": "integer"},
				"dst_ip":    map[string]any{"type": "ip"},
				"dst_port":  map[string]any{"type": "integer"},
				"proto":     map[string]any{"type": "keyword"},
				"app_proto": map[string]any{"type": "keyword"},
				"seen_at":   map[string]any{"type": "date"},
			},
		},
	}
}
