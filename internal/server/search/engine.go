package search

import (
	"context"
	"sort"

	"github.com/yan/ndr-platform/internal/server/store"
	"github.com/yan/ndr-platform/internal/shared"
)

type Engine interface {
	SearchAlerts(ctx context.Context, query shared.AlertQuery) (shared.AlertListResponse, error)
	SearchFlows(ctx context.Context, query shared.FlowQuery) ([]shared.Flow, error)
}

type Indexer interface {
	IndexAlert(ctx context.Context, alert shared.Alert) error
	IndexFlow(ctx context.Context, flow shared.Flow) error
}

type BatchIndexer interface {
	IndexAlerts(ctx context.Context, alerts []shared.Alert) error
	IndexFlows(ctx context.Context, flows []shared.Flow) error
}

type Initializer interface {
	EnsureReady(ctx context.Context) error
}

type LocalEngine struct {
	store store.Repository
}

func NewLocalEngine(repo store.Repository) *LocalEngine {
	return &LocalEngine{store: repo}
}

func (e *LocalEngine) SearchAlerts(ctx context.Context, query shared.AlertQuery) (shared.AlertListResponse, error) {
	items, err := e.store.ListAlerts(ctx, query)
	if err != nil {
		return shared.AlertListResponse{}, err
	}
	if len(query.AllowedAssetIDs) > 0 {
		allowed := make(map[string]struct{}, len(query.AllowedAssetIDs))
		for _, id := range query.AllowedAssetIDs {
			allowed[id] = struct{}{}
		}
		filtered := make([]shared.Alert, 0, len(items))
		for _, item := range items {
			if _, ok := allowed[item.SourceAssetID]; ok {
				filtered = append(filtered, item)
				continue
			}
			if _, ok := allowed[item.TargetAssetID]; ok {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	sortAlerts(items, query.SortBy, query.SortOrder)
	page, pageSize := normalizePage(query.Page, query.PageSize)
	return shared.AlertListResponse{
		Items:    paginateAlerts(items, page, pageSize),
		Total:    len(items),
		Page:     page,
		PageSize: pageSize,
	}, nil
}

func (e *LocalEngine) SearchFlows(ctx context.Context, query shared.FlowQuery) ([]shared.Flow, error) {
	items, err := e.store.ListFlows(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(query.AllowedIPs) == 0 {
		return items, nil
	}
	allowed := make(map[string]struct{}, len(query.AllowedIPs))
	for _, ip := range query.AllowedIPs {
		allowed[ip] = struct{}{}
	}
	filtered := make([]shared.Flow, 0, len(items))
	for _, item := range items {
		if _, ok := allowed[item.SrcIP]; ok {
			filtered = append(filtered, item)
			continue
		}
		if _, ok := allowed[item.DstIP]; ok {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

type NoopIndexer struct{}

func (n NoopIndexer) IndexAlert(context.Context, shared.Alert) error { return nil }

func (n NoopIndexer) IndexFlow(context.Context, shared.Flow) error { return nil }

func sortAlerts(items []shared.Alert, sortBy, sortOrder string) {
	desc := sortOrder != "asc"
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]
		var less bool
		switch sortBy {
		case "severity":
			less = left.Severity < right.Severity
		case "risk_score":
			less = left.RiskScore < right.RiskScore
		default:
			less = left.LastSeenAt.Before(right.LastSeenAt)
		}
		if desc {
			return !less
		}
		return less
	})
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

func normalizePage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 200 {
		pageSize = 200
	}
	return page, pageSize
}
