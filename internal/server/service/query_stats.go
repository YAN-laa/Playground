package service

import (
	"sync"
	"time"

	"github.com/yan/ndr-platform/internal/shared"
)

type queryStats struct {
	mu            sync.Mutex
	items         []shared.QueryStat
	maxItems      int
	slowThreshold time.Duration
}

func newQueryStats(maxItems int, slowThreshold time.Duration) *queryStats {
	if maxItems <= 0 {
		maxItems = 200
	}
	if slowThreshold <= 0 {
		slowThreshold = 1500 * time.Millisecond
	}
	return &queryStats{
		items:         make([]shared.QueryStat, 0, maxItems),
		maxItems:      maxItems,
		slowThreshold: slowThreshold,
	}
}

func (q *queryStats) record(stat shared.QueryStat) shared.QueryStat {
	stat.Slow = time.Duration(stat.DurationMS)*time.Millisecond >= q.slowThreshold
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append([]shared.QueryStat{stat}, q.items...)
	if len(q.items) > q.maxItems {
		q.items = q.items[:q.maxItems]
	}
	return stat
}

func (q *queryStats) list() []shared.QueryStat {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]shared.QueryStat, len(q.items))
	copy(out, q.items)
	return out
}
