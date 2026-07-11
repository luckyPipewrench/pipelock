//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard/runtimesnapshot"
)

type BudgetSnapshotFreshness struct {
	ProducedAt time.Time
	Age        time.Duration
	Stale      bool
}

type budgetFreshnessSource interface {
	BudgetFreshness() (BudgetSnapshotFreshness, bool)
}

type budgetSourceUnavailable interface {
	BudgetSourceUnavailable() bool
}

type snapshotBudgetSource struct {
	path   string
	maxAge time.Duration
	now    func() time.Time

	mu        sync.Mutex
	freshness BudgetSnapshotFreshness
	hasFresh  bool
}

type snapshotBudgetUnavailableError struct {
	err error
}

func (e snapshotBudgetUnavailableError) Error() string {
	return "runtime snapshot budget source unavailable"
}

func (e snapshotBudgetUnavailableError) Unwrap() error {
	return e.err
}

func (e snapshotBudgetUnavailableError) BudgetSourceUnavailable() bool {
	return true
}

func NewSnapshotBudgetSource(path string, maxAge time.Duration) BudgetDataSource {
	if path == "" {
		return nil
	}
	return &snapshotBudgetSource{path: path, maxAge: maxAge, now: time.Now}
}

func (s *snapshotBudgetSource) AllAgentBudgets(_ context.Context, limit int) ([]AgentBudgetView, error) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	snap, fresh, err := runtimesnapshot.Read(s.path, s.maxAge, now())
	s.storeFreshness(fresh)
	if err != nil {
		return nil, snapshotBudgetUnavailableError{err: err}
	}
	rows := snap.Budgets
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]AgentBudgetView, 0, len(rows))
	for _, row := range rows {
		out = append(out, AgentBudgetView{
			Agent:             row.Agent,
			ForwardConfigured: true,
			RequestCount:      row.RequestCount,
			ByteCount:         row.ByteCount,
			UniqueDomainCount: row.UniqueDomainCount,
			WindowStart:       row.WindowStart,
			MaxRequests:       row.MaxRequests,
			MaxBytes:          row.MaxBytes,
			MaxUniqueDomains:  row.MaxUniqueDomains,
			WindowMinutes:     row.WindowMinutes,
		})
	}
	return out, nil
}

func (s *snapshotBudgetSource) BudgetFreshness() (BudgetSnapshotFreshness, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.freshness, s.hasFresh
}

func (s *snapshotBudgetSource) storeFreshness(fresh runtimesnapshot.Freshness) {
	if fresh.ProducedAt.IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.freshness = BudgetSnapshotFreshness{
		ProducedAt: fresh.ProducedAt,
		Age:        fresh.Age,
		Stale:      fresh.Stale,
	}
	s.hasFresh = true
}

func budgetUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var unavailable budgetSourceUnavailable
	if errors.As(err, &unavailable) {
		return unavailable.BudgetSourceUnavailable()
	}
	return false
}
