//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"fmt"
	"sort"
	"time"
)

const (
	budgetCompletenessClaim    = "mediated per-agent budget consumption as tracked by this Pipelock process"
	budgetCompletenessNonClaim = "does not prove consumption outside this process, before the current window, or on transports without budget enforcement"
	budgetUnlimited            = "unlimited"
	budgetEmptyDash            = "-"
	budgetAgentLimit           = 500
)

// BudgetDataSource is the dashboard-local read seam for per-agent budget
// consumption. Implementations MUST be read-only: the budgets route has no
// write or control authority. It surfaces the forward-proxy
// request/byte/domain budget supplied by the runtime snapshot.
type BudgetDataSource interface {
	// AllAgentBudgets returns budget views for configured agents. Limit is a
	// hard maximum requested by the dashboard; implementations should apply it
	// at the backing query boundary, preferably after deterministic agent-name
	// ordering. The caller still applies defensive sorting, truncation, and RBAC
	// redaction.
	AllAgentBudgets(ctx context.Context, limit int) ([]AgentBudgetView, error)
}

// AgentBudgetView is the dashboard-local per-agent budget row. It intentionally
// carries only fields rendered by budgets.tmpl.html.
type AgentBudgetView struct {
	Agent string

	// Forward-proxy budget (request/byte/unique-domain, rolling window).
	ForwardConfigured bool
	RequestCount      int
	ByteCount         int64
	UniqueDomainCount int
	WindowStart       time.Time
	MaxRequests       int
	MaxBytes          int64
	MaxUniqueDomains  int
	WindowMinutes     int
}

// BudgetsOverview is the rendered budgets page.
type BudgetsOverview struct {
	Nav                  NavContext
	SourceConfigured     bool
	SourceUnavailable    bool
	Claim                string
	NonClaim             string
	RawAllowed           bool
	Agents               []AgentBudgetView
	Truncated            bool
	SnapshotFreshness    BudgetSnapshotFreshness
	HasSnapshotFreshness bool
}

// Budgets builds the per-agent budget overview. It nil-degrades to an empty,
// source-not-configured page when no BudgetSource is wired. Session identifiers
// are redacted unless the request is authorized for the raw view.
func (m *ReadModel) Budgets(ctx context.Context, rawAllowed bool) (BudgetsOverview, error) {
	overview := BudgetsOverview{
		SourceConfigured: m.budgetSource != nil,
		Claim:            budgetCompletenessClaim,
		NonClaim:         budgetCompletenessNonClaim,
		RawAllowed:       rawAllowed,
	}
	if m.budgetSource == nil {
		return overview, nil
	}
	agents, err := m.budgetSource.AllAgentBudgets(ctx, budgetAgentLimit+1)
	if err != nil {
		if budgetUnavailable(err) {
			overview.SourceUnavailable = true
			overview.SnapshotFreshness, overview.HasSnapshotFreshness = budgetFreshness(m.budgetSource)
			return overview, nil
		}
		return BudgetsOverview{}, fmt.Errorf("list agent budgets: %w", err)
	}
	overview.SnapshotFreshness, overview.HasSnapshotFreshness = budgetFreshness(m.budgetSource)
	sort.Slice(agents, func(i, j int) bool { return agents[i].Agent < agents[j].Agent })
	if len(agents) > budgetAgentLimit {
		agents = agents[:budgetAgentLimit]
		overview.Truncated = true
	}
	overview.Agents = agents
	return overview, nil
}

func budgetFreshness(source BudgetDataSource) (BudgetSnapshotFreshness, bool) {
	freshSource, ok := source.(budgetFreshnessSource)
	if !ok {
		return BudgetSnapshotFreshness{}, false
	}
	return freshSource.BudgetFreshness()
}

// --- display helpers (used by budgets.tmpl.html) ---

func consumedOfLimit(consumed int, limit int) string {
	return consumedOfLimit64(int64(consumed), int64(limit))
}

func consumedOfLimit64(consumed int64, limit int64) string {
	if limit <= 0 {
		return fmt.Sprintf("%d / %s", consumed, budgetUnlimited)
	}
	return fmt.Sprintf("%d / %d", consumed, limit)
}

func (a AgentBudgetView) RequestsDisplay() string {
	return consumedOfLimit(a.RequestCount, a.MaxRequests)
}

func (a AgentBudgetView) BytesDisplay() string {
	return consumedOfLimit64(a.ByteCount, a.MaxBytes)
}

func (a AgentBudgetView) DomainsDisplay() string {
	return consumedOfLimit(a.UniqueDomainCount, a.MaxUniqueDomains)
}

func (a AgentBudgetView) WindowDisplay() string {
	if a.WindowMinutes <= 0 {
		return "no window (cumulative)"
	}
	return fmt.Sprintf("%d min rolling", a.WindowMinutes)
}

func (a AgentBudgetView) WindowStartDisplay() string {
	return displayBudgetTime(a.WindowStart)
}

func displayBudgetTime(value time.Time) string {
	if value.IsZero() {
		return budgetEmptyDash
	}
	return value.UTC().Format(time.RFC3339)
}

func (b BudgetSnapshotFreshness) ProducedAtDisplay() string {
	return displayBudgetTime(b.ProducedAt)
}

func (b BudgetSnapshotFreshness) AgeDisplay() string {
	if b.Age < 0 {
		return budgetEmptyDash
	}
	return b.Age.Round(time.Second).String()
}
