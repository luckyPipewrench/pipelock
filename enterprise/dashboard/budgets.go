//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	budgetCompletenessClaim    = "mediated per-agent budget consumption as tracked by this Pipelock process"
	budgetCompletenessNonClaim = "does not prove consumption outside this process, before the current window, or on transports without budget enforcement"
	budgetUnlimited            = "unlimited"
	budgetEmptyDash            = "-"
	budgetRedacted             = "redacted"
	budgetAgentLimit           = 500
	budgetSessionLimit         = 100
)

// BudgetDataSource is the dashboard-local read seam for per-agent budget
// consumption. Implementations MUST be read-only: the budgets route has no
// write or control authority. It surfaces two independent budget systems per
// agent: the forward-proxy request/byte/domain budget and the MCP
// denial-of-wallet (tool-call/concurrency) budget aggregated across the
// agent's live sessions.
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

	// MCP denial-of-wallet budget, aggregated across the agent's live sessions.
	// Limits are per session (each session enforces independently); the
	// consumption counters are summed across active sessions.
	DoWConfigured          bool
	ActiveSessions         int
	TotalToolCalls         int
	Inflight               int
	MaxToolCallsPerSession int
	MaxConcurrentToolCalls int
	MaxWallClockMinutes    int
	Sessions               []AgentBudgetSessionView
	SessionsTruncated      bool
}

// AgentBudgetSessionView is one live MCP session's DoW consumption.
type AgentBudgetSessionView struct {
	SessionID      string
	TotalToolCalls int
	Inflight       int
	StartedAt      time.Time
}

// BudgetsOverview is the rendered budgets page.
type BudgetsOverview struct {
	SourceConfigured bool
	Claim            string
	NonClaim         string
	RawAllowed       bool
	Agents           []AgentBudgetView
	Truncated        bool
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
		return BudgetsOverview{}, fmt.Errorf("list agent budgets: %w", err)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Agent < agents[j].Agent })
	if len(agents) > budgetAgentLimit {
		agents = agents[:budgetAgentLimit]
		overview.Truncated = true
	}
	agents = limitBudgetSessions(agents)
	if !rawAllowed {
		agents = redactAgentBudgets(agents)
	}
	overview.Agents = agents
	return overview, nil
}

func limitBudgetSessions(in []AgentBudgetView) []AgentBudgetView {
	out := make([]AgentBudgetView, len(in))
	for i, a := range in {
		if len(a.Sessions) > budgetSessionLimit {
			a.Sessions = a.Sessions[:budgetSessionLimit]
			a.SessionsTruncated = true
		}
		out[i] = a
	}
	return out
}

// redactAgentBudgets strips the sensitive per-session identifier from the DoW
// breakdown for the metadata (non-raw) view. Consumption counters and
// configured limits are policy/operational and stay visible; only the session
// id, which correlates a row to a specific live MCP session, is redacted. The
// agent name is the grouping key and is kept (it is the same identifier the
// agents panel shows).
func redactAgentBudgets(in []AgentBudgetView) []AgentBudgetView {
	out := make([]AgentBudgetView, len(in))
	for i, a := range in {
		if len(a.Sessions) > 0 {
			sessions := make([]AgentBudgetSessionView, len(a.Sessions))
			for j, s := range a.Sessions {
				s.SessionID = budgetRedacted
				sessions[j] = s
			}
			a.Sessions = sessions
		}
		out[i] = a
	}
	return out
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

func (a AgentBudgetView) ToolCallsDisplay() string {
	// Aggregate consumption across sessions vs the per-session limit.
	if a.MaxToolCallsPerSession <= 0 {
		return fmt.Sprintf("%d / %s", a.TotalToolCalls, budgetUnlimited)
	}
	return fmt.Sprintf("%d / %d per session", a.TotalToolCalls, a.MaxToolCallsPerSession)
}

func (a AgentBudgetView) InflightDisplay() string {
	if a.MaxConcurrentToolCalls <= 0 {
		return fmt.Sprintf("%d / %s", a.Inflight, budgetUnlimited)
	}
	return fmt.Sprintf("%d / %d per session", a.Inflight, a.MaxConcurrentToolCalls)
}

func (s AgentBudgetSessionView) SessionIDDisplay() string {
	return displayBudgetString(s.SessionID)
}

func (s AgentBudgetSessionView) StartedAtDisplay() string {
	return displayBudgetTime(s.StartedAt)
}

func displayBudgetString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return budgetEmptyDash
	}
	return value
}

func displayBudgetTime(value time.Time) string {
	if value.IsZero() {
		return budgetEmptyDash
	}
	return value.UTC().Format(time.RFC3339)
}
