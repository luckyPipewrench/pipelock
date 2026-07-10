//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Bounded filter value constants.
const (
	verdictAllow   = config.ActionAllow
	verdictBlock   = config.ActionBlock
	verdictWarn    = config.ActionWarn
	verdictDefer   = config.ActionDefer
	verdictNoMatch = "__invalid_verdict__"

	chainIntact  = "intact"
	chainBroken  = "broken"
	chainAny     = "any"
	chainNoMatch = "__invalid_chain__"

	pipUntampered = "U"
)

const fleetRedactionKeySize = 32

// FilterSpec describes a bounded filter for the agent/session list. Unknown
// non-empty enum values fail closed to no matches.
type FilterSpec struct {
	Verdict string // "allow", "block", "warn", "defer", or "" (any)
	Agent   string // case-insensitive substring of the agent name, or "" (any)
	Chain   string // "intact", "broken", "any", or "" (any)
}

// Options configures the read-only Evidence dashboard.
type Options struct {
	ReceiptDir  string
	TrustedKeys map[string]TrustedKey
	Config      *config.Config
	HasFeature  func(string) bool
	// Authorize, when non-nil, runs per request after the license-feature check
	// and fails the request closed (403) on a non-nil error. It is the handler's
	// authentication/authorization seam, distinct from the license entitlement
	// check. Nil means the surrounding router must own authentication.
	Authorize func(*http.Request) error
	// AuthorizeRaw gates the sensitive raw view (receipt destinations and full
	// signed payloads). A request is shown raw detail only when AuthorizeRaw is
	// non-nil AND returns nil for it; every other authenticated request gets the
	// redacted metadata view. Nil means raw detail is redacted for everyone
	// (fail closed): a destination URL can carry a capability token, and the raw
	// payload is the largest exfil surface, so raw is least-privilege by default.
	AuthorizeRaw func(*http.Request) error
	// AuthorizeFleetScope gates reads keyed by an operator-supplied org/fleet
	// scope before any conductor replay or fleet source is called. Nil is
	// fail-closed when a read source is configured for the requested page.
	AuthorizeFleetScope func(*http.Request, DecisionScope, bool) error
	// AuditWriter, when non-nil, receives access lines for authenticated
	// dashboard requests and scope lines for replay/fleet correlation lookups.
	// Scope values are logged as stable hashes, not raw org/fleet/artifact
	// identifiers. Viewing evidence is itself an audited action. Nil disables
	// the access log.
	AuditWriter io.Writer
	FleetSource FleetDataSource
	// ConductorSource, when non-nil, is the read-only conductor decision
	// dry-run/replay seam (BE-2) consumed by the Signed Action Workbench and
	// Incident Cockpit. It exposes no publish/kill/rollback method, so no write
	// path to fleet state is reachable through it. Nil renders the explicit
	// unconfigured-replay state, exactly like FleetSource.
	ConductorSource ConductorDecisionSource
	// BudgetSource, when non-nil, is the read-only per-agent budget seam for
	// the Pro budgets panel. Nil-degrades to an empty "no source configured"
	// panel.
	BudgetSource     BudgetDataSource
	ReceiptReadLimit int
	TimelineLimit    int
	// FilterPresets maps named presets to bounded filter specs. Loaded from
	// --filter-presets-file at startup. A preset name in the "preset" query
	// param pre-fills the same bounded params; explicit query params override.
	FilterPresets map[string]FilterSpec
	// ExemptionStore, when non-nil, is a durable lifecycle store overlaid
	// onto the read-only exemptions inventory. Its records add
	// owner/reason/expiry/status/last-matched to matching entries.
	ExemptionStore *ExemptionStore
	// Now supplies the current time for lifecycle rendering. Nil uses time.Now.
	Now func() time.Time
}

// ReadModel builds dashboard views over recorder sessions and receipts.
type ReadModel struct {
	receiptDir        string
	trustedKeys       map[string]TrustedKey
	cfg               *config.Config
	receiptReadLimit  int
	timelineLimit     int
	filterPresets     map[string]FilterSpec
	fleetSource       FleetDataSource
	conductorSource   ConductorDecisionSource
	budgetSource      BudgetDataSource
	fleetRedactionKey [fleetRedactionKeySize]byte
	exemptionStore    *ExemptionStore
	now               func() time.Time
}

// NewReadModel creates a dashboard read model from Options.
func NewReadModel(opts Options) *ReadModel {
	receiptReadLimit := opts.ReceiptReadLimit
	if receiptReadLimit <= 0 {
		receiptReadLimit = dashboardReceiptReadLimit
	}
	timelineLimit := opts.TimelineLimit
	if timelineLimit <= 0 {
		timelineLimit = dashboardTimelineLimit
	}
	var fleetRedactionKey [fleetRedactionKeySize]byte
	if _, err := rand.Read(fleetRedactionKey[:]); err != nil {
		panic(fmt.Errorf("generate dashboard fleet redaction key: %w", err))
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &ReadModel{
		receiptDir:        opts.ReceiptDir,
		trustedKeys:       cloneTrustedKeys(opts.TrustedKeys),
		cfg:               opts.Config,
		receiptReadLimit:  receiptReadLimit,
		timelineLimit:     timelineLimit,
		filterPresets:     opts.FilterPresets,
		fleetSource:       opts.FleetSource,
		conductorSource:   opts.ConductorSource,
		budgetSource:      opts.BudgetSource,
		fleetRedactionKey: fleetRedactionKey,
		exemptionStore:    opts.ExemptionStore,
		now:               now,
	}
}

// Sessions lists available recorder sessions and computes their compact state.
func (m *ReadModel) Sessions() ([]SessionSummary, error) {
	ids, err := recorder.ListSessions(m.receiptDir)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}

	summaries := make([]SessionSummary, 0, len(ids))
	for _, id := range ids {
		receipts, readLimited, err := receipt.ExtractReceiptsFromSessionDirBounded(m.receiptDir, id, m.receiptReadLimit)
		if err != nil {
			return nil, fmt.Errorf("read session %s receipts: %w", id, err)
		}
		summaries = append(summaries, sessionSummary(id, receipts, m.trustedKeys, readLimited, m.receiptReadLimit))
	}
	return summaries, nil
}

// Session reads one session's complete evidence.
func (m *ReadModel) Session(id string) (SessionEvidence, error) {
	receipts, readLimited, err := receipt.ExtractReceiptsFromSessionDirBounded(m.receiptDir, id, m.receiptReadLimit)
	if err != nil {
		return SessionEvidence{}, fmt.Errorf("read session %s receipts: %w", id, err)
	}
	return sessionEvidence(id, receipts, m.trustedKeys, readLimited, m.receiptReadLimit, m.timelineLimit), nil
}

// Agents lists sessions grouped by agent with bounded rollup counts,
// optionally filtered by the given FilterSpec.
func (m *ReadModel) Agents(filter FilterSpec) ([]evidenceview.AgentGroup, error) {
	sessions, err := m.Sessions()
	if err != nil {
		return nil, err
	}
	sessions = applyFilter(sessions, normalizeFilter(filter))
	return evidenceview.GroupByAgent(sessions), nil
}

// Agent returns one agent's group (its sessions + rollup), optionally filtered.
func (m *ReadModel) Agent(id string, filter FilterSpec) (evidenceview.AgentGroup, bool, error) {
	groups, err := m.Agents(filter)
	if err != nil {
		return evidenceview.AgentGroup{}, false, err
	}
	for _, g := range groups {
		if g.Agent == id {
			return g, true, nil
		}
	}
	return evidenceview.AgentGroup{}, false, nil
}

// ReceiptDetail loads one receipt by session ID and chain sequence number,
// returning a DecisionExplanation. The CALLER redacts per RBAC.
func (m *ReadModel) ReceiptDetail(sessionID string, seq uint64) (evidenceview.DecisionExplanation, bool, error) {
	receipts, _, err := receipt.ExtractReceiptsFromSessionDirBounded(m.receiptDir, sessionID, m.receiptReadLimit)
	if err != nil {
		return evidenceview.DecisionExplanation{}, false, fmt.Errorf("read session %s receipts: %w", sessionID, err)
	}
	for _, r := range receipts {
		if r.ActionRecord.ChainSeq == seq {
			return evidenceview.ExplainReceipt(r), true, nil
		}
	}
	return evidenceview.DecisionExplanation{}, false, nil
}

// ResolveFilter resolves a FilterSpec from query params, falling back to a
// named preset if no explicit params are given.
func (m *ReadModel) ResolveFilter(r *http.Request) FilterSpec {
	q := r.URL.Query()
	verdict := q.Get("verdict")
	agent := q.Get("agent")
	chain := q.Get("chain")
	preset := q.Get("preset")

	// If no explicit params, try a named preset.
	if verdict == "" && agent == "" && chain == "" && preset != "" && m.filterPresets != nil {
		if p, ok := m.filterPresets[preset]; ok {
			// Explicit query params override the preset.
			return FilterSpec{
				Verdict: overrideIfSet(verdict, p.Verdict),
				Agent:   overrideIfSet(agent, p.Agent),
				Chain:   overrideIfSet(chain, p.Chain),
			}
		}
	}
	return FilterSpec{Verdict: verdict, Agent: agent, Chain: chain}
}

func overrideIfSet(explicit, preset string) string {
	if explicit != "" {
		return explicit
	}
	return preset
}

// normalizeFilter clamps filter values to the enumerated bounded set.
// Unknown non-empty enum values become no-match sentinels.
func normalizeFilter(f FilterSpec) FilterSpec {
	switch f.Verdict {
	case "", verdictAllow, verdictBlock, verdictWarn, verdictDefer:
		// valid
	default:
		f.Verdict = verdictNoMatch
	}
	switch f.Chain {
	case "", chainIntact, chainBroken, chainAny:
		// valid
	default:
		f.Chain = chainNoMatch
	}
	return f
}

func applyFilter(sessions []SessionSummary, f FilterSpec) []SessionSummary {
	if f.Verdict == verdictNoMatch || f.Chain == chainNoMatch {
		return nil
	}
	if f.Verdict == "" && f.Agent == "" && f.Chain == "" {
		return sessions
	}
	agentQuery := strings.ToLower(strings.TrimSpace(f.Agent))
	filtered := make([]SessionSummary, 0, len(sessions))
	for _, s := range sessions {
		if agentQuery != "" && !strings.Contains(strings.ToLower(s.Agent), agentQuery) {
			continue
		}
		if f.Chain != "" && f.Chain != chainAny {
			match := false
			for _, pip := range s.Pips {
				if pip.Label == pipUntampered {
					switch f.Chain {
					case chainIntact:
						match = pip.State == StateVerify || pip.State == StateLimited
					case chainBroken:
						match = pip.State == StateFail
					}
					break
				}
			}
			if !match {
				continue
			}
		}
		// Verdict filter: keep sessions that carried at least one receipt with
		// the requested verdict. This is a session-level filter (an agent is
		// shown if any of its receipts matched), not a per-receipt filter.
		if f.Verdict != "" && !s.HasVerdict(f.Verdict) {
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}
