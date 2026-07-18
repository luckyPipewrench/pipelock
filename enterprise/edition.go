//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"context"
	"net/http"
	"sort"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// enterpriseEdition implements edition.Edition with full multi-agent support:
// per-agent configs, scanners, budgets, CIDR matching, and license gating.
type enterpriseEdition struct {
	registry *AgentRegistry
	cfg      *config.Config
	sc       *scanner.Scanner
}

// NewEdition creates an enterprise Edition from config. This is the
// implementation behind edition.NewEditionFunc.
func NewEdition(cfg *config.Config, sc *scanner.Scanner) (edition.Edition, error) {
	reg, err := NewAgentRegistry(cfg, sc)
	if err != nil {
		return nil, err
	}
	return &enterpriseEdition{registry: reg, cfg: cfg, sc: sc}, nil
}

// ResolveAgent maps a request to an agent-specific config, scanner, budget,
// and identity using the 4-step resolution: context override > CIDR >
// header/query > fallback.
func (e *enterpriseEdition) ResolveAgent(ctx context.Context, r *http.Request) (*edition.ResolvedAgent, edition.AgentIdentity) {
	return e.registry.ResolveFromRequest(ctx, r, e.cfg, e.sc)
}

// LookupProfile resolves a named profile without an HTTP request.
// Returns (resolved, true) for known or default profiles.
// Returns (default, false) for unknown names.
// Always returns a non-nil ResolvedAgent.
func (e *enterpriseEdition) LookupProfile(name string) (*edition.ResolvedAgent, bool) {
	if name == "" || name == edition.ProfileDefault {
		ra, found := e.registry.LookupByName(edition.ProfileDefault)
		if found {
			return ra, true
		}
		// No _default in registry; return base config as fallback.
		return e.registry.Fallback(), true
	}
	ra, found := e.registry.LookupByName(name)
	if !found {
		// Unknown name: return the registry fallback (which is _default
		// if configured, otherwise the base config).
		return e.registry.Fallback(), false
	}
	return ra, true
}

// Reload rebuilds the edition from new config. Returns a NEW immutable
// Edition instance. The caller atomically swaps and closes the old one.
func (e *enterpriseEdition) Reload(cfg *config.Config, sc *scanner.Scanner) (edition.Edition, error) {
	reg, err := NewAgentRegistry(cfg, sc)
	if err != nil {
		return nil, err
	}
	return &enterpriseEdition{registry: reg, cfg: cfg, sc: sc}, nil
}

// KnownProfiles returns configured profile names for bounded cardinality
// in metrics and logging.
func (e *enterpriseEdition) KnownProfiles() map[string]bool {
	profiles := e.registry.Profiles()
	m := make(map[string]bool, len(profiles))
	for _, name := range profiles {
		m[name] = true
	}
	return m
}

// defaultAgentBudgetSnapshotLimit caps how many per-agent budget snapshots are
// returned when the caller passes a non-positive limit, bounding output
// cardinality for the read-only observability surface.
const defaultAgentBudgetSnapshotLimit = 1000

// AgentBudgetSnapshots implements edition.AgentBudgetSnapshotProvider. It walks
// configured profiles and returns a read-only, point-in-time forward-budget
// snapshot for each agent whose budget tracker exposes one. NoopBudget does not
// implement edition.BudgetSnapshotProvider, so agents without a configured
// forward budget are omitted. It never mutates budget or enforcement state.
// Profiles are sorted for deterministic output and bounded by limit.
func (e *enterpriseEdition) AgentBudgetSnapshots(_ context.Context, limit int) ([]edition.AgentBudgetSnapshot, error) {
	if limit <= 0 {
		limit = defaultAgentBudgetSnapshotLimit
	}
	names := append([]string(nil), e.registry.Profiles()...)
	sort.Strings(names)
	out := make([]edition.AgentBudgetSnapshot, 0, len(names))
	for _, name := range names {
		if len(out) >= limit {
			break
		}
		ra := e.registry.Lookup(name)
		if ra == nil {
			continue
		}
		sp, ok := ra.Budget.(edition.BudgetSnapshotProvider)
		if !ok {
			continue
		}
		out = append(out, edition.AgentBudgetSnapshot{
			Agent:          name,
			BudgetSnapshot: sp.Snapshot(),
		})
	}
	return out, nil
}

// Ports returns address->profile mappings for per-agent listeners.
func (e *enterpriseEdition) Ports() map[string]string { return e.registry.Ports() }

// Close releases scanners and other resources. Idempotent.
func (e *enterpriseEdition) Close() {
	if e.registry != nil {
		e.registry.Close()
	}
}
