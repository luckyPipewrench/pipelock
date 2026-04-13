//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"context"
	"net/http"

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

// Ports returns address->profile mappings for per-agent listeners.
func (e *enterpriseEdition) Ports() map[string]string { return e.registry.Ports() }

// Close releases scanners and other resources. Idempotent.
func (e *enterpriseEdition) Close() {
	if e.registry != nil {
		e.registry.Close()
	}
}
