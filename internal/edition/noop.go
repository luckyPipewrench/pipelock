// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package edition

import (
	"context"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// noopEdition is the OSS Edition. All requests use the global default
// scanner and config. No per-agent resolution, budgets, or isolation.
type noopEdition struct {
	cfg *config.Config
	sc  *scanner.Scanner
}

func newNoopEdition(cfg *config.Config, sc *scanner.Scanner) (Edition, error) {
	return &noopEdition{cfg: cfg, sc: sc}, nil
}

func (e *noopEdition) ResolveAgent(_ context.Context, r *http.Request) (*ResolvedAgent, AgentIdentity) {
	identity := ResolveAgentIdentity(r, nil, e.cfg.DefaultAgentIdentity, e.cfg.BindDefaultAgentIdentity)

	return &ResolvedAgent{
		Name:    ProfileDefault,
		Config:  e.cfg,
		Scanner: e.sc,
		Budget:  NoopBudget,
	}, identity
}

func (e *noopEdition) LookupProfile(name string) (*ResolvedAgent, bool) {
	ra := &ResolvedAgent{Name: ProfileDefault, Config: e.cfg, Scanner: e.sc, Budget: NoopBudget}
	return ra, name == "" || name == ProfileDefault
}

func (e *noopEdition) Reload(cfg *config.Config, sc *scanner.Scanner) (Edition, error) {
	return &noopEdition{cfg: cfg, sc: sc}, nil
}

func (e *noopEdition) KnownProfiles() map[string]bool { return nil }
func (e *noopEdition) Ports() map[string]string       { return nil }
func (e *noopEdition) Close()                         {}
