// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// profileDefault is the reserved name for the default agent profile.
const profileDefault = "_default"

// ResolvedAgent holds the fully merged config and pre-built scanner for a
// named agent profile.
type ResolvedAgent struct {
	Name    string
	Config  *config.Config
	Scanner *scanner.Scanner
	Budget  *BudgetTracker
}

// AgentRegistry maps agent profile names to resolved agents. Built at
// startup and on hot-reload, then swapped atomically.
type AgentRegistry struct {
	agents   map[string]*ResolvedAgent
	ports    map[string]string // listen addr -> profile name
	fallback *ResolvedAgent
}

// NewAgentRegistry builds a registry from the base config. Each agent profile
// is deep-merged with the base, and a scanner is built from the merged config.
func NewAgentRegistry(base *config.Config) (*AgentRegistry, error) {
	reg := &AgentRegistry{
		agents: make(map[string]*ResolvedAgent, len(base.Agents)),
		ports:  make(map[string]string),
	}

	for name, profile := range base.Agents {
		merged, err := config.MergeAgentProfile(base, &profile)
		if err != nil {
			return nil, fmt.Errorf("agent %q: %w", name, err)
		}
		sc := scanner.New(merged)
		resolved := &ResolvedAgent{
			Name:    name,
			Config:  merged,
			Scanner: sc,
			Budget:  NewBudgetTracker(&profile.Budget),
		}
		reg.agents[name] = resolved

		for _, addr := range profile.Listeners {
			reg.ports[addr] = name
		}
	}

	// Set fallback: _default profile if defined, else base config.
	if def, ok := reg.agents[profileDefault]; ok {
		reg.fallback = def
	} else {
		sc := scanner.New(base)
		reg.fallback = &ResolvedAgent{
			Name:    profileDefault,
			Config:  base,
			Scanner: sc,
		}
	}

	return reg, nil
}

// Lookup returns the ResolvedAgent for the given profile name.
// Unknown names return the fallback (either _default or base config).
func (r *AgentRegistry) Lookup(profile string) *ResolvedAgent {
	if agent, ok := r.agents[profile]; ok {
		return agent
	}
	return r.fallback
}

// ProfileForPort returns the agent profile name bound to a listen address.
func (r *AgentRegistry) ProfileForPort(addr string) (string, bool) {
	name, ok := r.ports[addr]
	return name, ok
}

// Close releases resources (scanners) held by the registry.
func (r *AgentRegistry) Close() {
	for _, agent := range r.agents {
		agent.Scanner.Close()
	}
	if _, isMapped := r.agents[r.fallback.Name]; !isMapped {
		// fallback was built from base, not from agents map
		r.fallback.Scanner.Close()
	}
}

// Profiles returns all configured agent profile names (excluding fallback
// if it was synthesized from the base config).
func (r *AgentRegistry) Profiles() []string {
	names := make([]string, 0, len(r.agents))
	for name := range r.agents {
		names = append(names, name)
	}
	return names
}
