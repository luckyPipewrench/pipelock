// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// cidrMapping maps a parsed network to the agent profile name that owns it.
type cidrMapping struct {
	network *net.IPNet
	profile string
}

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
	agents           map[string]*ResolvedAgent
	ports            map[string]string // listen addr -> profile name
	cidrs            []cidrMapping     // source CIDR -> profile name
	fallback         *ResolvedAgent
	licenseExpiresAt int64 // Unix timestamp; 0 = perpetual. Checked on Lookup().
}

// NewAgentRegistry builds a registry from the base config. Each agent profile
// is deep-merged with the base, and a scanner is built from the merged config.
func NewAgentRegistry(base *config.Config) (_ *AgentRegistry, err error) {
	reg := &AgentRegistry{
		agents:           make(map[string]*ResolvedAgent, len(base.Agents)),
		ports:            make(map[string]string),
		licenseExpiresAt: base.LicenseExpiresAt,
	}
	defer func() {
		if err != nil {
			reg.Close()
		}
	}()

	for name, profile := range base.Agents {
		merged, err := config.MergeAgentProfile(base, &profile)
		if err != nil {
			return nil, fmt.Errorf("agent %q: %w", name, err)
		}
		if err := config.ValidateMergedAgent(name, merged); err != nil {
			return nil, err
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
			if prev, exists := reg.ports[addr]; exists {
				return nil, fmt.Errorf("listener %q is assigned to both %q and %q", addr, prev, name)
			}
			reg.ports[addr] = name
		}

		// Parse source CIDRs (already validated in config.Validate).
		for _, cidr := range profile.SourceCIDRs {
			_, network, _ := net.ParseCIDR(cidr) // safe: validated at config load
			reg.cidrs = append(reg.cidrs, cidrMapping{network: network, profile: name})
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
// If the license has expired since startup, non-default profiles are
// rejected and the fallback is returned instead.
func (r *AgentRegistry) Lookup(profile string) *ResolvedAgent {
	if agent, ok := r.agents[profile]; ok {
		// Runtime license expiry: if the license has a non-zero expiry
		// and it's past, fall back for non-default profiles.
		if profile != profileDefault && r.licenseExpiresAt > 0 && time.Now().Unix() > r.licenseExpiresAt {
			return r.fallback
		}
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
// Nil-safe: a nil registry is a no-op.
func (r *AgentRegistry) Close() {
	if r == nil {
		return
	}
	for _, agent := range r.agents {
		agent.Scanner.Close()
	}
	if r.fallback == nil {
		return
	}
	if _, isMapped := r.agents[r.fallback.Name]; !isMapped {
		// fallback was built from base, not from agents map
		r.fallback.Scanner.Close()
	}
}

// Ports returns a copy of the listen-address-to-profile mapping.
func (r *AgentRegistry) Ports() map[string]string {
	out := make(map[string]string, len(r.ports))
	for addr, name := range r.ports {
		out[addr] = name
	}
	return out
}

// MatchCIDR returns the agent profile name whose source_cidrs contain ip.
// Returns ("", false) if no CIDR matches. Linear scan is acceptable because
// the number of agent profiles is small (typically <20).
func (r *AgentRegistry) MatchCIDR(ip net.IP) (string, bool) {
	for _, m := range r.cidrs {
		if m.network.Contains(ip) {
			return m.profile, true
		}
	}
	return "", false
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
