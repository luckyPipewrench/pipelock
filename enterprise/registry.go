//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// cidrMapping maps a parsed network to the agent profile name that owns it.
type cidrMapping struct {
	network *net.IPNet
	profile string
}

// AgentRegistry maps agent profile names to resolved agents. Built at
// startup and on hot-reload, then swapped atomically via Edition.
type AgentRegistry struct {
	agents           map[string]*edition.ResolvedAgent
	ports            map[string]string // listen addr -> profile name
	cidrs            []cidrMapping     // source CIDR -> profile name
	fallback         *edition.ResolvedAgent
	licenseExpiresAt int64 // Unix timestamp; 0 = perpetual. Checked on Lookup().
}

// NewAgentRegistry builds a registry from the base config. Each agent profile
// is deep-merged with the base, and a scanner is built from the merged config.
func NewAgentRegistry(base *config.Config) (_ *AgentRegistry, err error) {
	reg := &AgentRegistry{
		agents:           make(map[string]*edition.ResolvedAgent, len(base.Agents)),
		ports:            make(map[string]string),
		licenseExpiresAt: base.LicenseExpiresAt,
	}
	defer func() {
		if err != nil {
			reg.Close()
		}
	}()

	for name, profile := range base.Agents {
		merged, mergeErr := MergeAgentProfile(base, &profile)
		if mergeErr != nil {
			return nil, fmt.Errorf("agent %q: %w", name, mergeErr)
		}
		if err := ValidateMergedAgent(name, merged); err != nil {
			return nil, err
		}
		sc := scanner.New(merged)
		bt := NewBudgetTracker(&profile.Budget)

		// BudgetTracker → BudgetChecker interface.
		// Use NoopBudget when no budget is configured to avoid nil-interface
		// panics in proxy handlers.
		budget := edition.NoopBudget
		if bt != nil {
			budget = bt
		}

		resolved := &edition.ResolvedAgent{
			Name:    name,
			Config:  merged,
			Scanner: sc,
			Budget:  budget,
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
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("agent %q: invalid source_cidr %q: %w", name, cidr, err)
			}
			reg.cidrs = append(reg.cidrs, cidrMapping{network: network, profile: name})
		}
	}

	// Set fallback: _default profile if defined, else base config.
	if def, ok := reg.agents[edition.ProfileDefault]; ok {
		reg.fallback = def
	} else {
		sc := scanner.New(base)
		reg.fallback = &edition.ResolvedAgent{
			Name:    edition.ProfileDefault,
			Config:  base,
			Scanner: sc,
			Budget:  edition.NoopBudget,
		}
	}

	return reg, nil
}

// Fallback returns the registry's default ResolvedAgent. This is the _default
// profile if configured, otherwise a base-config agent. Always non-nil.
func (r *AgentRegistry) Fallback() *edition.ResolvedAgent { return r.fallback }

// Lookup returns the ResolvedAgent for the given profile name.
// Unknown names return the fallback (either _default or base config).
// If the license has expired since startup, non-default profiles are
// rejected and the fallback is returned instead.
func (r *AgentRegistry) Lookup(profile string) *edition.ResolvedAgent {
	if agent, ok := r.agents[profile]; ok {
		// Runtime license expiry: if the license has a non-zero expiry
		// and it's past, fall back for non-default profiles.
		if profile != edition.ProfileDefault && r.licenseExpiresAt > 0 && time.Now().Unix() > r.licenseExpiresAt {
			return r.fallback
		}
		return agent
	}
	return r.fallback
}

// LookupByName resolves a named profile for Edition.LookupProfile.
// Returns (resolved, true) for known profiles.
// Returns (fallback, false) for unknown profiles.
// Enforces runtime license expiry: expired non-default profiles return fallback.
func (r *AgentRegistry) LookupByName(name string) (*edition.ResolvedAgent, bool) {
	if agent, ok := r.agents[name]; ok {
		// Runtime license expiry: same check as Lookup().
		if name != edition.ProfileDefault && r.licenseExpiresAt > 0 && time.Now().Unix() > r.licenseExpiresAt {
			return r.fallback, false
		}
		return agent, true
	}
	return r.fallback, false
}

// ResolveFromRequest implements the 4-step agent resolution for Edition.ResolveAgent.
// Priority: context override > CIDR > header/query > fallback.
func (r *AgentRegistry) ResolveFromRequest(ctx context.Context, req *http.Request, defaultCfg *config.Config, defaultSc *scanner.Scanner) (*edition.ResolvedAgent, edition.AgentIdentity) {
	// 1. Context override (set by per-agent listener binding).
	if profile, ok := edition.AgentOverrideFromContext(ctx); ok {
		id := edition.AgentIdentity{Name: profile, Profile: profile}
		return r.Lookup(id.Profile), id
	}

	// 2. Source CIDR match: map client IP to profile.
	if clientIP := extractIP(req); clientIP != nil {
		if profile, ok := r.MatchCIDR(clientIP); ok {
			id := edition.AgentIdentity{Name: profile, Profile: profile}
			return r.Lookup(id.Profile), id
		}
	}

	// 3+4. Header/query/fallback via ResolveAgentIdentity.
	profiles := r.Profiles()
	known := make(map[string]bool, len(profiles))
	for _, name := range profiles {
		known[name] = true
	}
	id := edition.ResolveAgentIdentity(req, known)
	return r.Lookup(id.Profile), id
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

// extractIP parses the client IP from r.RemoteAddr, stripping the port.
func extractIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}
