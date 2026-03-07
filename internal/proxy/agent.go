// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"regexp"
)

// AgentHeader is the HTTP header used to identify the calling agent.
const AgentHeader = "X-Pipelock-Agent"

const agentAnonymous = "anonymous"

// maxAgentNameLen limits agent names to prevent log bloat.
const maxAgentNameLen = 64

// agentNameRe matches characters NOT allowed in agent names.
var agentNameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// ctxKeyAgentOverride is set by port-bound agent handlers to inject
// the profile name via context (spoof-proof, not header-based).
// Value 10 leaves room for future context keys between ctxKeyAgent (2) and this.
const ctxKeyAgentOverride contextKey = 10

// AgentIdentity carries the resolved agent name and profile key.
type AgentIdentity struct {
	Name    string // raw name from header/port (for audit logs)
	Profile string // resolved config profile key (for scanner/metrics)
}

// ResolveAgent determines the agent identity for a request.
// Priority: context override > header > query param > fallback.
// The knownProfiles map contains profile names that exist in the registry.
// Unrecognized names get Profile="_default" (bounded cardinality for metrics).
func ResolveAgent(r *http.Request, knownProfiles map[string]bool) AgentIdentity {
	// 1. Context override (listener mode): trusted, spoof-proof.
	if profile, ok := r.Context().Value(ctxKeyAgentOverride).(string); ok && profile != "" {
		return AgentIdentity{Name: profile, Profile: profile}
	}

	// 2. Header / query (via existing ExtractAgent).
	name := ExtractAgent(r)
	if name == agentAnonymous {
		return AgentIdentity{Name: "", Profile: profileDefault}
	}

	// 3. Check if name matches a known profile.
	if knownProfiles[name] {
		return AgentIdentity{Name: name, Profile: name}
	}

	// 4. Unrecognized: name preserved for audit, profile = _default.
	return AgentIdentity{Name: name, Profile: profileDefault}
}

// ExtractAgent reads the agent name from the request. It checks the
// X-Pipelock-Agent header first, then the "agent" query parameter,
// falling back to agentAnonymous. Names are sanitized to prevent log injection.
func ExtractAgent(r *http.Request) string {
	agent := r.Header.Get(AgentHeader)
	if agent == "" {
		agent = r.URL.Query().Get("agent")
	}
	if agent == "" {
		return agentAnonymous
	}
	agent = agentNameRe.ReplaceAllString(agent, "_")
	if len(agent) > maxAgentNameLen {
		agent = agent[:maxAgentNameLen]
	}
	if agent == "" {
		return agentAnonymous
	}
	return agent
}
