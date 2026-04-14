// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package edition defines the multi-agent extension point for pipelock.
// Core proxy code uses these types and hook variables.
// Enterprise builds provide real implementations; OSS uses noop defaults.
package edition

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Edition provides multi-agent capabilities to the proxy.
// OSS builds use noopEdition (returns defaults for all requests).
// Enterprise builds use the full AgentRegistry with per-agent
// scanners, budgets, and config isolation.
type Edition interface {
	// ResolveAgent maps a request to an agent-specific scanner, config,
	// and identity. Uses context override (spoof-proof listener binding),
	// then CIDR, then header/query, then fallback.
	// Noop returns global defaults for all requests.
	ResolveAgent(ctx context.Context, r *http.Request) (*ResolvedAgent, AgentIdentity)

	// LookupProfile resolves a named profile without an HTTP request.
	// Returns (resolved, true) for known, current, or default profiles.
	// Returns (fallback, false) for unknown names or known-but-expired
	// profiles. Callers use KnownProfiles() to distinguish unknown from
	// expired (expired entries appear in KnownProfiles, unknown do not).
	// Always returns a non-nil ResolvedAgent.
	LookupProfile(name string) (*ResolvedAgent, bool)

	// Reload rebuilds edition state from new config. Returns a new
	// Edition instance (caller atomically swaps). Returns error if
	// rebuild fails (caller keeps old state).
	Reload(cfg *config.Config, sc *scanner.Scanner) (Edition, error)

	// KnownProfiles returns configured profile names for bounded
	// cardinality in metrics/logging. Returns nil for noop.
	KnownProfiles() map[string]bool

	// Ports returns address->profile mappings for per-agent listeners.
	// Returns nil for noop.
	Ports() map[string]string

	// Close releases scanners and other resources. Idempotent.
	Close()
}

// ResolvedAgent carries the resolved per-agent config, scanner, and
// budget tracker for a single request. Budget must be NoopBudget (not nil)
// when unlimited to avoid nil-interface panics.
type ResolvedAgent struct {
	Name    string
	Config  *config.Config
	Scanner *scanner.Scanner
	Budget  BudgetChecker
}

// BudgetChecker enforces per-agent request/byte budgets.
// Enterprise builds provide BudgetTracker; OSS uses NoopBudget.
// Use NoopBudget instead of nil to avoid nil-interface panics in handlers.
type BudgetChecker interface {
	CheckAdmission(domain string) error
	RecordBytes(n int64) error
	RecordRequest(domain string, bodyBytes int64) error
	// RemainingBytes returns bytes left before the byte budget is exceeded.
	// Returns -1 when no byte limit is configured (unlimited).
	RemainingBytes() int64
}

// NoopBudget is a BudgetChecker that permits everything.
// Used by OSS builds and enterprise agents without budget config.
var NoopBudget BudgetChecker = noopBudget{}

type noopBudget struct{}

func (noopBudget) CheckAdmission(string) error       { return nil }
func (noopBudget) RecordBytes(int64) error           { return nil }
func (noopBudget) RecordRequest(string, int64) error { return nil }
func (noopBudget) RemainingBytes() int64             { return -1 }

// AgentIdentity carries the resolved agent name and profile key.
type AgentIdentity struct {
	Name    string             // display name (sanitized header value or profile name)
	Profile string             // config key used for registry lookup
	Auth    envelope.ActorAuth // how the identity was determined (bound/matched/self-declared)
}

// ProfileDefault is the reserved name for the default agent profile.
const ProfileDefault = "_default"

// AgentHeader is the HTTP header used to identify the calling agent.
const AgentHeader = "X-Pipelock-Agent"

const agentAnonymous = "anonymous"

// maxAgentNameLen limits agent names to prevent log bloat.
const maxAgentNameLen = 64

// agentNameRe matches characters NOT allowed in agent names.
var agentNameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// --- Context override helpers (key is private) ---

type contextKey int

// keyAgentOverride is the context key for spoof-proof listener binding.
// Value 10 leaves room for future context keys.
const keyAgentOverride contextKey = 10

// WithAgentOverride returns a context with the agent profile override set.
// Used by per-agent listener binding to inject identity via context
// instead of trusting the X-Pipelock-Agent header.
func WithAgentOverride(ctx context.Context, profile string) context.Context {
	return context.WithValue(ctx, keyAgentOverride, profile)
}

// AgentOverrideFromContext reads the spoof-proof agent override.
// Returns ("", false) when no override is set.
func AgentOverrideFromContext(ctx context.Context) (string, bool) {
	profile, ok := ctx.Value(keyAgentOverride).(string)
	return profile, ok && profile != ""
}

// ValidateAgentName checks that a profile name is valid for agent config.
// Returns an error if the name would be altered by the request-side sanitizer
// (ExtractAgent) or exceeds the length limit. This prevents profiles that
// silently fall back to _default because the header value doesn't round-trip.
func ValidateAgentName(name string) error {
	if name == "" {
		return fmt.Errorf("agent profile name must not be empty")
	}
	if name == agentAnonymous {
		return fmt.Errorf("agent profile name %q is reserved", name)
	}
	if len(name) > maxAgentNameLen {
		return fmt.Errorf("agent profile name %q exceeds %d character limit", name, maxAgentNameLen)
	}
	if agentNameRe.MatchString(name) {
		return fmt.Errorf("agent profile name %q contains invalid characters (allowed: a-z, A-Z, 0-9, '.', '_', '-')", name)
	}
	return nil
}

// --- Agent name extraction ---

// ExtractAgent reads the agent name from the request header or query param.
// Returns "anonymous" when no agent is specified.
// Names are sanitized to prevent log injection.
func ExtractAgent(r *http.Request) string {
	return ExtractAgentWithDefault(r, "", false)
}

func boundDefaultIdentity(defaultIdentity string, bindDefaultIdentity bool) (string, bool) {
	if !bindDefaultIdentity || defaultIdentity == "" {
		return "", false
	}
	return sanitizeAgentName(defaultIdentity), true
}

func configDefaultIdentity(knownProfiles map[string]bool, defaultIdentity string) AgentIdentity {
	resolved := sanitizeAgentName(defaultIdentity)
	if knownProfiles[resolved] {
		return AgentIdentity{Name: resolved, Profile: resolved, Auth: envelope.ActorAuthConfigDefault}
	}
	return AgentIdentity{Name: resolved, Profile: ProfileDefault, Auth: envelope.ActorAuthConfigDefault}
}

// ExtractAgentWithDefault reads the agent name from the request header,
// default identity, or query param before "anonymous".
// Priority:
//   - when bindDefaultIdentity=true and defaultIdentity is set:
//     defaultIdentity > "anonymous" (header/query ignored)
//   - otherwise:
//     header > defaultIdentity > query param > "anonymous"
//
// Names are sanitized to prevent log injection.
func ExtractAgentWithDefault(r *http.Request, defaultIdentity string, bindDefaultIdentity bool) string {
	if boundName, ok := boundDefaultIdentity(defaultIdentity, bindDefaultIdentity); ok {
		return boundName
	}
	agent := r.Header.Get(AgentHeader)
	if agent != "" {
		return sanitizeAgentName(agent)
	}
	if defaultIdentity != "" {
		return sanitizeAgentName(defaultIdentity)
	}
	agent = r.URL.Query().Get("agent")
	if agent == "" {
		return agentAnonymous
	}
	return sanitizeAgentName(agent)
}

// sanitizeAgentName strips disallowed characters and truncates.
func sanitizeAgentName(agent string) string {
	agent = agentNameRe.ReplaceAllString(agent, "_")
	if len(agent) > maxAgentNameLen {
		agent = agent[:maxAgentNameLen]
	}
	if agent == "" {
		return agentAnonymous
	}
	return agent
}

// ResolveAgentIdentity determines agent identity from a request.
// Priority:
//   - context override
//   - bound defaultIdentity when bindDefaultIdentity=true
//   - header > defaultIdentity > query param > fallback otherwise
//
// knownProfiles contains profile names that exist in the registry.
// Unrecognized names get Profile=ProfileDefault (bounded cardinality).
func ResolveAgentIdentity(r *http.Request, knownProfiles map[string]bool, defaultIdentity string, bindDefaultIdentity bool) AgentIdentity {
	if profile, ok := AgentOverrideFromContext(r.Context()); ok {
		return AgentIdentity{Name: profile, Profile: profile, Auth: envelope.ActorAuthBound}
	}

	if _, ok := boundDefaultIdentity(defaultIdentity, bindDefaultIdentity); ok {
		return configDefaultIdentity(knownProfiles, defaultIdentity)
	}

	headerName := sanitizeAgentName(r.Header.Get(AgentHeader))
	if headerName != agentAnonymous {
		if knownProfiles[headerName] {
			return AgentIdentity{Name: headerName, Profile: headerName, Auth: envelope.ActorAuthMatched}
		}
		return AgentIdentity{Name: headerName, Profile: ProfileDefault, Auth: envelope.ActorAuthSelfDeclared}
	}

	if defaultIdentity != "" {
		return configDefaultIdentity(knownProfiles, defaultIdentity)
	}

	name := sanitizeAgentName(r.URL.Query().Get("agent"))
	if name == agentAnonymous {
		return AgentIdentity{Name: "", Profile: ProfileDefault, Auth: envelope.ActorAuthSelfDeclared}
	}

	if knownProfiles[name] {
		return AgentIdentity{Name: name, Profile: name, Auth: envelope.ActorAuthMatched}
	}

	return AgentIdentity{Name: name, Profile: ProfileDefault, Auth: envelope.ActorAuthSelfDeclared}
}
