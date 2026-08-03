// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

// Scope describes how broadly a configured rule applies to a destination.
//
// Pipelock's existing destination rules are PORTLESS by design. `trusted_domains`
// exempts a hostname wherever it is reached, and `ssrf.ip_allowlist` permits an
// address regardless of the port behind it. Guard grants (added later, once the
// grant type exists) are the opposite: they authorize an exact protocol, host
// AND port, so api.dev.example:6443 can be reachable while :443 is not.
//
// Both kinds of rule end up answering the same question, and this type keeps
// the difference visible instead of letting it collapse into one boolean.
type Scope int

const (
	// ScopeNone means the rule does not apply to the destination.
	ScopeNone Scope = iota
	// ScopeExact means the rule named this network, host and port.
	ScopeExact
	// ScopePortless means the rule matched the host or address but said
	// nothing about the port or the transport. Every legacy rule is this.
	ScopePortless
)

// Effect is what a rule says about reaching a destination.
type Effect int

const (
	// EffectNoMatch means the rule had nothing to say.
	EffectNoMatch Effect = iota
	// EffectAllow means the rule permits the destination.
	EffectAllow
	// EffectDeny means the rule refuses the destination. A deny at the
	// immutable floor outranks every allow, whatever its source.
	EffectDeny
)

// Source names which policy surface produced a decision.
//
// These are deliberately NOT interchangeable. A content-scanning exemption is
// not an egress authorization, and flattening them into a single "authorized"
// boolean is how an exemption written for one purpose silently becomes
// permission for another.
type Source int

const (
	// SourceNone is the zero value: no rule matched.
	SourceNone Source = iota
	// SourceImmutableFloor is the non-overridable deny for cloud metadata,
	// link-local, multicast and unspecified targets. Nothing overrides it.
	SourceImmutableFloor
	// SourceTrustedDomain is the portless `trusted_domains` hostname
	// exemption. It rejects IP literals but is broad across ports.
	SourceTrustedDomain
	// SourceIPAllowlist is the portless `ssrf.ip_allowlist` CIDR exemption.
	SourceIPAllowlist
	// SourceBlocklist is the domain blocklist, a host-wide deny.
	SourceBlocklist
	// SourceStrictAllowlist is the strict-mode positive allowlist.
	SourceStrictAllowlist
	// SourceGuardGrant is an exact protocol/host/port guard grant. No such
	// grant exists yet; the constant is declared so the decision type does
	// not have to change shape when grants arrive.
	SourceGuardGrant
)

// Decision is the outcome of evaluating one rule against one destination.
//
// It carries provenance, not just a verdict, because both the audit record and
// the operator-facing block explanation have to be able to say WHICH rule
// decided and HOW broadly it applied. An operator who cannot tell an exact
// grant from a broad legacy match cannot audit their own policy, and that is
// the failure this type exists to prevent.
type Decision struct {
	Effect Effect
	Scope  Scope
	Source Source
	// Rule is the configured pattern or CIDR that matched, verbatim, for
	// audit output and the explain surface.
	Rule string
}

// Matched reports whether any rule applied at all.
func (d Decision) Matched() bool { return d.Effect != EffectNoMatch }

// String renders a scope for audit output. The zero value renders as "none"
// rather than as an empty string, so a log line can never silently omit it.
func (s Scope) String() string {
	switch s {
	case ScopeExact:
		return "exact"
	case ScopePortless:
		return "portless"
	default:
		return "none"
	}
}

// String renders an effect for audit output.
func (e Effect) String() string {
	switch e {
	case EffectAllow:
		return "allow"
	case EffectDeny:
		return "deny"
	default:
		return "no-match"
	}
}

// String renders a decision source for audit output. An unrecognized source
// renders as "unknown" rather than as a number, because an operator reading an
// audit record needs to know which policy surface decided.
func (s Source) String() string {
	switch s {
	case SourceImmutableFloor:
		return "immutable-floor"
	case SourceTrustedDomain:
		return "trusted-domain"
	case SourceIPAllowlist:
		return "ip-allowlist"
	case SourceBlocklist:
		return "blocklist"
	case SourceStrictAllowlist:
		return "strict-allowlist"
	case SourceGuardGrant:
		return "guard-grant"
	default:
		return "unknown"
	}
}

// NOTE ON THE PORTLESS/EXACT COLLISION.
//
// An earlier draft of this file carried a single boolean chokepoint deciding
// whether a portless legacy rule could authorize a destination whose port
// nobody named. That was premature and the wrong shape, for two reasons found
// in adversarial review:
//
//  1. Guard grants do not exist yet, so there is no collision to resolve and
//     no way to settle the choice by reproduction. Preserving today's HTTP
//     semantics exactly is the correct behavior for this extraction.
//  2. A boolean discards the provenance above. The decision belongs with the
//     grant type, expressed as a Decision, so a deny can name the broad legacy
//     rule that matched and the exact grant that was missing.
//
// When grants arrive, whatever resolves this must keep two invariants: an
// immutable-floor deny outranks every allow, and an over-strict outcome that
// makes a working operator config start denying without an explanation is
// treated as seriously as a fail-open, because it gets the control disabled.
