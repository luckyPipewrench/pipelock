// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"fmt"
)

// Grant is a runtime-only authorization for a single exact destination: one
// network, one normalized host (or canonical IP literal), one port. No
// wildcards, no CIDRs, no port ranges. The zero value is not valid.
//
// A grant can NEVER override the immutable floor. An attempt to construct a
// grant naming a cloud-metadata, link-local, multicast, or unspecified address
// is rejected at construction time, and the evaluator re-checks at decision
// time as defense in depth.
type Grant struct {
	dest Destination
}

// Destination returns the exact target this grant authorizes.
func (g Grant) Destination() Destination { return g.dest }

// String renders the grant for audit output.
func (g Grant) String() string { return g.dest.String() }

// ErrGrantFloorViolation is returned when a grant names an address that the
// immutable floor would deny. Accepting such a grant would be misleading:
// the grant could never actually authorize the destination.
var ErrGrantFloorViolation = fmt.Errorf("destination: grant targets a non-overridable address")

// NewGrant validates and constructs a single grant. It reuses destination.New
// for normalization and field validation, then checks that the target does not
// fall on the immutable SSRF floor.
func NewGrant(network Network, host string, port uint16) (Grant, error) {
	dest, err := New(network, host, port)
	if err != nil {
		return Grant{}, fmt.Errorf("destination: invalid grant: %w", err)
	}
	if ip := ParseIPLiteral(dest.Host); ip != nil {
		if IsNonOverridableSSRFTarget(ip) {
			return Grant{}, fmt.Errorf("%w: %s", ErrGrantFloorViolation, dest.String())
		}
	}
	return Grant{dest: dest}, nil
}

// GrantSet is an immutable collection of grants built through a validating
// constructor. An empty set authorizes nothing.
type GrantSet struct {
	byKey map[string]Grant
}

// NewGrantSet builds a grant set, rejecting any malformed or floor-violating
// entry. A single bad entry fails the entire set — partial application would
// leave the operator unable to reason about which grants are live.
func NewGrantSet(grants ...Grant) GrantSet {
	if len(grants) == 0 {
		return GrantSet{}
	}
	m := make(map[string]Grant, len(grants))
	for _, g := range grants {
		m[g.dest.String()] = g
	}
	return GrantSet{byKey: m}
}

// Len returns the number of grants in the set.
func (gs GrantSet) Len() int { return len(gs.byKey) }

// Contains reports whether the set holds a grant for the exact destination.
func (gs GrantSet) Contains(d Destination) bool {
	if gs.byKey == nil {
		return false
	}
	_, ok := gs.byKey[d.String()]
	return ok
}

// Evaluate checks a destination against the grant set and returns a Decision.
//
// The immutable floor is checked FIRST: a destination whose IP is
// non-overridable is denied regardless of any grant. This is defense in depth
// — NewGrant already rejects floor addresses, but a hand-built or
// deserialized grant set must not silently authorize metadata.
//
// If the floor does not apply, the set is checked for an exact match. Only an
// exact network+host+port match produces EffectAllow; there is no fallback to
// a broader scope.
//
// A destination that is not in the set returns EffectNoMatch (not EffectDeny),
// because the absence of a grant is not a policy denial — other rules
// (trusted_domains, ip_allowlist) may still authorize it.
func (gs GrantSet) Evaluate(d Destination) Decision {
	// Defense-in-depth floor check: even if a grant somehow exists for a
	// floor address (construction should prevent this), deny unconditionally.
	if ip := ParseIPLiteral(d.Host); ip != nil {
		if IsNonOverridableSSRFTarget(ip) {
			return Decision{
				Effect: EffectDeny,
				Scope:  ScopeExact,
				Source: SourceImmutableFloor,
				Rule:   "non-overridable SSRF target",
			}
		}
	}
	if gs.byKey == nil {
		return Decision{}
	}
	if g, ok := gs.byKey[d.String()]; ok {
		return Decision{
			Effect: EffectAllow,
			Scope:  ScopeExact,
			Source: SourceGuardGrant,
			Rule:   g.dest.String(),
		}
	}
	return Decision{}
}
