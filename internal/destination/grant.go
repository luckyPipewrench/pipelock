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
// grant naming a cloud-metadata, link-local, multicast, or unspecified IP
// literal is rejected at construction time, and the evaluator re-checks at
// decision time as defense in depth. Hostname resolution and dial-time address
// enforcement belong to the consuming scanner and dialer; a GrantSet does not
// resolve names.
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
	if isFloorHost(dest.Host) {
		return Grant{}, fmt.Errorf("%w: %s", ErrGrantFloorViolation, dest.String())
	}
	return Grant{dest: dest}, nil
}

// isFloorHost reports whether host is an IP literal on the immutable SSRF
// floor. DNS names are resolved and checked by the consuming scanner and
// dialer, not by this transport-neutral value type.
func isFloorHost(host string) bool {
	ip := ParseIPLiteral(host)
	return ip != nil && IsNonOverridableSSRFTarget(ip)
}

// GrantSet is an immutable collection of grants built through a validating
// constructor. An empty set authorizes nothing.
type GrantSet struct {
	byKey map[string]Grant
}

// NewGrantSet validates and builds a grant set. A single malformed or
// floor-violating entry fails the entire set; partial application would leave
// the operator unable to reason about which grants are live. Duplicate exact
// destinations collapse to one entry.
func NewGrantSet(grants ...Grant) (GrantSet, error) {
	if len(grants) == 0 {
		return GrantSet{}, nil
	}
	m := make(map[string]Grant, len(grants))
	for i, g := range grants {
		validated, err := NewGrant(g.dest.Network, g.dest.Host, g.dest.Port)
		if err != nil {
			return GrantSet{}, fmt.Errorf("destination: invalid grant set entry %d: %w", i, err)
		}
		m[validated.dest.String()] = validated
	}
	return GrantSet{byKey: m}, nil
}

// Len returns the number of grants in the set.
func (gs GrantSet) Len() int { return len(gs.byKey) }

// Contains reports whether the exact destination is authorized: an exact
// grant exists and the destination is not on the immutable SSRF floor. Like
// Evaluate, it enforces the floor even if a hand-built GrantSet contains a
// grant for a floor address.
func (gs GrantSet) Contains(d Destination) bool {
	return gs.Evaluate(d).Effect == EffectAllow
}

// Evaluate checks a destination against the grant set and returns a Decision.
//
// The immutable floor is checked FIRST: a destination whose host is an IP
// literal on the floor is denied regardless of any grant. This is defense in
// depth — NewGrantSet rejects floor addresses, but a hand-built GrantSet must
// not silently authorize metadata. A consuming scanner and dialer must apply
// the same floor to resolved addresses before connecting; Evaluate does not
// perform DNS resolution.
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
	if isFloorHost(d.Host) {
		return Decision{
			Effect: EffectDeny,
			Scope:  ScopeExact,
			Source: SourceImmutableFloor,
			Rule:   "non-overridable SSRF target",
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
