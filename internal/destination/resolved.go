// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"net"
	"strings"
)

// ResolvedAddr is one address a hostname resolved to, paired with the spelling
// it arrived in.
//
// Both are kept because they answer different questions. IP is what gets
// enforced against, canonicalized so two spellings of one address cannot
// disagree. Display is what the operator sees in the block reason, and it must
// stay verbatim: reporting a normalized form for an address that arrived with a
// zone index or in mapped-IPv6 form would show the operator something other
// than what their resolver actually returned.
type ResolvedAddr struct {
	IP      net.IP
	Display string
}

// ParseResolved normalizes resolver output into enforceable addresses.
//
// Each entry has its IPv6 zone index stripped and IPv4-mapped IPv6 reduced to
// its 4-byte form, so a mapped address is checked against IPv4 CIDRs rather
// than sliding past them. Entries that do not parse are dropped: they cannot be
// dialed, so they cannot be a destination.
//
// The whole set is parsed once and reused by every pass, because a floor pass
// and a CIDR pass that each re-parsed could disagree about what an address is.
func ParseResolved(ips []string) []ResolvedAddr {
	out := make([]ResolvedAddr, 0, len(ips))
	for _, raw := range ips {
		display := raw
		literal := raw
		if idx := strings.Index(literal, "%"); idx != -1 {
			literal = literal[:idx]
		}
		ip := net.ParseIP(literal)
		if ip == nil {
			continue
		}
		out = append(out, ResolvedAddr{IP: NormalizeIP(ip), Display: display})
	}
	return out
}

// FirstFloorHit returns the first address belonging to the non-overridable
// class, and whether one was found.
//
// This pass must run BEFORE any exemption, because the floor is precisely the
// set no configuration may waive. Running it after a trusted-domain or
// allowlist check would let an exemption authorize a cloud-metadata endpoint.
func FirstFloorHit(addrs []ResolvedAddr) (ResolvedAddr, bool) {
	for _, a := range addrs {
		if IsNonOverridableSSRFTarget(a.IP) {
			return a, true
		}
	}
	return ResolvedAddr{}, false
}

// FirstInternalHit returns the first address inside any of the supplied CIDRs
// that is not exempted by allowlisted, and whether one was found.
//
// allowlisted is a callback rather than a slice so the caller keeps ownership of
// exemption policy; this package decides containment, not trust. A nil callback
// means nothing is exempt, which is the fail-closed reading.
func FirstInternalHit(addrs []ResolvedAddr, cidrs []*net.IPNet, allowlisted func(net.IP) bool) (ResolvedAddr, bool) {
	for _, a := range addrs {
		for _, cidr := range cidrs {
			if cidr == nil || !cidr.Contains(a.IP) {
				continue
			}
			if allowlisted != nil && allowlisted(a.IP) {
				continue
			}
			return a, true
		}
	}
	return ResolvedAddr{}, false
}
