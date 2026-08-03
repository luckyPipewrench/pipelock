// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package destination provides a transport-neutral representation of a network
// destination and the verdict machinery that decides whether it may be reached.
//
// Before this package existed, every destination decision was reachable only
// through a hostname string that had been recovered from an http/https URL. A
// non-HTTP target therefore had to invent a URL, which the URL scanner rejects
// outright at its scheme check. Guard grants need to authorize an exact
// protocol, host and port, so the decision surface has to be expressible
// without a URL at all.
//
// This package deliberately does not change any existing HTTP verdict. It is
// the shared vocabulary; the scanner and the proxy dialer remain the callers
// that apply it.
package destination

import (
	"net"
	"strconv"
	"strings"
)

// Network is the transport a destination is reached over. It is a distinct
// type rather than a bare string so a caller cannot accidentally pass a scheme
// ("https") where a transport ("tcp") is required; the two are different
// vocabularies and conflating them is what forced the synthetic-URL workaround.
type Network string

const (
	// NetworkTCP is a stream transport. Every destination Pipelock currently
	// mediates is TCP; UDP and QUIC are named here only so the type is not
	// reshaped later, not because they are supported.
	NetworkTCP Network = "tcp"
	// NetworkUDP is a datagram transport. Reserved: no evaluator path grants
	// it today, and an unrecognized network must never be treated as TCP.
	NetworkUDP Network = "udp"
)

// String returns the canonical lowercase transport token.
func (n Network) String() string { return string(n) }

// Valid reports whether the network is one this package recognizes.
//
// This is deliberately a closed set. An unknown transport must fail closed at
// the call site rather than degrade into a default, because a destination whose
// transport we cannot name is a destination we cannot claim to have mediated.
func (n Network) Valid() bool {
	switch n {
	case NetworkTCP, NetworkUDP:
		return true
	default:
		return false
	}
}

// Destination is an exact, already-normalized network target.
//
// Host is either a canonical lowercase DNS name with no trailing dot, or the
// string form of a canonical IP literal. Port is the concrete numeric port; it
// is never a scheme default that the caller left implicit, because the whole
// point of carrying it is that host:443 must not vouch for host:6443.
type Destination struct {
	Network Network
	Host    string
	Port    uint16
}

// IsLiteralIP reports whether Host is an IP literal rather than a DNS name.
// A literal target is enforced directly against the floor, the internal CIDRs
// and the IP allowlist; DNS never influences a literal verdict.
// It uses ParseIPLiteral rather than net.ParseIP because Destination has
// exported fields, so a caller can build one without going through New. A
// hand-built Destination{Host: "0x7f000001"} would otherwise report as a DNS
// name, the literal-IP floor would never run, and the dial would still reach
// 127.0.0.1. For values produced by New this changes nothing, since New already
// stores the canonical form.
func (d Destination) IsLiteralIP() bool {
	return ParseIPLiteral(d.Host) != nil
}

// IP returns the parsed literal address and whether Host was a literal at all.
// The returned address is 4-byte-normalized for IPv4 so that comparisons and
// map keys agree regardless of which spelling produced it.
func (d Destination) IP() (net.IP, bool) {
	ip := ParseIPLiteral(d.Host)
	if ip == nil {
		return nil, false
	}
	return ip, true
}

// String renders the destination in a stable, log-safe form. IPv6 hosts are
// bracketed so the result round-trips through net.SplitHostPort.
func (d Destination) String() string {
	host := d.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return string(d.Network) + "://" + host + ":" + strconv.FormatUint(uint64(d.Port), 10)
}

// Equal reports whether two destinations name the same exact target. All three
// fields participate: a matching host alone is not a matching destination.
func (d Destination) Equal(other Destination) bool {
	return d.Network == other.Network && d.Host == other.Host && d.Port == other.Port
}
