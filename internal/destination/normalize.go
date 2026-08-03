// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// Errors returned by the parsing helpers. Callers match on these rather than on
// message text so a wording change cannot silently alter a caller's branch.
var (
	// ErrEmptyHost is returned when a destination carries no host at all.
	ErrEmptyHost = errors.New("destination: empty host")
	// ErrInvalidPort is returned for a port that is absent, non-numeric, or
	// outside 1-65535. Port 0 is rejected: it is the "any port" wildcard at
	// the syscall layer and must never stand in for a concrete destination.
	ErrInvalidPort = errors.New("destination: invalid port")
	// ErrInvalidNetwork is returned for a transport this package does not
	// recognize. An unnamed transport fails closed rather than defaulting.
	ErrInvalidNetwork = errors.New("destination: invalid network")
	// ErrInvalidHost is returned for a host carrying characters that cannot
	// appear in a real destination: control characters, embedded whitespace,
	// or a zone separator on something that is not an IPv6 literal.
	ErrInvalidHost = errors.New("destination: invalid host")
)

// hasUnsafeHostChars reports whether a host token carries a character that
// cannot legitimately appear in a hostname or address literal.
//
// This is not cosmetic. Destination.String() feeds audit output and the
// operator explain surface, so a host containing a newline splits one record
// into two and lets an attacker-influenced hostname forge a log line. Embedded
// whitespace is rejected for the same reason: it is never valid in a real host
// and its presence means the token was never a single destination.
func hasUnsafeHostChars(host string) bool {
	for _, r := range host {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// NormalizeHost canonicalizes a host token for comparison.
//
// It lowercases, trims surrounding whitespace, drops a single trailing root dot
// and strips an IPv6 zone index. It deliberately does NOT resolve, punycode, or
// rewrite alternative IPv4 spellings; that canonicalization has its own entry
// point below so a caller can see, at the call site, that a rewrite happened.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	host = stripIPv6Zone(host)
	return strings.ToLower(host)
}

// NormalizeIP returns a canonical form of an address so two spellings of the
// same address compare and hash identically. IPv4 is reduced to its 4-byte
// form, which also collapses IPv4-mapped IPv6 onto the address it actually
// reaches — an alternate spelling must not evade a floor check.
func NormalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// stripIPv6Zone removes a scope identifier ("fe80::1%eth0" -> "fe80::1"). The
// zone names a local interface, not a different destination, so it must not
// make an address look distinct from the one being enforced against.
func stripIPv6Zone(host string) string {
	if idx := strings.Index(host, "%"); idx != -1 {
		return host[:idx]
	}
	return host
}

// ParsePort converts a port token to a concrete port number.
//
// Empty, non-numeric, negative, zero and out-of-range values are all rejected
// rather than defaulted. A caller that knows a scheme default resolves it
// before calling; leaving that to this function would let an unknown port
// quietly become 443 and vouch for a destination nobody scanned.
func ParsePort(port string) (uint16, error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return 0, fmt.Errorf("%w: empty", ErrInvalidPort)
	}
	n, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrInvalidPort, port)
	}
	if n == 0 || n > 65535 {
		return 0, fmt.Errorf("%w: %d out of range 1-65535", ErrInvalidPort, n)
	}
	return uint16(n), nil
}

// New builds a normalized Destination from its parts, rejecting anything it
// cannot name exactly. Every field is validated: this is the only constructor
// that should be used to reach an evaluator, so an unvalidated destination
// cannot exist further in.
func New(network Network, host string, port uint16) (Destination, error) {
	if !network.Valid() {
		return Destination{}, fmt.Errorf("%w: %q", ErrInvalidNetwork, string(network))
	}
	if rejectMalformedZone(strings.TrimSpace(host)) {
		return Destination{}, fmt.Errorf("%w: zone separator on non-IPv6 host %q", ErrEmptyHost, host)
	}
	host = NormalizeHost(host)
	if host == "" {
		return Destination{}, ErrEmptyHost
	}
	if hasUnsafeHostChars(host) {
		return Destination{}, fmt.Errorf("%w: control or whitespace character in %q", ErrInvalidHost, host)
	}
	if port == 0 {
		return Destination{}, fmt.Errorf("%w: 0", ErrInvalidPort)
	}
	// A literal address is stored in its canonical string form so that two
	// spellings of one address produce one Host value, and so IsLiteralIP
	// cannot disagree with what the floor check will later parse.
	//
	// This uses ParseIPLiteral, not net.ParseIP, because the alternative IPv4
	// spellings (0x7f000001, 2130706433, 0177.0.0.1) still reach the address
	// they encode. Classifying one of those as a DNS name would skip the
	// literal-IP floor and let a direct dial to loopback or metadata through.
	if ip := ParseIPLiteral(host); ip != nil {
		host = ip.String()
	}
	return Destination{Network: network, Host: host, Port: port}, nil
}

// rejectMalformedZone reports whether a host token carries a zone separator
// that cannot legitimately be there. A zone index is only meaningful on an
// IPv6 literal; silently truncating "evil%25foo.example" to "evil" would let
// one token normalize into a different destination than it names.
func rejectMalformedZone(raw string) bool {
	idx := strings.Index(raw, "%")
	if idx == -1 {
		return false
	}
	return net.ParseIP(stripIPv6Zone(raw)) == nil
}

// ParseHostPort builds a Destination from a "host:port" authority, the form
// produced by net.SplitHostPort and by a CONNECT request line. IPv6 authorities
// must be bracketed, exactly as the standard library requires.
func ParseHostPort(network Network, hostPort string) (Destination, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(hostPort))
	if err != nil {
		return Destination{}, fmt.Errorf("destination: parse %q: %w", hostPort, err)
	}
	parsedPort, err := ParsePort(port)
	if err != nil {
		return Destination{}, err
	}
	return New(network, host, parsedPort)
}
