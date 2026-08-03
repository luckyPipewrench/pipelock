// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"net"
	"strconv"
	"strings"
)

// ParseIPLiteral parses a host token as an IP literal, accepting the
// alternative IPv4 spellings that resolvers and connect(2) honor but
// net.ParseIP rejects: hex (0x7f000001), integer (2130706433), octal
// (0177.0.0.1), and short inet_aton forms (127.1, 10.0.1).
//
// This matters because the literal-IP floor is what blocks a direct dial to
// loopback, RFC1918 and metadata addresses. A caller that only used
// net.ParseIP would classify 0x7f000001 as a DNS name, skip the literal floor
// entirely, and reach 127.0.0.1 anyway. That is a fail-open, so every
// destination that claims to be "not a literal" must have been tested against
// these forms and not merely against dotted-decimal.
//
// Returns nil when the token is not an IP literal in any spelling.
func ParseIPLiteral(host string) net.IP {
	host = strings.TrimSpace(host)
	host = stripIPv6Zone(host)
	host = strings.TrimSuffix(host, ".")
	ip := net.ParseIP(host)
	if ip == nil {
		ip = parseAlternativeIP(host)
	}
	return NormalizeIP(ip)
}

// parseAlternativeIP handles the non-dotted-decimal IPv4 spellings. Standard
// dotted-decimal is deliberately left to net.ParseIP so there is exactly one
// parser for the common case.
func parseAlternativeIP(host string) net.IP {
	if host == "" {
		return nil
	}

	if strings.Contains(host, ".") {
		return parseDottedInetAton(host)
	}

	// Bare integer or hex form: 2130706433 or 0x7f000001.
	value, ok := parseInetAtonComponent(host, 32)
	if !ok {
		return nil
	}
	// #nosec G115 -- parseInetAtonComponent caps the value at 32 bits.
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

// parseDottedInetAton handles the 2-, 3- and 4-component dotted forms. Two
// components are A.B where B is 24 bits; three are A.B.C where C is 16 bits.
func parseDottedInetAton(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) < 2 || len(parts) > net.IPv4len {
		return nil
	}

	if len(parts) < net.IPv4len {
		widths := []int{8, 24}
		if len(parts) == 3 {
			widths = []int{8, 8, 16}
		}
		values := make([]uint64, len(parts))
		for i, part := range parts {
			value, ok := parseInetAtonComponent(part, widths[i])
			if !ok {
				return nil
			}
			values[i] = value
		}
		packed := values[0] << 24
		if len(values) == 2 {
			packed |= values[1]
		} else {
			packed |= values[1]<<16 | values[2]
		}
		// #nosec G115 -- the per-component bit limits prove packed fits in 32 bits.
		return net.IPv4(byte(packed>>24), byte(packed>>16), byte(packed>>8), byte(packed))
	}

	octets := make([]byte, net.IPv4len)
	for i, part := range parts {
		val, ok := parseInetAtonComponent(part, 8)
		if !ok {
			return nil
		}
		octets[i] = byte(val & 0xFF)
	}
	// Only claim the token when at least one octet used non-standard notation;
	// plain dotted-decimal already parsed via net.ParseIP above.
	for _, part := range parts {
		if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") ||
			(len(part) > 1 && part[0] == '0' && part != "0") {
			return net.IPv4(octets[0], octets[1], octets[2], octets[3])
		}
	}
	return nil
}

// parseInetAtonComponent parses one component in decimal, octal (leading zero)
// or hex (0x prefix) and rejects anything that overflows the allowed width.
func parseInetAtonComponent(part string, bits int) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	base := 10
	digits := part
	switch {
	case strings.HasPrefix(part, "0x"), strings.HasPrefix(part, "0X"):
		base = 16
		digits = part[2:]
	case len(part) > 1 && part[0] == '0':
		base = 8
		digits = part[1:]
	}
	if digits == "" {
		return 0, false
	}
	value, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		return 0, false
	}
	if bits < 64 && value >= 1<<uint(bits) {
		return 0, false
	}
	return value, true
}
