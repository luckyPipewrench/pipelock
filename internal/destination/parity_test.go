// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// This is an external test package (destination_test) on purpose. The
// extraction ends with internal/scanner importing internal/destination, and an
// in-package test that imported the scanner would then be an import cycle.
package destination_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestParseIPLiteral_ParityWithScanner pins the destination literal parser to
// the scanner's, spelling for spelling.
//
// This exists because the two are the same decision in two places, and the
// failure is silent and one-directional: if destination stops recognizing a
// spelling the scanner recognizes, that host is classified as a DNS name, the
// literal-IP floor never runs, and a direct dial to loopback or cloud metadata
// succeeds. Nothing else in the suite would notice.
//
// Verified non-vacuous: reverting destination.ParseIPLiteral to a bare
// net.ParseIP makes every alternative spelling below fail this test.
func TestParseIPLiteral_ParityWithScanner(t *testing.T) {
	spellings := []struct {
		name string
		host string
	}{
		{"dotted decimal loopback", "127.0.0.1"},
		{"hex loopback", "0x7f000001"},
		{"integer loopback", "2130706433"},
		{"octal loopback", "0177.0.0.1"},
		{"short form loopback", "127.1"},
		{"three component", "10.0.1"},
		{"metadata dotted", "169.254.169.254"},
		{"metadata hex", "0xa9fea9fe"},
		{"metadata integer", "2852039166"},
		{"rfc1918 dotted", "10.0.0.1"},
		{"ipv6 loopback", "::1"},
		{"ipv6 mapped v4", "::ffff:127.0.0.1"},
		{"ipv6 with zone", "fe80::1%eth0"},
		{"trailing dot", "127.0.0.1."},
		{"ordinary hostname", "api.vendor.example"},
		{"not an ip", "not-an-ip"},
		{"empty", ""},
	}

	for _, tc := range spellings {
		t.Run(tc.name, func(t *testing.T) {
			want := scanner.ParseIPLiteral(tc.host)
			got := destination.ParseIPLiteral(tc.host)

			if (want == nil) != (got == nil) {
				t.Fatalf("literal classification diverged for %q: scanner=%v destination=%v", tc.host, want, got)
			}
			if want != nil && !want.Equal(got) {
				t.Fatalf("literal value diverged for %q: scanner=%v destination=%v", tc.host, want, got)
			}
		})
	}
}

// TestNew_AlternativeSpellingsAreLiterals is the fail-open regression this
// whole parity concern is about: a Destination built from an alternative IPv4
// spelling must report itself as a literal, so the literal-IP floor runs.
func TestNew_AlternativeSpellingsAreLiterals(t *testing.T) {
	for _, host := range []string{"0x7f000001", "2130706433", "0177.0.0.1", "127.1"} {
		t.Run(host, func(t *testing.T) {
			d, err := destination.New(destination.NetworkTCP, host, 443)
			if err != nil {
				t.Fatalf("New(%q) returned error: %v", host, err)
			}
			if !d.IsLiteralIP() {
				t.Fatalf("New(%q) produced Host %q which is not recognized as a literal; "+
					"the literal-IP floor would be skipped for an address that reaches loopback", host, d.Host)
			}
			if d.Host != "127.0.0.1" {
				t.Fatalf("New(%q) canonicalized to %q, want 127.0.0.1", host, d.Host)
			}
		})
	}
}

// TestNew_RejectsMalformedZone covers the other direction: a zone separator on
// something that is not an IPv6 literal must be rejected, not silently
// truncated into a shorter and different host.
func TestNew_RejectsMalformedZone(t *testing.T) {
	if _, err := destination.New(destination.NetworkTCP, "evil%25foo.example", 443); err == nil {
		t.Fatal("New accepted a malformed zone separator on a DNS host; truncating at % would " +
			"normalize the token into a different destination than it names")
	}
	if _, err := destination.New(destination.NetworkTCP, "fe80::1%eth0", 443); err != nil {
		t.Fatalf("New rejected a legitimate IPv6 zone index: %v", err)
	}
}
