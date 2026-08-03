// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"fmt"
	"net"
	"testing"
)

// TestParseIPLiteral_Spellings covers every alternative IPv4 form the parser
// accepts, and the malformed inputs it must refuse.
//
// The accept cases matter because each is an address that really reaches its
// target, so failing to recognize one means the literal floor never runs for
// it. The reject cases matter for the opposite reason: claiming a token is an
// address when it is not would route a legitimate hostname through
// address-comparison instead of domain-comparison.
func TestParseIPLiteral_Spellings(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // empty means "not an IP literal"
	}{
		{name: "dotted decimal", in: "127.0.0.1", want: "127.0.0.1"},
		{name: "hex whole", in: "0x7f000001", want: "127.0.0.1"},
		{name: "hex whole uppercase prefix", in: "0X7f000001", want: "127.0.0.1"},
		{name: "integer whole", in: "2130706433", want: "127.0.0.1"},
		{name: "two component short form", in: "127.1", want: "127.0.0.1"},
		{name: "three component", in: "10.0.1", want: "10.0.0.1"},
		{name: "three component short form packs the last as 16 bits", in: "1.2.3", want: "1.2.0.3"},
		{name: "octal dotted", in: "0177.0.0.1", want: "127.0.0.1"},
		{name: "hex dotted octet", in: "0x7f.0.0.1", want: "127.0.0.1"},
		{name: "metadata hex", in: "0xa9fea9fe", want: "169.254.169.254"},
		{name: "trailing dot", in: "127.0.0.1.", want: "127.0.0.1"},
		{name: "ipv6", in: "::1", want: "::1"},
		{name: "ipv6 zone stripped", in: "fe80::1%eth0", want: "fe80::1"},
		{name: "ipv4-mapped ipv6", in: "::ffff:10.0.0.1", want: "10.0.0.1"},

		{name: "ordinary hostname", in: "api.vendor.example"},
		{name: "empty", in: ""},
		{name: "not hex", in: "0xzzzz"},
		{name: "empty hex digits", in: "0x"},
		{name: "octet overflows 8 bits", in: "999.0.0.1"},
		{name: "too many components", in: "1.2.3.4.5"},
		{name: "single component that is not numeric", in: "localhost"},

		{name: "empty component", in: "10..1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseIPLiteral(tc.in)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("ParseIPLiteral(%q) = %v, want nil", tc.in, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("ParseIPLiteral(%q) = nil, want %s; an unrecognized spelling "+
					"skips the literal floor for an address that still reaches its target",
					tc.in, tc.want)
			}
			if !got.Equal(net.ParseIP(tc.want)) {
				t.Fatalf("ParseIPLiteral(%q) = %v, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestIsCloudMetadataIP covers every provider endpoint and both address
// families. A provider address missing here is a metadata endpoint that reaches
// an agent, which is the credential-theft case the floor exists to stop.
func TestIsCloudMetadataIP(t *testing.T) {
	metadata := []string{
		"169.254.169.254", // AWS / Azure / GCP IMDS
		"168.63.129.16",   // Azure WireServer
		"100.100.100.200", // Alibaba Cloud ECS
		"fd00:ec2::254",   // AWS IMDSv6
	}
	for _, s := range metadata {
		if !IsCloudMetadataIP(net.ParseIP(s)) {
			t.Errorf("IsCloudMetadataIP(%s) = false, want true", s)
		}
	}

	notMetadata := []string{"93.184.216.34", "10.0.0.1", "127.0.0.1", "::1", "169.254.1.1"}
	for _, s := range notMetadata {
		if IsCloudMetadataIP(net.ParseIP(s)) {
			t.Errorf("IsCloudMetadataIP(%s) = true, want false", s)
		}
	}

	if IsCloudMetadataIP(nil) {
		t.Error("IsCloudMetadataIP(nil) = true, want false")
	}
	// A mapped spelling reaches the same endpoint, so it must classify the same.
	if !IsCloudMetadataIP(net.ParseIP("::ffff:169.254.169.254")) {
		t.Error("mapped IPv6 metadata address must still classify as metadata")
	}
}

// TestIsNonOverridableSSRFTarget pins exactly which classes no configuration
// may waive, in both directions. Over-including here would break the
// allowlist's intended use; under-including would make the floor waivable.
func TestIsNonOverridableSSRFTarget(t *testing.T) {
	nonOverridable := []string{
		"169.254.169.254", // metadata
		"169.254.1.1",     // link-local unicast
		"224.0.0.1",       // multicast
		"ff02::1",         // link-local multicast
		"ff01::1",         // interface-local multicast
		"0.0.0.0",         // unspecified
		"::",              // unspecified v6
	}
	for _, s := range nonOverridable {
		if !IsNonOverridableSSRFTarget(net.ParseIP(s)) {
			t.Errorf("IsNonOverridableSSRFTarget(%s) = false, want true", s)
		}
	}

	// Loopback and ordinary private ranges are deliberately overridable:
	// exempting a specific internal service is what the allowlist is for.
	overridable := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "fd00::1", "93.184.216.34"}
	for _, s := range overridable {
		if IsNonOverridableSSRFTarget(net.ParseIP(s)) {
			t.Errorf("IsNonOverridableSSRFTarget(%s) = true, want false; loopback and "+
				"ordinary private ranges must stay exemptable", s)
		}
	}

	if IsNonOverridableSSRFTarget(nil) {
		t.Error("IsNonOverridableSSRFTarget(nil) = true, want false")
	}
}

// TestNormalizeIPAndHost covers the normalization helpers directly.
func TestNormalizeIPAndHost(t *testing.T) {
	if NormalizeIP(nil) != nil {
		t.Error("NormalizeIP(nil) must be nil")
	}
	if got := NormalizeIP(net.ParseIP("::ffff:10.0.0.1")); got.String() != "10.0.0.1" {
		t.Errorf("mapped IPv6 normalized to %q, want 10.0.0.1", got)
	}
	if got := NormalizeHost("  API.Vendor.Example.  "); got != "api.vendor.example" {
		t.Errorf("NormalizeHost = %q, want api.vendor.example", got)
	}
	if got := NormalizeHost("FE80::1%ETH0"); got != "fe80::1" {
		t.Errorf("NormalizeHost = %q, want fe80::1", got)
	}
}

// TestParsePort pins the refusals. Port 0 is the any-port wildcard at the
// syscall layer and must never stand in for a concrete destination.
func TestParsePort(t *testing.T) {
	if p, err := ParsePort(" 443 "); err != nil || p != 443 {
		t.Errorf("ParsePort(443) = %d, %v", p, err)
	}
	for _, bad := range []string{"", "0", "65536", "-1", "abc", "44 3"} {
		if _, err := ParsePort(bad); err == nil {
			t.Errorf("ParsePort(%q) succeeded, want an error", bad)
		}
	}
}

// TestParseHostPort covers the authority form used by CONNECT and by
// net.SplitHostPort callers.
func TestParseHostPort(t *testing.T) {
	d, err := ParseHostPort(NetworkTCP, "api.vendor.example:8443")
	if err != nil {
		t.Fatalf("ParseHostPort: %v", err)
	}
	if d.Host != "api.vendor.example" || d.Port != 8443 {
		t.Fatalf("got %s, want api.vendor.example:8443", d)
	}

	// IPv6 authorities must be bracketed, exactly as the standard library
	// requires, and the bracketed form must round-trip through String().
	d6, err := ParseHostPort(NetworkTCP, "[::1]:443")
	if err != nil {
		t.Fatalf("ParseHostPort ipv6: %v", err)
	}
	if d6.Host != "::1" {
		t.Fatalf("ipv6 host = %q, want ::1", d6.Host)
	}
	if _, _, err := net.SplitHostPort(d6.String()[len("tcp://"):]); err != nil {
		t.Fatalf("String() did not round-trip through SplitHostPort: %v", err)
	}

	for _, bad := range []string{"no-port", "host:0", "host:abc", ""} {
		if _, err := ParseHostPort(NetworkTCP, bad); err == nil {
			t.Errorf("ParseHostPort(%q) succeeded, want an error", bad)
		}
	}
}

// TestDestinationHelpers covers the small predicates on the type itself.
func TestDestinationHelpers(t *testing.T) {
	lit, err := New(NetworkTCP, "10.0.0.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !lit.IsLiteralIP() {
		t.Error("10.0.0.1 must report as a literal")
	}
	if ip, ok := lit.IP(); !ok || ip.String() != "10.0.0.1" {
		t.Errorf("IP() = %v, %v", ip, ok)
	}

	dns, err := New(NetworkTCP, "api.vendor.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	if dns.IsLiteralIP() {
		t.Error("a hostname must not report as a literal")
	}
	if _, ok := dns.IP(); ok {
		t.Error("IP() must report false for a hostname")
	}
	if dns.Equal(lit) {
		t.Error("different destinations must not compare equal")
	}
	if !dns.Equal(dns) {
		t.Error("a destination must equal itself")
	}
	// All three fields participate: a matching host alone is not a match.
	other, _ := New(NetworkTCP, "api.vendor.example", 8443)
	if dns.Equal(other) {
		t.Error("same host on a different port must not compare equal")
	}
	if !NetworkTCP.Valid() || !NetworkUDP.Valid() || Network("sctp").Valid() {
		t.Error("Network.Valid did not classify correctly")
	}
	if NetworkTCP.String() != "tcp" {
		t.Error("Network.String")
	}
}

// TestMatchesDomainList covers the list helper.
func TestMatchesDomainList(t *testing.T) {
	patterns := []string{"*.vendor.example", "exact.example"}
	for _, h := range []string{"api.vendor.example", "vendor.example", "exact.example"} {
		if !MatchesDomainList(h, patterns) {
			t.Errorf("MatchesDomainList(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"vendor.example.evil", "other.example", ""} {
		if MatchesDomainList(h, patterns) {
			t.Errorf("MatchesDomainList(%q) = true, want false", h)
		}
	}
}

// TestHandBuiltDestinationStillFailsClosed covers the second door into the
// literal-floor fail-open.
//
// Destination has exported fields, so a caller can build one without New. If
// the predicates used net.ParseIP, a hand-built Destination whose Host is an
// alternative IPv4 spelling would report as a DNS name, the literal-IP floor
// would never run, and the dial would still reach the address it encodes.
func TestHandBuiltDestinationStillFailsClosed(t *testing.T) {
	for _, host := range []string{"0x7f000001", "2130706433", "0177.0.0.1", "127.1"} {
		t.Run(host, func(t *testing.T) {
			d := Destination{Network: NetworkTCP, Host: host, Port: 443}
			if !d.IsLiteralIP() {
				t.Fatalf("hand-built Destination{Host: %q} reports as a DNS name; the "+
					"literal-IP floor would be skipped for an address that reaches loopback", host)
			}
			ip, ok := d.IP()
			if !ok || ip.String() != "127.0.0.1" {
				t.Fatalf("IP() = %v, %v; want 127.0.0.1", ip, ok)
			}
		})
	}
}

// TestNew_RejectsUnsafeHostCharacters covers log-record forgery.
//
// Destination.String() feeds audit output and the operator explain surface, so
// a host containing a newline splits one record into two. Embedded whitespace
// is never valid in a real host and means the token was never one destination.
func TestNew_RejectsUnsafeHostCharacters(t *testing.T) {
	bad := []string{
		"good.example\nfake-audit-line",
		"good.example\rfake",
		"host name.example",
		"host\texample",
		"host\x00.example",
		"host\x7f.example",
	}
	for _, host := range bad {
		t.Run(fmt.Sprintf("%q", host), func(t *testing.T) {
			if _, err := New(NetworkTCP, host, 443); err == nil {
				t.Fatalf("New(%q) was accepted; an embedded control character or space "+
					"reaches audit output through String() and can forge a log record", host)
			}
		})
	}
	// A legitimate host with surrounding whitespace is still fine: it is
	// trimmed, not rejected. Over-strictness here would deny real destinations.
	if _, err := New(NetworkTCP, "  api.vendor.example  ", 443); err != nil {
		t.Errorf("New rejected a legitimate host with surrounding whitespace: %v", err)
	}
}

// TestNew_ErrorPaths covers the remaining constructor refusals.
func TestNew_ErrorPaths(t *testing.T) {
	if _, err := New(Network("sctp"), "host.example", 443); err == nil {
		t.Error("unrecognized network must be refused")
	}
	if _, err := New(NetworkTCP, "", 443); err == nil {
		t.Error("empty host must be refused")
	}
	if _, err := New(NetworkTCP, "   ", 443); err == nil {
		t.Error("whitespace-only host must be refused")
	}
	if _, err := New(NetworkTCP, "host.example", 0); err == nil {
		t.Error("port 0 must be refused")
	}
}

// TestMatchDomain_IPLiteralsDoNotWildcard covers the documented IP-literal rule.
// The dots in an address are not domain separators, so a wildcard pattern must
// never expand across them and authorize an unrelated address.
func TestMatchDomain_IPLiteralsDoNotWildcard(t *testing.T) {
	if MatchDomain("192.168.1.1", "*.168.1.1") {
		t.Error("a wildcard pattern must not match an IP literal by suffix")
	}
	if !MatchDomain("192.168.1.1", "192.168.1.1") {
		t.Error("an IP literal must match itself exactly")
	}
	if MatchDomain("192.168.1.1", "168.1.1") {
		t.Error("an IP literal must not match a suffix of itself")
	}
}

// TestDecisionStrings pins the audit renderings, including the zero values,
// which must never render as an empty string in a log record.
func TestDecisionStrings(t *testing.T) {
	if ScopeNone.String() != "none" || ScopeExact.String() != "exact" || ScopePortless.String() != "portless" {
		t.Error("Scope.String")
	}
	if EffectNoMatch.String() != "no-match" || EffectAllow.String() != "allow" || EffectDeny.String() != "deny" {
		t.Error("Effect.String")
	}
	if SourceNone.String() != "unknown" || SourceGuardGrant.String() != "guard-grant" ||
		SourceImmutableFloor.String() != "immutable-floor" {
		t.Error("Source.String")
	}
	if (Decision{}).Matched() {
		t.Error("a zero Decision must not report as matched")
	}
	if !(Decision{Effect: EffectDeny}).Matched() {
		t.Error("a deny decision must report as matched")
	}
}
