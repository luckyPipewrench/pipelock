// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/idna"
)

// These reference implementations freeze the pre-fast-path semantics from
// 67001cf1150415b068e077b05adb20aa2a45a8ca. Keep the profile independent of the
// production helpers so both normalizer output and matching remain comparable.
var referenceHostIDNAProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.CheckHyphens(false),
)

func referenceCanonicalDomainForMatch(value string) string {
	prefix := ""
	base := value
	if strings.HasPrefix(value, "*.") {
		prefix = "*."
		base = value[2:]
	}
	if base == "" {
		return value
	}
	ascii, err := referenceHostIDNAProfile.ToASCII(base)
	if err != nil || ascii == "" {
		return value
	}
	return prefix + ascii
}

func referenceMatchDomain(hostname, pattern string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(referenceCanonicalDomainForMatch(hostname), "."))
	pattern = strings.ToLower(strings.TrimSuffix(referenceCanonicalDomainForMatch(pattern), "."))
	if net.ParseIP(hostname) != nil {
		return hostname == pattern
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		base := pattern[2:]
		return hostname == base || strings.HasSuffix(hostname, suffix)
	}
	return hostname == pattern
}

type domainMatchFixture struct {
	name  string
	value string
}

func domainMatchFixtures() []domainMatchFixture {
	return []domainMatchFixture{
		{name: "empty"},
		{name: "root", value: "."},
		{name: "two roots", value: ".."},
		{name: "ascii", value: "vendor.example"},
		{name: "subdomain", value: "api.vendor.example"},
		{name: "deep subdomain", value: "one.two.vendor.example"},
		{name: "unrelated", value: "other.example"},
		{name: "partial suffix", value: "notvendor.example"},
		{name: "uppercase", value: "VENDOR.EXAMPLE"},
		{name: "mixed case", value: "Api.Vendor.Example"},
		{name: "root dot", value: "vendor.example."},
		{name: "two root dots", value: "vendor.example.."},
		{name: "leading dot", value: ".vendor.example"},
		{name: "empty interior label", value: "api..vendor.example"},
		{name: "leading hyphen", value: "-api.vendor.example"},
		{name: "trailing hyphen", value: "api-.vendor.example"},
		{name: "double hyphen", value: "my--host.vendor.example"},
		{name: "bare hyphen", value: "-.vendor.example"},
		{name: "single label", value: "fixture"},
		{name: "long label", value: strings.Repeat("a", 64) + ".example"},
		{name: "long domain", value: strings.Repeat("fixture.", 40) + "example"},
		{name: "wildcard", value: "*.vendor.example"},
		{name: "rooted wildcard", value: "*.vendor.example."},
		{name: "double-rooted wildcard", value: "*.vendor.example.."},
		{name: "empty wildcard", value: "*."},
		{name: "bare wildcard", value: "*"},
		{name: "nested wildcard", value: "*.*.vendor.example"},
		{name: "interior wildcard", value: "api.*.example"},
		{name: "leading space", value: " vendor.example"},
		{name: "trailing space", value: "vendor.example "},
		{name: "underscore", value: "_service.vendor.example"},
		{name: "port", value: "vendor.example:443"},
		{name: "unicode", value: "bücher.example"},
		{name: "unicode subdomain", value: "api.bücher.example"},
		{name: "unicode wildcard", value: "*.bücher.example"},
		{name: "ace", value: "xn--bcher-kva.example"},
		{name: "ace subdomain", value: "api.xn--bcher-kva.example"},
		{name: "ace wildcard", value: "*.xn--bcher-kva.example"},
		{name: "uppercase ace", value: "XN--BCHER-KVA.EXAMPLE"},
		{name: "invalid ace", value: "xn--a.example"},
		{name: "empty ace", value: "xn--.example"},
		{name: "ascii ace", value: "xn--fixture-.example"},
		{name: "interior ace marker", value: "fixturexn--label.example"},
		{name: "ideographic separator", value: "vendor。example。"},
		{name: "fullwidth separator", value: "vendor．example．"},
		{name: "halfwidth separator", value: "vendor｡example｡"},
		{name: "fullwidth letters", value: "ｖｅｎｄｏｒ.example"},
		{name: "compatibility letter", value: "Kelvin.example"},
		{name: "composed unicode", value: "café.example"},
		{name: "decomposed unicode", value: "cafe\u0301.example"},
		{name: "nontransitional letter", value: "straße.example"},
		{name: "ignored character", value: "ven\u00addor.example"},
		{name: "invalid joiner", value: "bad\u200d.vendor.example"},
		{name: "partial mapping error", value: "ＡＰＩ._service.example"},
		{name: "bidi label", value: "مثال.example"},
		{name: "mixed bidi label", value: "aمثال.example"},
		{name: "invalid utf8", value: "api.\xff.example"},
		{name: "ipv4", value: "192.0.2.8"},
		{name: "ipv4 root dot", value: "192.0.2.8."},
		{name: "ipv4 wildcard suffix", value: "*.0.2.8"},
		{name: "mapped ipv4", value: "１９２.０.２.８"},
		{name: "alternative ipv4", value: "192.000.002.008"},
		{name: "ipv6", value: "2001:db8::1"},
		{name: "uppercase ipv6", value: "2001:DB8::1"},
		{name: "zoned ipv6", value: "2001:db8::1%fixture"},
		{name: "bracketed ipv6", value: "[2001:db8::1]"},
		{name: "mapped ipv6", value: "::ffff:192.0.2.8"},
	}
}

func TestCanonicalDomainForMatchReferenceParity(t *testing.T) {
	t.Parallel()
	for _, tc := range domainMatchFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, want := canonicalDomainForMatch(tc.value), referenceCanonicalDomainForMatch(tc.value); got != want {
				t.Fatalf("canonicalDomainForMatch(%q) = %q, reference %q", tc.value, got, want)
			}
		})
	}
}

func TestDomainMatchReferenceCorpusCoverage(t *testing.T) {
	t.Parallel()
	var identity, mapped, changed, invalid, partial, matches, misses int
	fixtures := domainMatchFixtures()
	for _, fixture := range fixtures {
		base := strings.TrimPrefix(fixture.value, "*.")
		if base != "" {
			if isDomainASCIIIdentity(base) {
				identity++
			} else {
				mapped++
			}
			ascii, err := referenceHostIDNAProfile.ToASCII(base)
			if err != nil {
				invalid++
				if ascii != "" && ascii != base {
					partial++
				}
			}
		}
		if referenceCanonicalDomainForMatch(fixture.value) != fixture.value {
			changed++
		}
		for _, pattern := range fixtures {
			if referenceMatchDomain(fixture.value, pattern.value) {
				matches++
			} else {
				misses++
			}
		}
	}
	for _, tc := range []struct {
		name  string
		count int
	}{
		{name: "identity fast path", count: identity},
		{name: "IDNA fallback path", count: mapped},
		{name: "mapped spelling changes", count: changed},
		{name: "conversion errors", count: invalid},
		{name: "discarded partial mappings", count: partial},
		{name: "matching pairs", count: matches},
		{name: "nonmatching pairs", count: misses},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.count == 0 {
				t.Fatal("parity corpus does not exercise this behavior")
			}
			t.Logf("reference corpus covers %d cases", tc.count)
		})
	}
}

func TestMatchDomainReferenceParity(t *testing.T) {
	t.Parallel()
	fixtures := domainMatchFixtures()
	for _, host := range fixtures {
		t.Run(host.name, func(t *testing.T) {
			t.Parallel()
			for _, pattern := range fixtures {
				if got, want := MatchDomain(host.value, pattern.value), referenceMatchDomain(host.value, pattern.value); got != want {
					t.Errorf("MatchDomain(%q, %q) = %v, reference %v", host.value, pattern.value, got, want)
				}
			}
		})
	}
}

func TestDomainMatchByteReferenceParity(t *testing.T) {
	t.Parallel()
	for value := byte(0); ; value++ {
		t.Run(fmt.Sprintf("byte_%02x", value), func(t *testing.T) {
			t.Parallel()
			part := string([]byte{value})
			for _, input := range []string{part + "api.example", "api." + part + ".example", "api.example" + part, "*." + part + ".example"} {
				if got, want := canonicalDomainForMatch(input), referenceCanonicalDomainForMatch(input); got != want {
					t.Errorf("canonicalDomainForMatch(%q) = %q, reference %q", input, got, want)
				}
				for _, pattern := range []string{input, strings.ToUpper(input), "*.example", "api.example", "other.example", ""} {
					if got, want := MatchDomain(input, pattern), referenceMatchDomain(input, pattern); got != want {
						t.Errorf("MatchDomain(%q, %q) = %v, reference %v", input, pattern, got, want)
					}
					if got, want := MatchDomain(pattern, input), referenceMatchDomain(pattern, input); got != want {
						t.Errorf("MatchDomain(%q, %q) = %v, reference %v", pattern, input, got, want)
					}
				}
			}
		})
		if value == 0xff {
			break
		}
	}
}

func TestDomainASCIIIdentity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "ascii", value: "api.vendor.example", want: true},
		{name: "digits", value: "192.0.2.8", want: true},
		{name: "hyphens", value: "my--host.example", want: true},
		{name: "empty labels", value: ".api..example..", want: true},
		{name: "uppercase", value: "API.vendor.example"},
		{name: "unicode", value: "bücher.example"},
		{name: "ace", value: "xn--bcher-kva.example"},
		{name: "interior ace", value: "api.xn--bcher-kva.example"},
		{name: "interior marker", value: "apixn--label.example"},
		{name: "punctuation", value: "_service.example"},
		{name: "invalid byte", value: "api.\xff.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDomainASCIIIdentity(tc.value); got != tc.want {
				t.Fatalf("isDomainASCIIIdentity(%q) = %v, want %v", tc.value, got, tc.want)
			}
			if tc.want && referenceCanonicalDomainForMatch(tc.value) != tc.value {
				t.Fatalf("identity subset changed %q under the reference profile", tc.value)
			}
		})
	}
}

func TestMatchDomainRequestIsolation(t *testing.T) {
	t.Parallel()
	requests := []struct {
		host    string
		pattern string
		want    bool
	}{
		{host: "api.vendor.example", pattern: "*.vendor.example", want: true},
		{host: "other.example", pattern: "*.vendor.example"},
		{host: "api.vendor.example", pattern: "*.other.example"},
		{host: "other.example", pattern: "*.other.example", want: true},
		{host: "bücher.example", pattern: "xn--bcher-kva.example", want: true},
		{host: "other.example", pattern: "xn--bcher-kva.example"},
		{host: "192.0.2.8", pattern: "*.0.2.8"},
		{host: "node.0.2.8", pattern: "*.0.2.8", want: true},
		{host: "vendor.example.", pattern: "vendor.example", want: true},
		{host: "vendor.example..", pattern: "vendor.example"},
		{host: "_service.vendor.example", pattern: "*.vendor.example", want: true},
		{host: "_service.other.example", pattern: "*.vendor.example"},
	}
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse_%v", reverse), func(t *testing.T) {
			for range 3 {
				for i := range requests {
					if reverse {
						i = len(requests) - 1 - i
					}
					tc := requests[i]
					if got := MatchDomain(tc.host, tc.pattern); got != tc.want {
						t.Fatalf("request %d: MatchDomain(%q, %q) = %v, want %v", i, tc.host, tc.pattern, got, tc.want)
					}
					if got := MatchesDomainList(tc.host, []string{"unrelated.example", tc.pattern}); got != tc.want {
						t.Fatalf("request %d: MatchesDomainList(%q, %q) = %v, want %v", i, tc.host, tc.pattern, got, tc.want)
					}
				}
			}
		})
	}
}
