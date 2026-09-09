// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// url.Parse decodes percent-escapes into URL.Path, so a decoded comparison let
// `/document%2Fd/<blob>` match an exemption written for `/document/d/`. The
// origin server sees one `document/d` segment, so that is a route the operator
// never exempted, and the opaque segment rode through the entropy gate on it.
// Matching EscapedPath keeps the exemption pinned to the literal configured
// route. Reproduced before the fix: the encoded form returned allowed=true from
// the full pipeline.
func TestPathEntropyExclusion_EncodedSeparatorDoesNotBorrowTheExemption(t *testing.T) {
	t.Parallel()

	s := pathExclusionScanner(t, config.PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
	})
	defer s.Close()

	tests := []struct {
		name      string
		rawURL    string
		wantBlock bool
		why       string
	}{
		{
			name:      "control: the literal exempted route is allowed",
			rawURL:    "https://docs.vendor.example/document/d/" + highEntropyID,
			wantBlock: false,
			why:       "without this the whole matrix could pass by exempting nothing",
		},
		{
			name:      "control: an unexempted route on the same host blocks",
			rawURL:    "https://docs.vendor.example/collect/" + highEntropyID,
			wantBlock: true,
			why:       "proves the gate is live, so a block below is not incidental",
		},
		{
			name:      "an encoded slash does not reach the exemption",
			rawURL:    "https://docs.vendor.example/document%2Fd/" + highEntropyID,
			wantBlock: true,
			why:       "the origin server sees one document/d segment, a different route",
		},
		{
			name:      "an encoded prefix character does not reach it either",
			rawURL:    "https://docs.vendor.example/%64ocument/d/" + highEntropyID,
			wantBlock: true,
			why:       "an escaped spelling of the same bytes is still not the configured route",
		},
		{
			name:      "a dot segment does not reach the exemption",
			rawURL:    "https://docs.vendor.example/document/./d/" + highEntropyID,
			wantBlock: true,
			why:       "a non-canonical spelling must fail closed, not borrow the exemption",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if blocked := !s.checkEntropy(parsed).Allowed; blocked != tt.wantBlock {
				t.Fatalf("checkEntropy(%q) blocked = %v, want %v (%s)", tt.rawURL, blocked, tt.wantBlock, tt.why)
			}
		})
	}
}

// A traversal path bypasses the entropy gate in isolation, and the full pipeline
// denies it anyway because path traversal is checked at step 3 and entropy at
// step 10.
//
// This asserts BOTH halves separately, and that matters: an earlier version of
// this test only checked the final denial, which a review round correctly called
// out as not proving anything about ordering. It does not, because if entropy
// ran first it would match the exemption and ALLOW, traversal would still deny,
// and the assertion would pass unchanged. Asserting the gate-level allow and the
// pipeline-level denial separately pins the real state: the exemption does match
// this path, and something earlier than entropy is what refuses the request. If
// either half changes, one of these fails.
func TestPathEntropyExclusion_TraversalIsDeniedByAnEarlierCheck(t *testing.T) {
	t.Parallel()

	s := pathExclusionScanner(t, config.PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
	})
	defer s.Close()

	raw := "https://docs.vendor.example/document/d/../collect/" + highEntropyID
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	// Half one: the exemption DOES match this path, so the entropy gate alone
	// allows it. This is the isolated gap, stated rather than implied.
	if res := s.checkEntropy(parsed); !res.Allowed {
		t.Fatalf("expected the entropy gate alone to allow the traversal path via the exemption, got %q", res.Reason)
	}

	// Half two: the request is still denied, by the traversal check, which runs
	// before entropy. The exemption never gets the last word.
	res := s.Scan(context.Background(), raw)
	if res.Allowed {
		t.Fatalf("a traversal path rode the exemption through the full pipeline: %q", raw)
	}
	if !strings.Contains(strings.ToLower(res.Scanner+" "+res.Reason), "traversal") {
		t.Fatalf("expected the traversal check to own this denial, got scanner=%q reason=%q", res.Scanner, res.Reason)
	}
}

// The reload candidate from the same review round: that a changed exclusion
// list would not affect enforcement because the list compiles only at
// construction. It does not survive the chain. Hot reload builds a NEW scanner
// from the new config (internal/cli/runtime/server_reload.go calls
// scanner.New(newCfg)) and Proxy.Reload atomically swaps it in, so the compiled
// list is rebuilt every reload. This asserts the property that matters at this
// layer: construction is what compiles the list, so a new config enforces it.
func TestPathEntropyExclusion_ConstructionCompilesTheCurrentList(t *testing.T) {
	t.Parallel()

	raw := "https://docs.vendor.example/document/d/" + highEntropyID
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	entry := config.PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/d/"}

	before := pathExclusionScanner(t)
	blockedBefore := !before.checkEntropy(parsed).Allowed
	before.Close()

	added := pathExclusionScanner(t, entry)
	blockedAfterAdd := !added.checkEntropy(parsed).Allowed
	added.Close()

	removed := pathExclusionScanner(t)
	blockedAfterRemove := !removed.checkEntropy(parsed).Allowed
	removed.Close()

	if !blockedBefore {
		t.Fatal("control failed: with no exclusions the route must block")
	}
	if blockedAfterAdd {
		t.Error("a scanner built with the exclusion still blocked; an added route did not take effect")
	}
	if !blockedAfterRemove {
		t.Error("a scanner built without the exclusion allowed the route; a removed route did not take effect")
	}
}

// buildPathEntropyExclusions drops an over-broad entry at the point of use, not
// only in validation, because a Config can reach the scanner without having
// been validated. That defense was incomplete: it caught an empty host and an
// empty prefix and let a bare / prefix and a cleartext scheme through, which
// are the same over-broad exemption in different spellings. These construct the
// scanner directly, bypassing Validate exactly as the gap required.
func TestPathEntropyExclusion_BuilderDropsOverBroadEntries(t *testing.T) {
	t.Parallel()

	exempted := "https://docs.vendor.example/document/d/" + highEntropyID

	// Control: a well-formed entry DOES exempt its route, so a block below
	// means the entry was dropped rather than the fixture being wrong.
	okScanner := pathExclusionScanner(t, config.PathEntropyExclusion{
		Host: "docs.vendor.example", PathPrefix: "/document/d/",
	})
	control, err := url.Parse(exempted)
	if err != nil {
		okScanner.Close()
		t.Fatalf("url.Parse: %v", err)
	}
	if res := okScanner.checkEntropy(control); !res.Allowed {
		okScanner.Close()
		t.Fatalf("control failed: a valid entry did not exempt the route (%s)", res.Reason)
	}
	okScanner.Close()

	// Each case names the URL its OWN pattern would match if the entry were
	// installed. Probing one fixed host would make the wildcard cases vacuous:
	// *.com never matches docs.vendor.example, so such a case would pass
	// whether or not the entry was dropped.
	tests := []struct {
		name   string
		entry  config.PathEntropyExclusion
		probe  string
		reason string
	}{
		{
			name:   "a bare root prefix exempts the whole host",
			entry:  config.PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/"},
			probe:  "https://docs.vendor.example/anything/" + highEntropyID,
			reason: "a / prefix is a host-wide exemption in a different spelling",
		},
		{
			name:   "a cleartext scheme must never be installed",
			entry:  config.PathEntropyExclusion{Scheme: "http", Host: "docs.vendor.example", PathPrefix: "/document/d/"},
			probe:  "http://docs.vendor.example/document/d/" + highEntropyID,
			reason: "an exemption never covers cleartext",
		},
		{
			name:   "an unknown scheme is not silently treated as https",
			entry:  config.PathEntropyExclusion{Scheme: "ftp", Host: "docs.vendor.example", PathPrefix: "/document/d/"},
			probe:  exempted,
			reason: "an unrecognized scheme must not default into the https slot",
		},
		{
			name:   "a public-suffix wildcard exempts most of the internet",
			entry:  config.PathEntropyExclusion{Host: "*.com", PathPrefix: "/document/d/"},
			probe:  "https://evil.com/document/d/" + highEntropyID,
			reason: "MatchDomain matches *.com against every .com host, so the route prefix would exempt requests far outside the intended domain",
		},
		{
			name:   "repeated trailing dots must not survive the breadth check",
			entry:  config.PathEntropyExclusion{Host: "*.com..", PathPrefix: "/document/d/"},
			probe:  "https://evil.com/document/d/" + highEntropyID,
			reason: "one TrimSuffix left *.com. whose remaining dot read as a domain label, and runtime matching then stripped it and matched every .com host",
		},
		{
			name:   "a single trailing dot is the same host and is still refused",
			entry:  config.PathEntropyExclusion{Host: "*.com.", PathPrefix: "/document/d/"},
			probe:  "https://evil.com/document/d/" + highEntropyID,
			reason: "trailing dots are DNS-equivalent, so this is *.com by another spelling",
		},
		{
			name:   "a bare dot host normalizes to nothing and is dropped",
			entry:  config.PathEntropyExclusion{Host: ".", PathPrefix: "/document/d/"},
			probe:  exempted,
			reason: "an entry that cannot name a host is dead config, and the builder claims to drop dead config",
		},
		{
			name:   "a bare wildcard host is not a scoped route",
			entry:  config.PathEntropyExclusion{Host: "*", PathPrefix: "/document/d/"},
			probe:  exempted,
			reason: "a bare wildcard names no domain at all",
		},
		{
			name:   "a wildcard in the middle is not a supported pattern",
			entry:  config.PathEntropyExclusion{Host: "docs.*.example", PathPrefix: "/document/d/"},
			probe:  exempted,
			reason: "only exact hosts and leading *. wildcards are supported",
		},
		{
			name:   "a host:port is not a hostname",
			entry:  config.PathEntropyExclusion{Host: "docs.vendor.example:443", PathPrefix: "/document/d/"},
			probe:  exempted,
			reason: "a port makes the pattern unmatchable and is refused rather than trimmed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := url.Parse(tt.probe)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.probe, err)
			}

			// Calibrate this case: with the entry dropped, the probe must be
			// blockable at all. A probe the gate would allow anyway proves
			// nothing about whether the entry was installed.
			bare := pathExclusionScanner(t)
			bareAllowed := bare.checkEntropy(parsed).Allowed
			bare.Close()
			if bareAllowed {
				t.Fatalf("probe %q is allowed with NO exclusions configured, so this case cannot detect an installed entry", tt.probe)
			}

			s := pathExclusionScanner(t, tt.entry)
			res := s.checkEntropy(parsed)
			s.Close()
			if res.Allowed {
				t.Fatalf("entry %+v was installed and exempted %q; it must be dropped (%s)", tt.entry, tt.probe, tt.reason)
			}
		})
	}
}

// The escaped-path cases above drive checkEntropy on a pre-parsed URL, which
// exercises the matcher but not the real entry point. A review round asked
// whether Scan preserves the raw path far enough for the EscapedPath comparison
// to matter in production, and that is the right question: if Scan re-parsed
// and lost RawPath, the fix would be inert where it counts. It does not.
func TestPathEntropyExclusion_EscapedMatchingHoldsThroughScan(t *testing.T) {
	t.Parallel()

	s := pathExclusionScanner(t, config.PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
	})
	defer s.Close()

	tests := []struct {
		name      string
		rawURL    string
		wantBlock bool
	}{
		{
			name:      "the literal exempted route passes the whole pipeline",
			rawURL:    "https://docs.vendor.example/document/d/" + highEntropyID,
			wantBlock: false,
		},
		{
			name:      "an encoded separator is denied by the whole pipeline",
			rawURL:    "https://docs.vendor.example/document%2Fd/" + highEntropyID,
			wantBlock: true,
		},
		{
			name:      "a dot segment is denied by the whole pipeline",
			rawURL:    "https://docs.vendor.example/document/./d/" + highEntropyID,
			wantBlock: true,
		},
		{
			name:      "an unexempted route on the same host is denied",
			rawURL:    "https://docs.vendor.example/collect/" + highEntropyID,
			wantBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := s.Scan(context.Background(), tt.rawURL)
			if blocked := !res.Allowed; blocked != tt.wantBlock {
				t.Fatalf("Scan(%q) blocked = %v, want %v (scanner=%q reason=%q)", tt.rawURL, blocked, tt.wantBlock, res.Scanner, res.Reason)
			}
			if tt.wantBlock && res.Scanner != ScannerEntropy {
				t.Errorf("expected the entropy scanner to own the denial, got %q (%s)", res.Scanner, res.Reason)
			}
		})
	}
}
