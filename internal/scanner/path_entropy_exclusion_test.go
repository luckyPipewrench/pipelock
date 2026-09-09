// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A path-entropy exclusion exempts ONE host plus ONE literal path prefix from
// the path-entropy gate, and nothing else. The reason the field exists is that
// the only previous tool, subdomain_entropy_exclusions, is host-wide AND also
// governs the subdomain gate, so using it to fix a path false positive gave up
// an unrelated detection. These tests pin that this one does not.

// highEntropyID is a base64url-shaped identifier above the default 4.5
// threshold. Asserted rather than assumed, because a fixture below the
// threshold would make every case below pass for the wrong reason.
const highEntropyID = "pTyGJMuHbEL31IeL2HPcHyGcFRl1SPnXNYvMIHa_2o76umfX"

func pathExclusionScanner(t *testing.T, entries ...config.PathEntropyExclusion) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil // no DNS in unit tests; the literal-IP SSRF floor still runs
	cfg.FetchProxy.Monitoring.PathEntropyExclusions = entries
	return MustNew(cfg)
}

func TestPathEntropyExclusion_FixtureIsAboveThreshold(t *testing.T) {
	t.Parallel()
	got := ShannonEntropy(highEntropyID)
	if got <= 4.5 {
		t.Fatalf("fixture entropy = %.2f, which is not above the 4.5 default; every exclusion test would pass for the wrong reason", got)
	}
}

func TestPathEntropyExclusion_ExemptsOnlyTheNamedRoute(t *testing.T) {
	t.Parallel()

	entry := config.PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
		Reason:     "service-issued document identifier",
	}

	tests := []struct {
		name      string
		rawURL    string
		wantBlock bool
		why       string
	}{
		{
			name:      "exempted route allows the opaque segment",
			rawURL:    "https://docs.vendor.example/document/d/" + highEntropyID + "/edit",
			wantBlock: false,
			why:       "this is the false positive the field exists to fix",
		},
		{
			name:      "a different path on the SAME host still blocks",
			rawURL:    "https://docs.vendor.example/random/" + highEntropyID,
			wantBlock: true,
			why:       "the exemption is scoped to the prefix, not to the host",
		},
		{
			name:      "the same route on a DIFFERENT host still blocks",
			rawURL:    "https://other.vendor.example/document/d/" + highEntropyID + "/edit",
			wantBlock: true,
			why:       "the exemption names one host",
		},
		{
			name:      "a host that merely shares the prefix string still blocks",
			rawURL:    "https://docs.vendor.example.evil.test/document/d/" + highEntropyID,
			wantBlock: true,
			why:       "host matching is domain-aware, not a string prefix",
		},
		{
			name:      "http is not exempt when the entry is https",
			rawURL:    "http://docs.vendor.example/document/d/" + highEntropyID + "/edit",
			wantBlock: true,
			why:       "an entry never matches a scheme it does not name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := pathExclusionScanner(t, entry)
			defer s.Close()

			parsed, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			res := s.checkEntropy(parsed)
			blocked := !res.Allowed
			if blocked != tt.wantBlock {
				t.Fatalf("checkEntropy(%q) blocked = %v, want %v (%s); reason=%q", tt.rawURL, blocked, tt.wantBlock, tt.why, res.Reason)
			}
			if tt.wantBlock && !strings.Contains(res.Reason, "path segment") {
				t.Errorf("expected a path-entropy block, got reason %q", res.Reason)
			}
		})
	}
}

// The whole point of a dedicated field is that it does not disable the other
// gates the way the host-wide list does. Query entropy is the one that matters
// most: the query is where a payload actually reaches a collector.
func TestPathEntropyExclusion_LeavesQueryEntropyEnforced(t *testing.T) {
	t.Parallel()

	s := pathExclusionScanner(t, config.PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
	})
	defer s.Close()

	// Control: the exempted path is allowed, so a block below is attributable
	// to the query rather than to the path.
	allowed, err := url.Parse("https://docs.vendor.example/document/d/" + highEntropyID + "/edit")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if res := s.checkEntropy(allowed); !res.Allowed {
		t.Fatalf("control failed: the exempted path was blocked (%s)", res.Reason)
	}

	withQuery, err := url.Parse("https://docs.vendor.example/document/d/" + highEntropyID + "/edit?data=" + highEntropyID)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	res := s.checkEntropy(withQuery)
	if res.Allowed {
		t.Fatal("a high-entropy QUERY value was allowed on a path-exempted route; the path exemption must not reach the query gate")
	}
	if !strings.Contains(res.Reason, "query") {
		t.Fatalf("expected a query-entropy block, got %q", res.Reason)
	}
}

// An entry that cannot name a route is dropped rather than treated as a
// wildcard, so a malformed config cannot silently disable the gate. Validation
// rejects these too; this is the second line, at the point of use.
func TestPathEntropyExclusion_IncompleteEntriesAreInert(t *testing.T) {
	t.Parallel()

	for _, entry := range []config.PathEntropyExclusion{
		{Host: "", PathPrefix: "/document/d/"},
		{Host: "docs.vendor.example", PathPrefix: ""},
		{Host: "   ", PathPrefix: "   "},
	} {
		s := pathExclusionScanner(t, entry)
		parsed, err := url.Parse("https://docs.vendor.example/document/d/" + highEntropyID + "/edit")
		if err != nil {
			s.Close()
			t.Fatalf("url.Parse: %v", err)
		}
		res := s.checkEntropy(parsed)
		s.Close()
		if res.Allowed {
			t.Errorf("an incomplete entry %+v exempted the route; it must be inert", entry)
		}
	}
}

// With no entries configured the gate behaves exactly as before, which is what
// makes shipping the field with an empty default safe.
func TestPathEntropyExclusion_EmptyListChangesNothing(t *testing.T) {
	t.Parallel()

	s := pathExclusionScanner(t)
	defer s.Close()

	parsed, err := url.Parse("https://docs.vendor.example/document/d/" + highEntropyID + "/edit")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if res := s.checkEntropy(parsed); res.Allowed {
		t.Fatal("with no exclusions configured the opaque path segment must still block")
	}
}

// A wildcard host is supported because the sibling gates support it and an
// operator would reasonably expect consistency, but it must still be
// domain-aware rather than a string match.
func TestPathEntropyExclusion_WildcardHost(t *testing.T) {
	t.Parallel()

	s := pathExclusionScanner(t, config.PathEntropyExclusion{
		Host:       "*.vendor.example",
		PathPrefix: "/document/d/",
	})
	defer s.Close()

	cases := map[string]bool{
		"https://docs.vendor.example/document/d/" + highEntropyID:           false,
		"https://sheets.vendor.example/document/d/" + highEntropyID:         false,
		"https://vendor.example/document/d/" + highEntropyID:                false,
		"https://docs.vendor.example.evil.test/document/d/" + highEntropyID: true,
		"https://notvendor.example/document/d/" + highEntropyID:             true,
	}
	for raw, wantBlock := range cases {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		if blocked := !s.checkEntropy(parsed).Allowed; blocked != wantBlock {
			t.Errorf("checkEntropy(%q) blocked = %v, want %v", raw, blocked, wantBlock)
		}
	}
}
