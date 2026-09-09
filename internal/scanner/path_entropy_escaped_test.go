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

// A traversal prefix does bypass the entropy gate in isolation, which is what a
// review round flagged. It is not reachable as a bypass: path traversal is
// rejected at step 3 of the pipeline and entropy runs at step 10, so the full
// scan denies before the exemption is ever consulted. This pins that ordering,
// because a reorder that moved entropy ahead of traversal would turn the
// isolated gap into a real bypass with nothing else to catch it.
func TestPathEntropyExclusion_TraversalIsDeniedBeforeEntropyIsConsulted(t *testing.T) {
	t.Parallel()

	s := pathExclusionScanner(t, config.PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
	})
	defer s.Close()

	raw := "https://docs.vendor.example/document/d/../collect/" + highEntropyID
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
