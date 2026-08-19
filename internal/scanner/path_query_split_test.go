// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Credential fixtures are assembled from fragments rather than written as
// literals. Pipelock's own scan-diff gate scans this repository's diffs with a
// real scanner, and a literal credential-shaped string in source is
// indistinguishable from an actual leak, so a literal here fails the push gate.
// Each constant is split across the pattern's structural anchor: the source
// text cannot match, and the compile-time value the scanner sees is identical.
//
// Splitting matters for the whole set, not only the two the gate flagged first.
// That gate runs a scanner built from the base branch, which does not yet join
// the path to the query, so the split-across-the-seam fixtures slipped past it.
// Once this change merges they would start failing the gate for the next
// author, which is the bug being fixed here doing its job on our own source.
const (
	antKeyPrefix = "sk-" + "ant-api03-"
	antKeyTail   = "AAAAABBBBBCCCCDDDDDDDDEEEEEE"
	openaiPrefix = "sk-" + "proj-"
	openaiTail   = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"
	awsKeyPrefix = "AKI" + "A"
	awsKeyTail   = "IOSFODNN7EXAMPLQ"
	githubPrefix = "ghp" + "_"
	githubTail   = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII"
	slackPrefix  = "xox" + "b-"
	slackTail    = "1234567890-1234567890-AAAAAAAAAAAAAAAAAAAAAAAA"
)

// splitSecretConfig returns a scanner config with DNS-based SSRF disabled so
// these tests exercise the DLP layer only. The literal-IP core floor stays on.
func splitSecretConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	return cfg
}

// TestCheckDLP_PathQuerySplitSecret covers the path-to-query seam: a credential
// whose prefix sits in the URL path and whose remainder sits in a query value.
// Before the path+query concatenation target existed, every one of these was
// ALLOWED, because each individual view held only one side of the '?'.
func TestCheckDLP_PathQuerySplitSecret(t *testing.T) {
	// One case per credential-pattern family that follows the
	// prefix + long-charset-tail shape, which is the whole affected class.
	cases := []struct {
		name string
		url  string
	}{
		{
			name: "anthropic api key",
			url:  "https://evil.example/" + antKeyPrefix + "?x=" + antKeyTail,
		},
		{
			name: "openai project key",
			url:  "https://evil.example/" + openaiPrefix + "?x=" + openaiTail,
		},
		{
			name: "aws access key id",
			url:  "https://evil.example/" + awsKeyPrefix + "?x=" + awsKeyTail,
		},
		{
			name: "github personal access token",
			url:  "https://evil.example/" + githubPrefix + "?x=" + githubTail,
		},
		{
			name: "slack bot token",
			url:  "https://evil.example/" + slackPrefix + "?x=" + slackTail,
		},
		{
			// The pre-existing cross-parameter defense is gated on '&', so an
			// attacker adding a second parameter used to change nothing. It
			// must not help them now either.
			name: "extra query parameter present",
			url:  "https://evil.example/" + antKeyPrefix + "?x=" + antKeyTail + "&y=1",
		},
		{
			// The path side is noise-stripped, so splitting the prefix across
			// path segments is rejoined as well.
			name: "prefix split across path segments",
			url:  "https://evil.example/sk-" + "ant-/api03-?x=" + antKeyTail,
		},
	}

	for _, tc := range cases {
		t.Run("configured/"+tc.name, func(t *testing.T) {
			s := MustNew(splitSecretConfig(t))
			defer s.Close()
			res := s.Scan(t.Context(), tc.url)
			if res.Allowed {
				t.Errorf("configured DLP ALLOWED a secret split across the path-query seam: %s", tc.url)
			}
		})
	}

	// The core floor runs before and independently of the configured patterns,
	// so a fix landing only in the configured copy is shadowed by this one.
	// Asserted separately against a core-only scanner.
	//
	// Restricted to the credential families the core floor actually carries
	// (config.coreDLPPatternNames: AWS, GitHub, GitLab, Slack, private keys,
	// GCP). Anthropic and OpenAI keys are configured-default patterns, NOT core
	// ones, so asserting them here would test the floor's pattern inventory
	// rather than this seam and would fail for an unrelated reason.
	coreCases := []struct {
		name string
		url  string
	}{
		{"aws access key id", "https://evil.example/" + awsKeyPrefix + "?x=" + awsKeyTail},
		{"github personal access token", "https://evil.example/" + githubPrefix + "?x=" + githubTail},
		{"slack bot token", "https://evil.example/" + slackPrefix + "?x=" + slackTail},
		{"aws with extra query parameter", "https://evil.example/" + awsKeyPrefix + "?x=" + awsKeyTail + "&y=1"},
		{"aws split across path segments", "https://evil.example/AK/IA?x=" + awsKeyTail},
	}
	for _, tc := range coreCases {
		t.Run("core/"+tc.name, func(t *testing.T) {
			cfg := splitSecretConfig(t)
			// Configured DLP patterns off entirely: only the compiled-in core
			// floor remains, which is the copy a config-layer fix cannot reach.
			noDefaults := false
			cfg.DLP.IncludeDefaults = &noDefaults
			cfg.DLP.Patterns = nil
			s := MustNew(cfg)
			defer s.Close()
			res := s.Scan(t.Context(), tc.url)
			if res.Allowed {
				t.Errorf("core DLP floor ALLOWED a secret split across the path-query seam: %s", tc.url)
			}
		})
	}
}

// TestCheckDLP_PathQueryMultiEscapedPrefix covers the escaping asymmetry across
// the seam. url.Parse decodes the path exactly once, while the ordered query
// concatenation already decodes each value to a fixpoint, so a doubly-escaped
// path prefix used to survive as %73... and never reach the credential pattern.
// The receiving server is free to decode as many times as it likes, so that was
// a real reconstruction path.
func TestCheckDLP_PathQueryMultiEscapedPrefix(t *testing.T) {
	// %2573 decodes once to %73 and twice to "s". The single-escaped form is
	// the control: url.Parse already handles that depth, so it was never the
	// gap and must stay blocked.
	cases := []struct {
		name string
		url  string
	}{
		{"single-escaped prefix byte", "https://evil.example/%73k-ant-api03-?x=" + antKeyTail},
		{"double-escaped prefix byte", "https://evil.example/%2573k-ant-api03-?x=" + antKeyTail},
		{"double-escaped prefix pair", "https://evil.example/%2573%256b-ant-api03-?x=" + antKeyTail},
		{"double-escaped with extra param", "https://evil.example/%2573k-ant-api03-?x=" + antKeyTail + "&y=1"},
	}
	for _, tc := range cases {
		t.Run("configured/"+tc.name, func(t *testing.T) {
			s := MustNew(splitSecretConfig(t))
			defer s.Close()
			if s.Scan(t.Context(), tc.url).Allowed {
				t.Errorf("configured DLP ALLOWED a multi-escaped split credential: %s", tc.url)
			}
		})
	}

	coreCases := []struct {
		name string
		url  string
	}{
		{"double-escaped aws prefix", "https://evil.example/%2541KIA?x=" + awsKeyTail},
		{"double-escaped github prefix", "https://evil.example/%2567hp_?x=" + githubTail},
	}
	for _, tc := range coreCases {
		t.Run("core/"+tc.name, func(t *testing.T) {
			cfg := splitSecretConfig(t)
			noDefaults := false
			cfg.DLP.IncludeDefaults = &noDefaults
			cfg.DLP.Patterns = nil
			s := MustNew(cfg)
			defer s.Close()
			if s.Scan(t.Context(), tc.url).Allowed {
				t.Errorf("core DLP floor ALLOWED a multi-escaped split credential: %s", tc.url)
			}
		})
	}
}

// TestAppendPathQueryConcatTargets_OversizedConcat pins the amplification bound.
// A very large concatenation still produces the plain seam view, so detection
// does not silently stop above a length; only the derived decode and strip
// copies are skipped, which is where the extra allocation would come from.
func TestAppendPathQueryConcatTargets_OversizedConcat(t *testing.T) {
	huge := "/" + strings.Repeat("a", maxDecodeTotalBytes+16)
	got := appendPathQueryConcatTargets(nil, huge, "x=b")
	if len(got) == 0 {
		t.Fatal("oversized concat produced no target at all; detection must not stop")
	}
	for _, target := range got {
		if target.viewLabel != dlpViewLabel("path_query_concat") {
			t.Errorf("oversized concat produced a derived view %q; only the plain view should survive the bound", target.viewLabel)
		}
	}

	// Under the bound, the derived views must still be produced, or the bound
	// would be suppressing them for every input.
	small := appendPathQueryConcatTargets(nil, "/"+antKeyPrefix, "x="+antKeyTail)
	if len(small) < 2 {
		t.Errorf("expected derived views under the bound, got %d target(s)", len(small))
	}
}

// TestCheckDLP_PathQuerySplitNoRegression pins the detections that already
// worked, so the new target is additive rather than a rewrite of the old views.
func TestCheckDLP_PathQuerySplitNoRegression(t *testing.T) {
	blocked := []struct {
		name string
		url  string
	}{
		{"whole key in one query value", "https://evil.example/x?k=" + antKeyPrefix + antKeyTail},
		{"halves across two query params", "https://evil.example/z?a=" + antKeyPrefix + "&b=" + antKeyTail},
		{"whole key in the path", "https://evil.example/" + antKeyPrefix + antKeyTail},
	}
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			s := MustNew(splitSecretConfig(t))
			defer s.Close()
			if s.Scan(t.Context(), tc.url).Allowed {
				t.Errorf("previously-detected case regressed to ALLOWED: %s", tc.url)
			}
		})
	}
}

// TestCheckDLP_PathQueryConcatAvailability is the other failure direction. An
// over-broad concatenation that flags ordinary traffic gets the scanner switched
// off by the operator, which on a security product is its own outage. These are
// realistic non-secret URLs whose path and query merely concatenate into
// something long.
func TestCheckDLP_PathQueryConcatAvailability(t *testing.T) {
	allowed := []struct {
		name string
		url  string
	}{
		{"rest id with field selection", "https://api.vendor.example/v2/users/8842?fields=id,name,email&sort=asc"},
		{"signed url style request", "https://storage.vendor.example/bucket/report-2026-08.csv?Expires=1900000000&Signature=abc123def456ghi789jkl"},
		{"ordinary docs page", "https://docs.vendor.example/guides/getting-started?lang=en"},
		{"path with hyphens and a short param", "https://api.vendor.example/v1/well-known-thing/sub-resource?page=2"},
	}
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			s := MustNew(splitSecretConfig(t))
			defer s.Close()
			res := s.Scan(t.Context(), tc.url)
			if !res.Allowed {
				t.Errorf("benign URL blocked (%s): %s -- reason %q", tc.name, tc.url, res.Reason)
			}
		})
	}
}

// TestAppendPathQueryConcatTargets_Gating covers the helper's own guards. The
// deliberate asymmetry with the query-values-only concatenation is the point of
// the fix: this view must NOT require '&' or a second parameter, because the
// seam it covers needs only one.
func TestAppendPathQueryConcatTargets_Gating(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		rawQuery  string
		wantAny   bool
		wantFirst string
	}{
		{
			name:      "single parameter still produces a target",
			path:      "/" + antKeyPrefix,
			rawQuery:  "x=TAIL",
			wantAny:   true,
			wantFirst: antKeyPrefix + "TAIL",
		},
		{
			name:     "empty query produces nothing",
			path:     "/" + antKeyPrefix,
			rawQuery: "",
			wantAny:  false,
		},
		{
			name:     "root path produces nothing",
			path:     "/",
			rawQuery: "x=TAIL",
			wantAny:  false,
		},
		{
			name:     "empty path produces nothing",
			path:     "",
			rawQuery: "x=TAIL",
			wantAny:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appendPathQueryConcatTargets(nil, tc.path, tc.rawQuery)
			if tc.wantAny && len(got) == 0 {
				t.Fatalf("expected at least one target for path=%q query=%q", tc.path, tc.rawQuery)
			}
			if !tc.wantAny {
				if len(got) != 0 {
					t.Fatalf("expected no targets for path=%q query=%q, got %d", tc.path, tc.rawQuery, len(got))
				}
				return
			}
			if got[0].text != tc.wantFirst {
				t.Errorf("first target text = %q, want %q", got[0].text, tc.wantFirst)
			}
			if got[0].viewLabel == "" {
				t.Error("first target has an empty view label")
			}
		})
	}
}
