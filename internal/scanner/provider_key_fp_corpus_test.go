// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
)

// This file is the standing FALSE-POSITIVE GUARD for the LLM-provider-key DLP
// patterns. A false positive on a security product blocks a real customer's
// legitimate traffic, which is worse than missing a key (the destination
// allowlist is the primary control; key detection is defense in depth). So the
// bar is: the provider-key patterns must NOT fire on benign high-entropy tokens
// that merely look key-shaped.
//
// If a future pattern change starts matching anything in providerKeyBenignCorpus,
// THIS TEST FAILS and the change does not ship. When adding a new provider
// pattern, add its near-miss shapes (right prefix, wrong length/charset) here too.

// providerKeyBenignCorpus holds tokens that are NOT secrets but share the shape
// of provider keys: opaque high-entropy IDs, and near-misses of every covered
// prefix (too short, wrong charset, or embedded in a longer token). Every entry
// MUST scan clean.
var providerKeyBenignCorpus = map[string]string{
	// Generic opaque high-entropy tokens (the hardest class: a bare key is
	// indistinguishable from these, which is why bare-format keys are NOT covered).
	"uuid v4":             "550e8400-e29b-41d4-a716-446655440000",
	"git sha-40":          "9f52193c1a2b3c4d5e6f70819293a4b5c6d7e8f9",
	"hex session id 64":   "3b1f9c8a7e6d5c4b3a2918077665544332211000ffeeddccbbaa99887766aabb",
	"numeric request id":  "1234567890123456789012345678901234567890",
	"lowercase opaque 40": strings.Repeat("a", 40),

	// Near-misses of covered prefixes: correct prefix, but under the length floor,
	// wrong charset, or a trailing boundary that proves it is a longer token.
	"anthropic under floor":   testAnthropicPrefix + strings.Repeat("a", 10), // floor is 20
	"openai proj under floor": "sk-proj-" + strings.Repeat("b", 8),
	"openai svcacct short":    "sk-svcacct-" + strings.Repeat("c", 8),
	"fireworks under 22":      "fw_" + strings.Repeat("d", 10),
	"llm router under floor":  "sk-or-v1-" + strings.Repeat("e", 10),
	// Permanent tripwire: the LLM Router suffix charset must stay hex-only.
	// Hyphens/underscores and arbitrary letters let "sk-or-v1-" followed by
	// ordinary prose/slugs false-positive.
	"llm router hyphenated prose": "sk-or-v1-but-then-words-not-a-key-just-text",
	"llm router long word prose":  "sk-or-v1-thisisaverylongwordnotakey",
	"answer engine short":         "pplx-" + strings.Repeat("f", 8),
	"answer engine embedded":      "prefix_pplx-" + strings.Repeat("g", 24),
	"web research short":          "tvly-" + strings.Repeat("j", 8),
	"web research charset":        "tvly-" + strings.Repeat("k", 19) + "_",
	"google wrong length":         "AIza" + strings.Repeat("e", 10),
	"huggingface too short":       "hf_abc",
	"databricks non-hex":          "dapi" + strings.Repeat("z", 32), // z is not hex
	"replicate non-hex":           "r8_" + strings.Repeat("g", 40),  // g is not hex
	"together longer token":       "tok_" + strings.Repeat("a", 40) + "_suffix",
	"pinecone short":              "pcsk_" + strings.Repeat("h", 8),
	"groq short":                  "gsk_" + strings.Repeat("i", 8),
	"prefix inside a word":        "risk-projection-summary-table-v2-output",

	// Permanent tripwires: these benign identifiers were demonstrated to false
	// positive against the removed `sk_car_` ("Voice AI") and `jina_` ("Neural
	// Search") default patterns (their key formats are undisclosed, so a prefix
	// rule cannot be anchored precisely). The patterns were dropped; these MUST
	// keep scanning clean to prevent any FP-prone re-introduction.
	"car snake_case ref":   "sk_car_rental_booking_reference_2024_summary",
	"car admin snake_case": "sk_car_admin_panel_settings_layout_config",
	"jina plausible ident": "jina_clientidentifier1234567890",
}

func TestProviderKeyPatterns_NoFalsePositivesOnBenignCorpus(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()
	ctx := context.Background()

	for name, val := range providerKeyBenignCorpus {
		t.Run(name, func(t *testing.T) {
			res := s.ScanTextForDLP(ctx, val)
			if !res.Clean {
				names := make([]string, 0, len(res.Matches))
				for _, m := range res.Matches {
					names = append(names, m.PatternName)
				}
				t.Fatalf("FALSE POSITIVE: benign token %q matched %v (must scan clean)", name, names)
			}
		})
	}
}

// TestProviderKeyPatterns_PositiveControls makes the FP guard non-vacuous: real
// provider-key shapes MUST still be detected, so a regex that was loosened into
// uselessness (and therefore never false-positives) cannot pass the FP guard by
// matching nothing.
func TestProviderKeyPatterns_PositiveControls(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()
	ctx := context.Background()

	positives := map[string]string{
		"anthropic real shape": testAnthropicPrefix + strings.Repeat("a", 25),
		"openai proj real":     "sk-proj-" + strings.Repeat("b", 24),
		"fireworks real 22":    "fw_" + strings.Repeat("c", 22),
		"llm router real":      "sk-or-v1-" + strings.Repeat("d", 24),
		"answer engine real":   "pplx-" + strings.Repeat("e", 24),
		"web research real":    "tvly-" + strings.Repeat("g", 24),
		"groq real":            "gsk_" + strings.Repeat("j", 48),
	}
	for name, val := range positives {
		t.Run(name, func(t *testing.T) {
			if s.ScanTextForDLP(ctx, val).Clean {
				t.Fatalf("MISSED: %q (%s) should be detected as a provider key", val, name)
			}
		})
	}
}
