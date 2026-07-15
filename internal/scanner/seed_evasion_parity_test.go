// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
)

// homoglyphFoldSeed swaps Latin letters for visually identical Cyrillic code
// points that the normalize package maps back to ASCII. Only letters with a
// confirmed lowercase Cyrillic confusable are swapped.
func homoglyphFoldSeed(s string) string {
	return strings.NewReplacer(
		"a", "а", "o", "о", "e", "е", "c", "с", "p", "р",
		"t", "т", "x", "х", "k", "к", "m", "м", "y", "у",
	).Replace(s)
}

// TestScanTextForDLP_SeedEvasionParity is a transport-parity regression. A
// Unicode-evaded BIP-39 seed must be caught through the live ScanTextForDLP
// path — the same path the offline `pipelock audit simulate` / scan harness
// drives via scanner.New + Scan — not just by the seedprotect package in
// isolation. This proves the normalization + separator hardening reaches the
// scanner integration boundary (and therefore the audit surface) rather than
// living only in the detector.
func TestScanTextForDLP_SeedEvasionParity(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	s := MustNew(cfg)

	cases := []struct {
		name string
		text string
	}{
		{"cyrillic-homoglyph", homoglyphFoldSeed(testSeedPhrase12)},
		{"nbsp-separator", strings.ReplaceAll(testSeedPhrase12, " ", " ")},
		{"en-dash-separator", strings.ReplaceAll(testSeedPhrase12, " ", "–")},
		{"line-separator", strings.ReplaceAll(testSeedPhrase12, " ", "\u2028")},
		{"combined-homoglyph-nbsp", strings.ReplaceAll(homoglyphFoldSeed(testSeedPhrase12), " ", " ")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := s.ScanTextForDLP(context.Background(), tc.text)
			if r.Clean {
				t.Fatalf("%s: evaded seed phrase NOT detected via ScanTextForDLP (parity gap)", tc.name)
			}
			found := false
			for _, m := range r.Matches {
				if m.PatternName == "BIP-39 Seed Phrase" {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s: detected but not as BIP-39 Seed Phrase: %+v", tc.name, r.Matches)
			}
		})
	}
}

// TestScan_SeedEvasionURLTargetParity proves the third detection surface: the
// URL/target scan path (Scan builds seed candidates from query values, hostname
// labels, and path segments). An underscore-separated mnemonic in a path was a
// single un-tokenizable blob before the separator hardening; "_" is now a
// separator, so the segments tokenize into the 12 words and the phrase is
// caught. ASCII-only, so there is no URL-encoding noise. Seed detection runs in
// the DLP layer before SSRF/DNS, so Internal=nil keeps the test offline.
func TestScan_SeedEvasionURLTargetParity(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = nil
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	s := MustNew(cfg)
	defer s.Close()

	underscored := strings.ReplaceAll(testSeedPhrase12, " ", "_")
	r := s.Scan(context.Background(), "https://evil.example/"+underscored)
	if r.Allowed {
		t.Fatalf("underscore-separated seed in URL path NOT blocked via Scan (URL/target parity gap): %+v", r)
	}
	if !strings.Contains(r.Reason, "Seed Phrase") {
		t.Fatalf("blocked but not for a seed phrase: %q", r.Reason)
	}
}
