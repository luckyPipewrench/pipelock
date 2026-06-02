// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

// redactSeed12 is a valid BIP-39 12-word mnemonic (abandon x11 + about).
const redactSeed12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func homoglyphFoldSeed(s string) string {
	return strings.NewReplacer(
		"a", "а", "o", "о", "e", "е", "c", "с", "p", "р",
		"t", "т", "x", "х", "k", "к", "m", "м", "y", "у",
	).Replace(s)
}

// TestMatcher_SeedEvasionRedacted is a redaction-surface parity regression.
// Before the seedprotect normalization hardening, a homoglyph- or
// exotic-separator-disguised seed phrase evaded the redactor (matcher.go calls
// seedprotect.DetectSpans), so it would pass through unredacted even when the
// scanner flagged it elsewhere. The same evasion must now be redacted, keeping
// the detection and redaction surfaces in parity.
func TestMatcher_SeedEvasionRedacted(t *testing.T) {
	m := NewDefaultMatcher()

	cases := []struct {
		name string
		text string
	}{
		{"cyrillic-homoglyph", homoglyphFoldSeed(redactSeed12)},
		{"nbsp-separator", strings.ReplaceAll(redactSeed12, " ", " ")},
		{"combined-homoglyph-nbsp", strings.ReplaceAll(homoglyphFoldSeed(redactSeed12), " ", " ")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var found bool
			for _, mt := range m.Scan(tc.text) {
				if mt.Class == ClassSeedPhrase {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s: evaded seed phrase NOT redacted (no ClassSeedPhrase match)", tc.name)
			}
		})
	}
}
