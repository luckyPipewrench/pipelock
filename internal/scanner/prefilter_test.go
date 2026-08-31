// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"sort"
	"testing"
)

func TestDLPPreFilter_Candidates(t *testing.T) {
	// Build a pre-filter from the real config defaults.
	s := MustNew(testConfig())
	defer s.Close()

	pf := newDLPPreFilter(s.dlpPatterns)

	// Verify we extracted some prefixes and identified some always-run patterns.
	if len(pf.prefixes) == 0 {
		t.Fatal("expected at least one prefix, got none")
	}
	if len(pf.alwaysRun) == 0 {
		t.Fatal("expected at least one always-run pattern (SSN, credential URL, etc.)")
	}

	t.Run("clean text returns no candidates", func(t *testing.T) {
		hits := pf.candidates("ordinary weather forecast")
		if len(hits) != 0 {
			t.Errorf("expected 0 candidates for clean text, got %d", len(hits))
		}
	})

	t.Run("anthropic prefix returns candidates", func(t *testing.T) {
		hits := pf.candidates("found " + "sk-ant-" + "something here")
		if len(hits) == 0 {
			t.Error("expected candidates for sk-ant- prefix, got none")
		}
	})

	t.Run("case insensitive match", func(t *testing.T) {
		hits := pf.candidates("found " + "SK-ANT-" + "something here")
		if len(hits) == 0 {
			t.Error("expected candidates for SK-ANT- (uppercase), got none")
		}
	})

	t.Run("github pat prefix returns candidates", func(t *testing.T) {
		hits := pf.candidates("token=" + "github_pat_" + "abc123")
		if len(hits) == 0 {
			t.Error("expected candidates for github_pat_ prefix, got none")
		}
	})

	t.Run("hugging face prefix returns candidates", func(t *testing.T) {
		hits := pf.candidates("key=" + "hf_" + "abcdef12345")
		if len(hits) == 0 {
			t.Error("expected candidates for hf_ prefix, got none")
		}
	})

	t.Run("patternsToCheck returns sorted indices", func(t *testing.T) {
		// Input with multiple prefixes to trigger multiple candidate indices.
		text := "sk-ant-" + "fake and " + "github_pat_" + "fake and " + "hf_" + "fake"
		indices := pf.patternsToCheck(text)
		if len(indices) == 0 {
			t.Fatal("expected non-empty indices for multi-prefix input")
		}
		if !sort.IntsAreSorted(indices) {
			t.Errorf("patternsToCheck returned unsorted indices: %v", indices)
		}
	})
}

func TestDLPPreFilter_EndToEndAlwaysRun(t *testing.T) {
	// Verify always-run patterns are evaluated through the full scanner path
	// even when the input contains no literal prefix from prefix-gated patterns.
	s := MustNew(testConfig())
	defer s.Close()

	// AWS key has no extractable prefix (alternation). It must still be caught
	// via alwaysRun when scanning text that looks otherwise clean.
	key := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	result := s.ScanTextForDLP(context.Background(), "check this "+key+" value")
	if result.Clean {
		t.Error("expected AWS key to be caught by always-run pattern, got clean")
	}
}

func TestDLPPreFilter_AlwaysRunPatterns(t *testing.T) {
	s := MustNew(testConfig())
	defer s.Close()

	pf := newDLPPreFilter(s.dlpPatterns)

	// Check that patterns without a provable selective literal anchor remain in
	// alwaysRun. SSNs and Discord's first alternative do not have one. Generic
	// credential-field anchors are deliberately kept here
	// because their common words are not selective enough for a useful gate.
	alwaysRunNames := make(map[string]bool)
	configuredNames := make(map[string]bool)
	for _, pattern := range s.dlpPatterns {
		configuredNames[pattern.name] = true
	}
	for _, idx := range pf.alwaysRun {
		alwaysRunNames[s.dlpPatterns[idx].name] = true
	}

	expectedAlways := []string{
		"Social Security Number",
		"Discord Bot Token",
		"Credential in URL",
		"Environment Variable Secret",
	}

	for _, name := range expectedAlways {
		if !alwaysRunNames[name] {
			t.Errorf("expected %q in alwaysRun, but it was not found", name)
		}
	}

	for _, name := range []string{"Anthropic API Key", "GitHub Fine-Grained PAT"} {
		if !configuredNames[name] {
			t.Fatalf("expected anchored default pattern %q to exist", name)
		}
		if alwaysRunNames[name] {
			t.Errorf("expected %q to be anchor-gated, but it is in alwaysRun", name)
		}
	}
}
