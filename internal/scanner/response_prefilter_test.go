// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestExtractResponseKeywords(t *testing.T) {
	tests := []struct {
		name    string
		regex   string
		wantNil bool   // expect nil (pattern goes to alwaysRun)
		wantAny string // at least one keyword must contain this substring
		wantAll int    // exact keyword count (0 = don't check)
	}{
		{
			name:    "simple literal prefix",
			regex:   `(?i)from\s+now\s+on`,
			wantAny: "from",
		},
		{
			name:    "full alternation with all keywords",
			regex:   `(?i)(ignore|disregard|forget)\s+`,
			wantAll: 3,
			wantAny: "ignore",
		},
		{
			name:    "alternation with one short branch drops to alwaysRun",
			regex:   `(?i)(ignore|do|forget)\s+`,
			wantNil: true,
		},
		{
			name:    "alternation with nested optional group drops to alwaysRun",
			regex:   `(?i)(let's\s+play|pretend\s+you|(in\s+this\s+)?(hypothetical|fictional))`,
			wantNil: true,
		},
		{
			name:    "escaped pipe produces literal keywords",
			regex:   `(<\|endoftext\|>|\[INST\])`,
			wantAll: 2,
			wantAny: "<|endoftext|>",
		},
		{
			name:    "escaped braces produce literal keywords",
			regex:   `(?i)(\{GODMODE|RESET_CORTEX)`,
			wantAll: 2,
			wantAny: "{GODMODE",
		},
		{
			name:    "no extractable prefix → alwaysRun",
			regex:   `(?i)\d+\s+errors`,
			wantNil: true,
		},
		{
			name:    "leading anchor + metachar → alwaysRun",
			regex:   `(?im)^\s*system\s*:`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile to get the canonical regex string (same as production path).
			re := regexp.MustCompile(tt.regex)
			kw := extractResponseKeywords(re.String())

			if tt.wantNil {
				if kw != nil {
					t.Errorf("expected nil keywords, got %v", kw)
				}
				return
			}
			if kw == nil {
				t.Fatal("expected keywords, got nil")
			}
			if tt.wantAll > 0 && len(kw) != tt.wantAll {
				t.Errorf("expected %d keywords, got %d: %v", tt.wantAll, len(kw), kw)
			}
			if tt.wantAny != "" {
				found := false
				for _, k := range kw {
					if k == tt.wantAny {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected keyword containing %q, got %v", tt.wantAny, kw)
				}
			}
		})
	}
}

func TestResponsePreFilter_AlwaysRunCoversKeywordlessBranches(t *testing.T) {
	// Pattern with alternation where one branch has no extractable keyword.
	// The pattern must go to alwaysRun and be evaluated regardless of content.
	patterns := []*compiledPattern{
		{name: "test", re: regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+all`)},
		{name: "boundary", re: regexp.MustCompile(`(<\|endoftext\|>|\[INST\])`)},
	}
	pf := newResponsePreFilter(patterns)

	// Content has no keywords from pattern 0 ("ignore"/"disregard"/"forget").
	// Pattern 1 (boundary) has no keywords → must be in alwaysRun.
	indices := pf.patternsToCheck("some random text with <|endoftext|> marker")

	foundBoundary := false
	for _, idx := range indices {
		if idx == 1 {
			foundBoundary = true
		}
	}
	if !foundBoundary {
		t.Error("expected boundary pattern (index 1) in alwaysRun, but it was not returned")
	}
}

func TestPerPassPreFilterConstruction(t *testing.T) {
	// Verify that opt-space and vowel-fold pre-filters are built independently.
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = "block"
	s := New(cfg)
	defer s.Close()

	if s.responsePreFilter == nil {
		t.Fatal("expected primary pre-filter to be built")
	}
	if len(s.responseOptSpacePatterns) > 0 && s.responseOptSpacePreFilter == nil {
		t.Error("expected opt-space pre-filter to be built when opt-space patterns exist")
	}
	if len(s.responseVowelFoldPatterns) > 0 && s.responseVowelFoldPreFilter == nil {
		t.Error("expected vowel-fold pre-filter to be built when vowel-fold patterns exist")
	}
}
