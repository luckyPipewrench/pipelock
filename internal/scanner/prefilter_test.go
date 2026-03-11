// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"
)

func TestExtractLiteralPrefix(t *testing.T) {
	tests := []struct {
		name  string
		regex string
		want  string
	}{
		// Simple prefixes
		{"anthropic", "(?i)sk-ant-[a-zA-Z0-9]{10,}", "sk-ant-"},
		{"openai", "(?i)sk-proj-[a-zA-Z0-9]{10,}", "sk-proj-"},
		{"fireworks", "(?i)fw_[a-zA-Z0-9]{24,}", "fw_"},
		{"google api", "(?i)AIza[0-9A-Za-z]{35}", "aiza"},
		{"gocspx", "(?i)GOCSPX-[A-Za-z0-9_]{28,}", "gocspx-"},
		{"github pat", "(?i)github_pat_[a-zA-Z0-9_]{36,}", "github_pat_"},
		{"sendgrid", `(?i)SG\.[a-zA-Z0-9_-]{22}`, "sg."},
		{"mailgun", "(?i)key-[a-zA-Z0-9]{32}", "key-"},
		{"hugging face", "(?i)hf_[A-Za-z0-9]{20,}", "hf_"},
		{"databricks", "(?i)dapi[a-z0-9]{30,}", "dapi"},
		{"replicate", "(?i)r8_[A-Za-z0-9]{20,}", "r8_"},
		{"together", "(?i)tok_[a-z0-9]{40,}", "tok_"},
		{"pinecone", "(?i)pcsk_[a-zA-Z0-9]{36,}", "pcsk_"},
		{"digitalocean", "(?i)dop_v1_[a-f0-9]{64}", "dop_v1_"},
		{"vault", `(?i)hvs\.[a-zA-Z0-9]{23,}`, "hvs."},
		{"supabase", "(?i)sb_secret_[a-zA-Z0-9_-]{20,}", "sb_secret_"},
		{"npm", "(?i)npm_[A-Za-z0-9]{36,}", "npm_"},
		{"pypi", "(?i)pypi-[A-Za-z0-9_-]{16,}", "pypi-"},
		{"linear", "(?i)lin_api_[a-zA-Z0-9]{40,}", "lin_api_"},
		{"notion", "(?i)ntn_[a-zA-Z0-9]{40,}", "ntn_"},
		{"sentry", "(?i)sntrys_[a-zA-Z0-9]{40,}", "sntrys_"},
		{"slack token", "(?i)xox[bpras]-[0-9a-zA-Z-]{15,}", "xox"},
		{"slack app", "(?i)xapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+", "xapp-"},
		{"private key", `(?i)-----BEGIN\s+(RSA)?PRIVATE`, "-----begin"},
		{"ya29", `(?i)ya29\.[a-zA-Z0-9_-]{20,}`, "ya29."},

		// Alternation at start: no single prefix
		{"aws", "(?i)(AKIA|A3T|AGPA)[A-Z0-9]{16,}", ""},
		{"stripe", "(?i)[sr]k_(live|test)_[a-zA-Z0-9]{20,}", ""},
		{"github token", "(?i)gh[pousr]_[A-Za-z0-9_]{36,}", "gh"},
		{"discord", "(?i)[MN][A-Za-z0-9]{23,}", ""},

		// Word boundary at start: no prefix
		{"ssn", `(?i)\b\d{3}-\d{2}-\d{4}\b`, ""},
		{"credential url", `(?i)\b(?:password|token)=[^\s&]+`, ""},

		// Non-capturing group with single alternative
		{"vercel", "(?i)(?:vercel|vc[piark])_[a-zA-Z0-9]{24,}", ""},

		// Quantified non-capturing group: prefix is optional, can't gate on it
		{"optional group ?", "(?i)(?:sk-)?proj-[A-Za-z0-9]+", ""},
		{"optional group *", "(?i)(?:prefix)*suffix-[A-Za-z0-9]+", ""},
		{"optional group +", "(?i)(?:prefix)+suffix-[A-Za-z0-9]+", ""},
		{"optional group {}", "(?i)(?:prefix){0,3}suffix-[A-Za-z0-9]+", ""},

		// Edge cases
		{"empty", "", ""},
		{"just flag", "(?i)", ""},
		{"no flag", "sk-ant-foo", "sk-ant-foo"},
		{"twilio", "(?i)SK[a-f0-9]{32}", "sk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLiteralPrefix(tt.regex)
			if got != tt.want {
				t.Errorf("extractLiteralPrefix(%q) = %q, want %q", tt.regex, got, tt.want)
			}
		})
	}
}

func TestDLPPreFilter_Candidates(t *testing.T) {
	// Build a pre-filter from the real config defaults.
	s := New(testConfig())
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
		hits := pf.candidates("this is a normal url with no secret prefixes at all")
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
}

func TestDLPPreFilter_AlwaysRunPatterns(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	pf := newDLPPreFilter(s.dlpPatterns)

	// Check that patterns without literal prefixes end up in alwaysRun.
	// AWS (alternation), Stripe (char class), SSN (\b\d), Discord ([MN]),
	// credential URL (\b) should all be in alwaysRun.
	alwaysRunNames := make(map[string]bool)
	for _, idx := range pf.alwaysRun {
		alwaysRunNames[s.dlpPatterns[idx].name] = true
	}

	expectedAlways := []string{
		"AWS Access ID",
		"Stripe Key",
		"Social Security Number",
		"Discord Bot Token",
	}

	for _, name := range expectedAlways {
		if !alwaysRunNames[name] {
			t.Errorf("expected %q in alwaysRun, but it was not found", name)
		}
	}
}
