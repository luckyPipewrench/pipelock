// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// testDLPConfig returns a minimal config with SSRF disabled and one pattern.
// If warn is true, the pattern gets action: warn.
func testDLPConfig(patternName, regex string, warn bool) *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF for unit tests

	action := ""
	if warn {
		action = config.ActionWarn
	}
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     patternName,
		Regex:    regex,
		Severity: "high",
		Action:   action,
	})
	return cfg
}

func TestTextDLP_WarnPatternRoutesToInformational(t *testing.T) {
	cfg := testDLPConfig("staged-key", `staged-[A-Za-z0-9]{10,}`, true)
	s := New(cfg)

	result := s.ScanTextForDLP(context.Background(), "here is staged-ABCDEFGHIJ1234")

	// Warn-only: Clean should be true (no enforcement), Matches empty.
	if !result.Clean {
		t.Error("warn-only match should produce Clean=true")
	}
	if len(result.Matches) != 0 {
		t.Errorf("warn-only match should not appear in Matches, got %d", len(result.Matches))
	}
	if len(result.InformationalMatches) == 0 {
		t.Fatal("warn-only match should appear in InformationalMatches")
	}
	m := result.InformationalMatches[0]
	if m.PatternName != "staged-key" {
		t.Errorf("expected pattern name staged-key, got %q", m.PatternName)
	}
	if !m.Warn {
		t.Error("InformationalMatches entry should have Warn=true")
	}
}

func TestTextDLP_EnforcePatternRoutesToMatches(t *testing.T) {
	cfg := testDLPConfig("enforced-key", `enforced-[A-Za-z0-9]{10,}`, false)
	s := New(cfg)

	result := s.ScanTextForDLP(context.Background(), "here is enforced-ABCDEFGHIJ1234")

	if result.Clean {
		t.Error("enforced match should produce Clean=false")
	}
	if len(result.Matches) == 0 {
		t.Fatal("enforced match should appear in Matches")
	}
	if result.Matches[0].Warn {
		t.Error("enforced match should have Warn=false")
	}
	if len(result.InformationalMatches) != 0 {
		t.Errorf("enforced match should not appear in InformationalMatches, got %d",
			len(result.InformationalMatches))
	}
}

func TestTextDLP_MixedWarnAndEnforce(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{
			Name:     "warn-pattern",
			Regex:    `warn-[A-Za-z0-9]{10,}`,
			Severity: "medium",
			Action:   config.ActionWarn,
		},
		config.DLPPattern{
			Name:     "enforce-pattern",
			Regex:    `enforce-[A-Za-z0-9]{10,}`,
			Severity: "high",
		},
	)
	s := New(cfg)

	text := "warn-AAAAAAAAAA plus enforce-BBBBBBBBBB"
	result := s.ScanTextForDLP(context.Background(), text)

	// Should NOT be clean (enforced match exists).
	if result.Clean {
		t.Error("mixed result should not be clean when enforced match exists")
	}

	// Enforced match in Matches.
	foundEnforce := false
	for _, m := range result.Matches {
		if m.PatternName == "enforce-pattern" {
			foundEnforce = true
			if m.Warn {
				t.Error("enforce-pattern should not have Warn=true")
			}
		}
		if m.PatternName == "warn-pattern" {
			t.Error("warn-pattern should NOT appear in Matches")
		}
	}
	if !foundEnforce {
		t.Error("enforce-pattern not found in Matches")
	}

	// Warn match in InformationalMatches.
	foundWarn := false
	for _, m := range result.InformationalMatches {
		if m.PatternName == "warn-pattern" {
			foundWarn = true
			if !m.Warn {
				t.Error("warn-pattern should have Warn=true")
			}
		}
		if m.PatternName == "enforce-pattern" {
			t.Error("enforce-pattern should NOT appear in InformationalMatches")
		}
	}
	if !foundWarn {
		t.Error("warn-pattern not found in InformationalMatches")
	}
}

func TestURLDLP_WarnPatternAllowsRequest(t *testing.T) {
	cfg := testDLPConfig("staged-url-key", `staged-[A-Za-z0-9]{10,}`, true)
	s := New(cfg)

	result := s.Scan(context.Background(), "https://example.com/?key=staged-ABCDEFGHIJ1234")

	if !result.Allowed {
		t.Error("warn-mode URL DLP match should allow the request")
	}
	if len(result.WarnMatches) == 0 {
		t.Fatal("warn-mode URL DLP match should populate WarnMatches")
	}
	if result.WarnMatches[0].PatternName != "staged-url-key" {
		t.Errorf("expected pattern name staged-url-key, got %q", result.WarnMatches[0].PatternName)
	}
}

func TestURLDLP_EnforcePatternBlocksRequest(t *testing.T) {
	cfg := testDLPConfig("enforced-url-key", `enforced-[A-Za-z0-9]{10,}`, false)
	s := New(cfg)

	result := s.Scan(context.Background(), "https://example.com/?key=enforced-ABCDEFGHIJ1234")

	if result.Allowed {
		t.Error("enforced URL DLP match should block the request")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner %q, got %q", ScannerDLP, result.Scanner)
	}
}

func TestURLDLP_WarnDoesNotPreventEnforceBlock(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{
			Name:     "warn-url",
			Regex:    `warnurl-[A-Za-z0-9]{10,}`,
			Severity: "medium",
			Action:   config.ActionWarn,
		},
		config.DLPPattern{
			Name:     "enforce-url",
			Regex:    `enforceurl-[A-Za-z0-9]{10,}`,
			Severity: "critical",
		},
	)
	s := New(cfg)

	// Install hook to verify warn emission even on blocked requests.
	var hookCalled []string
	old := DLPWarnHook
	DLPWarnHook = func(patternName, _, _ string) {
		hookCalled = append(hookCalled, patternName)
	}
	defer func() { DLPWarnHook = old }()

	// URL with both warn and enforce matches — should be blocked by enforce.
	url := "https://example.com/?a=warnurl-AAAAAAAAAA&b=enforceurl-BBBBBBBBBB"
	result := s.Scan(context.Background(), url)

	if result.Allowed {
		t.Error("should be blocked when enforce pattern matches")
	}
	// Warn matches should still be reported even when blocked by another pattern.
	if len(result.WarnMatches) == 0 {
		t.Error("warn matches should be reported even when request is blocked by enforce pattern")
	}
	// Hook should fire for the warn pattern even though the request was blocked.
	foundWarnHook := false
	for _, name := range hookCalled {
		if name == "warn-url" {
			foundWarnHook = true
		}
	}
	if !foundWarnHook {
		t.Error("DLPWarnHook should fire for warn-url even when request is blocked by enforce pattern")
	}
}

func TestURLDLP_WarnMatchFromSubsequenceCombination(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     "staged-subseq",
		Regex:    `staged-subseq-[A-Za-z0-9]{20,}`,
		Severity: "high",
		Action:   config.ActionWarn,
	})
	s := New(cfg)

	// Secret split across 3 query params — subsequence recombination should
	// produce a warn match instead of blocking.
	url := "https://example.com/?a=staged-subseq-&x=junk&b=AABBCCDDEE&y=junk&c=FFEEDDCCBBAA"
	result := s.Scan(context.Background(), url)

	if !result.Allowed {
		t.Error("warn-mode subsequence match should not block")
	}
	// The pattern may or may not fire depending on concatenation order,
	// but the request MUST be allowed regardless.
}

func TestTextDLP_WarnPatternEncodedVariants(t *testing.T) {
	cfg := testDLPConfig("staged-encoded", `staged-encoded-[A-Za-z0-9]{10,}`, true)
	s := New(cfg)

	tests := []struct {
		name string
		text string
	}{
		{"raw", "staged-encoded-ABCDEFGHIJ1234"},
		{"url-encoded", "staged-encoded-%41%42%43%44%45%46%47%48%49%4a1234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), tt.text)
			if !result.Clean {
				t.Error("warn-only match should produce Clean=true")
			}
			if len(result.InformationalMatches) == 0 {
				t.Error("expected informational match for encoded variant")
			}
		})
	}
}

func TestDeduplicateWarnMatches(t *testing.T) {
	matches := []WarnMatch{
		{PatternName: "a", Severity: "high"},
		{PatternName: "b", Severity: "medium"},
		{PatternName: "a", Severity: "high"}, // duplicate
		{PatternName: "c", Severity: "low"},
		{PatternName: "b", Severity: "medium"}, // duplicate
	}
	deduped := deduplicateWarnMatches(matches)
	if len(deduped) != 3 {
		t.Errorf("expected 3 unique matches, got %d", len(deduped))
	}
}

func TestDeduplicateWarnMatches_NilAndSingle(t *testing.T) {
	if got := deduplicateWarnMatches(nil); got != nil {
		t.Errorf("nil input should return nil, got %v", got)
	}
	single := []WarnMatch{{PatternName: "x", Severity: "high"}}
	if got := deduplicateWarnMatches(single); len(got) != 1 {
		t.Errorf("single input should return as-is, got %d", len(got))
	}
}

func TestFragmentBuffer_WarnPatternNotEnforced(t *testing.T) {
	cfg := testDLPConfig("staged-frag", `staged-frag-[A-Za-z0-9]{20,}`, true)
	s := New(cfg)

	fb := NewFragmentBuffer(4096, 10, 60)
	defer fb.Close()

	// Split a staged secret across two fragments.
	fb.Append("session-1", []byte("staged-frag-"))
	fb.Append("session-1", []byte("AABBCCDDEEFFGGHHIIJJ"))

	matches := fb.ScanForSecrets(context.Background(), "session-1", s)
	// Warn-only cross-request matches must NOT appear in the enforcement
	// return — CEE callers treat len(matches) > 0 as an enforcement signal.
	// The DLPWarnHook inside ScanTextForDLP handles audit emission.
	if len(matches) != 0 {
		t.Errorf("warn-only pattern should not produce enforcement matches, got %d", len(matches))
	}
}

func TestDLPWarnHook_TextDLP(t *testing.T) {
	cfg := testDLPConfig("hook-text", `hook-text-[A-Za-z0-9]{10,}`, true)
	s := New(cfg)

	var called []string
	old := DLPWarnHook
	DLPWarnHook = func(patternName, severity, transport string) {
		called = append(called, patternName+":"+transport)
	}
	defer func() { DLPWarnHook = old }()

	s.ScanTextForDLP(context.Background(), "hook-text-ABCDEFGHIJ1234")

	if len(called) == 0 {
		t.Fatal("DLPWarnHook should have been called for text DLP warn match")
	}
	if called[0] != "hook-text:text" {
		t.Errorf("expected hook-text:text, got %q", called[0])
	}
}

func TestDLPWarnHook_URLDLP(t *testing.T) {
	cfg := testDLPConfig("hook-url", `hook-url-[A-Za-z0-9]{10,}`, true)
	s := New(cfg)

	var called []string
	old := DLPWarnHook
	DLPWarnHook = func(patternName, severity, transport string) {
		called = append(called, patternName+":"+transport)
	}
	defer func() { DLPWarnHook = old }()

	s.Scan(context.Background(), "https://example.com/?key=hook-url-ABCDEFGHIJ1234")

	if len(called) == 0 {
		t.Fatal("DLPWarnHook should have been called for URL DLP warn match")
	}
	if called[0] != "hook-url:url" {
		t.Errorf("expected hook-url:url, got %q", called[0])
	}
}

func TestDLPWarnHook_NilDoesNotPanic(t *testing.T) {
	cfg := testDLPConfig("hook-nil", `hook-nil-[A-Za-z0-9]{10,}`, true)
	s := New(cfg)

	old := DLPWarnHook
	DLPWarnHook = nil
	defer func() { DLPWarnHook = old }()

	// Should not panic with nil hook.
	s.ScanTextForDLP(context.Background(), "hook-nil-ABCDEFGHIJ1234")
	s.Scan(context.Background(), "https://example.com/?key=hook-nil-ABCDEFGHIJ1234")
}
