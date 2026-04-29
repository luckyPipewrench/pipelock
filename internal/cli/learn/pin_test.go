// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testPinSegment is the canonical literal used for pinning across the
// pin tests. Extracted to satisfy goconst.
const testPinSegment = "users"

// runPinCobra executes the pin subcommand with the given args against
// fresh in-memory stdout/stderr buffers and returns (stdout, err).
func runPinCobra(t *testing.T, args []string) (string, error) {
	t.Helper()
	cmd := pinCmd()
	var stdout strings.Builder
	cmd.SetOut(&stdout)
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

// pinnedValues returns the list of pinned segment values on the first
// path of the rule.
func pinnedValues(t *testing.T, parsed map[string]interface{}, ruleID string) []string {
	t.Helper()
	rule := findRuleNode(parsed, ruleID)
	if rule == nil {
		return nil
	}
	norm := firstNorm(rule)
	if norm == nil {
		return nil
	}
	pinned, ok := norm["pinned_segments"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(pinned))
	for _, e := range pinned {
		em, _ := e.(map[string]interface{})
		v, _ := em["value"].(string)
		out = append(out, v)
	}
	return out
}

func TestPin_HappyPath_AddsPin(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	stdout, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "pinned") {
		t.Errorf("expected 'pinned' in stdout, got %q", stdout)
	}

	parsed := loadParsed(t, cand)
	got := pinnedValues(t, parsed, testRuleID)
	if len(got) != 1 || got[0] != testPinSegment {
		t.Errorf("expected pinned_segments=[users], got %v", got)
	}
}

func TestPin_Idempotent(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	if _, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
	}); err != nil {
		t.Fatalf("first pin: %v", err)
	}

	stdout, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
	})
	if err != nil {
		t.Fatalf("second pin: %v", err)
	}
	if !strings.Contains(stdout, "already pinned") {
		t.Errorf("expected 'already pinned' note, got %q", stdout)
	}

	parsed := loadParsed(t, cand)
	got := pinnedValues(t, parsed, testRuleID)
	if len(got) != 1 {
		t.Errorf("expected 1 pinned entry after duplicate pin, got %v", got)
	}
}

func TestPin_PreservesExistingPins(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	if _, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testOtherRule,
		"--segment", "auth",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	parsed := loadParsed(t, cand)
	got := pinnedValues(t, parsed, testOtherRule)
	// Original fixture has "existing-pin"; we added "auth".
	if len(got) != 2 {
		t.Fatalf("expected 2 pinned entries, got %d (%v)", len(got), got)
	}
	hasExisting := false
	hasAuth := false
	for _, v := range got {
		switch v {
		case "existing-pin":
			hasExisting = true
		case "auth":
			hasAuth = true
		}
	}
	if !hasExisting || !hasAuth {
		t.Errorf("expected both existing-pin and auth, got %v", got)
	}
}

func TestPin_RejectsMissingRule(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	_, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-does-not-exist",
		"--segment", testPinSegment,
	})
	if err == nil {
		t.Fatal("expected error for missing rule")
	}
	if !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("expected ErrRuleNotFound, got %v", err)
	}
}

func TestPin_AtomicWrite_OnFailure(t *testing.T) {
	if runtime.GOOS == goosWindows {
		t.Skip("read-only directory semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 0o500 doesn't restrict writes")
	}

	cand := writeTestCandidate(t, canonicalCandidate)
	original, err := os.ReadFile(filepath.Clean(cand))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	dir := filepath.Dir(cand)
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // test: intentionally restrictive perms
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // test: restore dir permissions for cleanup

	_, err = runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
	})
	if err == nil {
		t.Fatal("expected error when write target is read-only")
	}

	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // test: restore dir permissions
		t.Fatalf("chmod back: %v", err)
	}
	after, err := os.ReadFile(filepath.Clean(cand))
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(original) != string(after) {
		t.Errorf("candidate was mutated despite write failure")
	}
}

func TestPin_OutFlag_WritesElsewhere(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)
	original, err := os.ReadFile(filepath.Clean(cand))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "pin-output.yaml")

	_, err = runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
		"--out", outPath,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("expected --out file to exist: %v", err)
	}

	after, err := os.ReadFile(filepath.Clean(cand))
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	if string(original) != string(after) {
		t.Errorf("candidate file should be unchanged when --out is set")
	}

	parsed := loadParsed(t, outPath)
	got := pinnedValues(t, parsed, testRuleID)
	if len(got) != 1 || got[0] != testPinSegment {
		t.Errorf("expected pinned_segments=[users] in --out file, got %v", got)
	}
}

func TestPin_InvalidYAML_Rejects(t *testing.T) {
	dir := t.TempDir()
	cand := filepath.Join(dir, testFile)
	if err := os.WriteFile(cand, []byte("not: valid: yaml: nope:::"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate, got %v", err)
	}
}

func TestPin_EmptySegmentRejects(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	_, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", "   ",
	})
	if err == nil {
		t.Fatal("expected error for whitespace-only segment")
	}
	if !errors.Is(err, ErrEmptySegment) {
		t.Errorf("expected ErrEmptySegment, got %v", err)
	}
}

func TestPin_RejectsRelativeCandidate(t *testing.T) {
	_, err := runPinCobra(t, []string{
		"--candidate", "relative/path.yaml",
		"--rule", testRuleID,
		"--segment", testPinSegment,
	})
	if err == nil {
		t.Fatal("expected error for relative candidate path")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate for relative path, got %v", err)
	}
}

func TestPin_RejectsRelativeOut(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	_, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
		"--out", "relative.yaml",
	})
	if err == nil {
		t.Fatal("expected error for relative --out")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate for relative --out, got %v", err)
	}
}

func TestPin_HelpText(t *testing.T) {
	cmd := pinCmd()
	if !strings.Contains(cmd.Long, "Pinned segments") {
		t.Errorf("pin Long should describe pinned semantics; got %q", cmd.Long)
	}
	if !strings.Contains(cmd.Long, "atomic") {
		t.Errorf("pin Long should mention atomic write; got %q", cmd.Long)
	}
}

func TestPin_RejectsPositionalArgs(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	_, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
		"stray",
	})
	if err == nil {
		t.Fatal("expected error for stray positional argument")
	}
}

func TestPin_NoRulesSection(t *testing.T) {
	dir := t.TempDir()
	cand := filepath.Join(dir, testFile)
	if err := os.WriteFile(cand, []byte("contract_version: v2.4\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
	})
	if err == nil {
		t.Fatal("expected error for missing rules section")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate, got %v", err)
	}
}

func TestPin_RuleWithoutSelector(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-noselector
`
	cand := writeTestCandidate(t, body)

	stdout, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-noselector",
		"--segment", testPinSegment,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "already pinned") {
		t.Errorf("expected idempotent no-op note for no-selector rule, got %q", stdout)
	}
}

func TestPin_RejectsNonexistentCandidate(t *testing.T) {
	_, err := runPinCobra(t, []string{
		"--candidate", "/nonexistent/path/candidate.yaml",
		"--rule", testRuleID,
		"--segment", testPinSegment,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent candidate")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate, got %v", err)
	}
}

func TestPin_NormalizationWithoutPinnedSegments(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-no-pinned
    selector:
      paths:
        - value: /a/*
          normalization:
            collapsed_segments:
              - index: 2
                reason: high_entropy_identifier_segment
            retained_segments:
              - index: 1
                value: a
                reason: low_entropy_literal_segment
`
	cand := writeTestCandidate(t, body)

	if _, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-no-pinned",
		"--segment", testPinSegment,
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	parsed := loadParsed(t, cand)
	got := pinnedValues(t, parsed, "r-test-no-pinned")
	if len(got) != 1 || got[0] != testPinSegment {
		t.Errorf("expected new pinned_segments=[users], got %v", got)
	}
}

func TestPin_RequiredFlagsEnforced(t *testing.T) {
	// Missing all required flags: cobra should fail.
	_, err := runPinCobra(t, []string{})
	if err == nil {
		t.Fatal("expected error for missing required flags")
	}
}

func TestPin_OutputPermissionsSecure(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)
	if _, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", testPinSegment,
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	st, err := os.Stat(cand)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := st.Mode().Perm()
	if mode&0o077 != 0 {
		t.Errorf("output perms %#o leak group/other access; expected 0o600 floor", mode)
	}
}

func TestPin_TrimWhitespaceFromSegment(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	if _, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--segment", "  users  ",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	parsed := loadParsed(t, cand)
	got := pinnedValues(t, parsed, testRuleID)
	if len(got) != 1 || got[0] != testPinSegment {
		t.Errorf("expected trimmed segment 'users', got %v", got)
	}
}
