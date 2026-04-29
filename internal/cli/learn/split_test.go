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

	"gopkg.in/yaml.v3"
)

// Shared test constants. Extracted to satisfy goconst.
const (
	testRuleID    = "r-test-rule-001"
	testOtherRule = "r-test-rule-002"
	testFile      = "candidate.yaml"
)

// canonicalCandidate is the synthetic candidate YAML used across the
// split + pin test suites. Two paths, both with two collapsed
// segments and one retained segment. The shape mirrors the
// candidate-contract YAML emitted by the future compile pipeline
// without committing to the full schema.
const canonicalCandidate = `---
contract_version: v2.4
rules:
  - rule_id: r-test-rule-001
    selector:
      paths:
        - value: /repos/*/*
          normalization:
            algorithm: frequency_weighted_entropy_v1
            collapsed_segments:
              - index: 2
                distinct_values: 87
                event_count: 412
                reason: high_entropy_identifier_segment
              - index: 3
                distinct_values: 14
                event_count: 412
                reason: high_entropy_identifier_segment
            retained_segments:
              - index: 1
                value: repos
                reason: low_entropy_literal_segment
            pinned_segments: []
  - rule_id: r-test-rule-002
    selector:
      paths:
        - value: /api/*
          normalization:
            algorithm: frequency_weighted_entropy_v1
            collapsed_segments:
              - index: 2
                distinct_values: 50
                event_count: 100
                reason: high_entropy_identifier_segment
            retained_segments:
              - index: 1
                value: api
                reason: low_entropy_literal_segment
            pinned_segments:
              - value: existing-pin
                reason: operator_pin
`

// writeCandidate drops the canonical YAML to a tempdir and returns
// its absolute path.
func writeTestCandidate(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, testFile)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return abs
}

// loadParsed reads and parses a YAML file as a map for assertions.
// Walking with yaml.Node would mirror the production code under test;
// using map[string]interface{} keeps the assertion code orthogonal to
// the production parser.
func loadParsed(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out map[string]interface{}
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return out
}

// findRuleNode returns the parsed map for a rule by id, or nil if
// absent.
func findRuleNode(parsed map[string]interface{}, ruleID string) map[string]interface{} {
	rules, ok := parsed["rules"].([]interface{})
	if !ok {
		return nil
	}
	for _, r := range rules {
		m, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if m["rule_id"] == ruleID {
			return m
		}
	}
	return nil
}

// firstNorm returns the normalization map from the first path of a
// rule, or nil if absent.
func firstNorm(rule map[string]interface{}) map[string]interface{} {
	selector, ok := rule["selector"].(map[string]interface{})
	if !ok {
		return nil
	}
	paths, ok := selector["paths"].([]interface{})
	if !ok || len(paths) == 0 {
		return nil
	}
	pmap, ok := paths[0].(map[string]interface{})
	if !ok {
		return nil
	}
	norm, _ := pmap["normalization"].(map[string]interface{})
	return norm
}

// firstPathValue returns the rendered path value from the first path
// of a rule.
func firstPathValue(rule map[string]interface{}) string {
	selector, ok := rule["selector"].(map[string]interface{})
	if !ok {
		return ""
	}
	paths, ok := selector["paths"].([]interface{})
	if !ok || len(paths) == 0 {
		return ""
	}
	pmap, ok := paths[0].(map[string]interface{})
	if !ok {
		return ""
	}
	v, _ := pmap["value"].(string)
	return v
}

// runSplitCobra executes the split subcommand with the given args
// against fresh in-memory stdout/stderr buffers and returns
// (stdout, err).
func runSplitCobra(t *testing.T, args []string) (string, error) {
	t.Helper()
	cmd := splitCmd()
	var stdout strings.Builder
	cmd.SetOut(&stdout)
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

func TestSplit_HappyPath_AllSegments(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	stdout, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "2 segments demoted") {
		t.Errorf("expected '2 segments demoted' in stdout, got %q", stdout)
	}

	parsed := loadParsed(t, cand)
	rule := findRuleNode(parsed, testRuleID)
	if rule == nil {
		t.Fatal("rule disappeared after split")
	}
	norm := firstNorm(rule)
	if norm == nil {
		t.Fatal("normalization disappeared")
	}

	collapsed, _ := norm["collapsed_segments"].([]interface{})
	if len(collapsed) != 0 {
		t.Errorf("expected empty collapsed_segments, got %d entries", len(collapsed))
	}
	retained, _ := norm["retained_segments"].([]interface{})
	// Original retained had 1 entry (index=1). Both demoted entries
	// (index 2 and 3) should now be present with reason=operator_split.
	if len(retained) != 3 {
		t.Errorf("expected 3 retained entries (1 original + 2 demoted), got %d", len(retained))
	}
	demotedCount := 0
	for _, e := range retained {
		em, _ := e.(map[string]interface{})
		if em["reason"] == reasonOperatorSplit {
			demotedCount++
		}
	}
	if demotedCount != 2 {
		t.Errorf("expected 2 entries with reason=%s, got %d", reasonOperatorSplit, demotedCount)
	}
}

func TestSplit_HappyPath_SpecificIndex(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	stdout, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--index", "2",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "1 segments demoted") {
		t.Errorf("expected '1 segments demoted', got %q", stdout)
	}

	parsed := loadParsed(t, cand)
	rule := findRuleNode(parsed, testRuleID)
	norm := firstNorm(rule)

	collapsed, _ := norm["collapsed_segments"].([]interface{})
	if len(collapsed) != 1 {
		t.Errorf("expected 1 remaining collapsed entry, got %d", len(collapsed))
	}
	if len(collapsed) == 1 {
		em, _ := collapsed[0].(map[string]interface{})
		if idx, _ := em["index"].(int); idx != 3 {
			t.Errorf("expected remaining collapsed index=3, got %v", em["index"])
		}
	}
}

func TestSplit_RejectsMissingRule(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	_, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-does-not-exist",
	})
	if err == nil {
		t.Fatal("expected error for missing rule")
	}
	if !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("expected ErrRuleNotFound, got %v", err)
	}
}

func TestSplit_RejectsMissingIndex(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	_, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--index", "99",
	})
	if err == nil {
		t.Fatal("expected error for missing index")
	}
	if !errors.Is(err, ErrCollapsedSegmentNotFound) {
		t.Errorf("expected ErrCollapsedSegmentNotFound, got %v", err)
	}
}

func TestSplit_AtomicWrite_OnFailure(t *testing.T) {
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

	// Make the directory read-only so atomicfile.Write's CreateTemp
	// fails. The candidate file itself stays readable.
	dir := filepath.Dir(cand)
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // test: intentionally restrictive perms
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // test: restore dir permissions for cleanup

	_, err = runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
	})
	if err == nil {
		t.Fatal("expected error when write target is read-only")
	}

	// Restore to read so we can verify the original is untouched.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // test: restore dir permissions
		t.Fatalf("chmod dir back: %v", err)
	}
	after, err := os.ReadFile(filepath.Clean(cand))
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(original) != string(after) {
		t.Errorf("candidate was mutated despite write failure")
	}
}

func TestSplit_OutFlag_WritesElsewhere(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)
	original, err := os.ReadFile(filepath.Clean(cand))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "split-output.yaml")

	_, err = runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
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
}

func TestSplit_Idempotent(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	if _, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
	}); err != nil {
		t.Fatalf("first split: %v", err)
	}

	stdout, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
	})
	if err != nil {
		t.Fatalf("second split: %v", err)
	}
	if !strings.Contains(stdout, "no collapsed segments to demote") {
		t.Errorf("expected idempotent no-op note, got %q", stdout)
	}
}

func TestSplit_InvalidYAML_Rejects(t *testing.T) {
	dir := t.TempDir()
	cand := filepath.Join(dir, testFile)
	if err := os.WriteFile(cand, []byte("not: valid: yaml: nope:::"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate, got %v", err)
	}
}

func TestSplit_RejectsRelativeCandidate(t *testing.T) {
	_, err := runSplitCobra(t, []string{
		"--candidate", "relative/path.yaml",
		"--rule", testRuleID,
	})
	if err == nil {
		t.Fatal("expected error for relative candidate path")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate for relative path, got %v", err)
	}
}

func TestSplit_RejectsNonexistentCandidate(t *testing.T) {
	_, err := runSplitCobra(t, []string{
		"--candidate", "/nonexistent/path/candidate.yaml",
		"--rule", testRuleID,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent candidate")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate, got %v", err)
	}
}

func TestSplit_RejectsRelativeOut(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	_, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"--out", "relative.yaml",
	})
	if err == nil {
		t.Fatal("expected error for relative --out")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate for relative --out, got %v", err)
	}
}

func TestSplit_PathValueRebuilt(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	if _, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	parsed := loadParsed(t, cand)
	rule := findRuleNode(parsed, testRuleID)
	got := firstPathValue(rule)
	// After splitting both collapsed segments (index 2 and 3) back to
	// retained, the path slot for index 2 and 3 has no literal value
	// (the demoted entries don't carry a `value` field in the
	// fixture), so they render as wildcards.
	if got == "" {
		t.Errorf("expected non-empty rebuilt path value")
	}
}

func TestSplit_HelpText(t *testing.T) {
	cmd := splitCmd()
	if !strings.Contains(cmd.Long, "collapsed") {
		t.Errorf("split Long should mention 'collapsed'; got %q", cmd.Long)
	}
	if !strings.Contains(cmd.Long, "atomic") {
		t.Errorf("split Long should mention 'atomic' write semantics; got %q", cmd.Long)
	}
}

func TestSplit_RejectsPositionalArgs(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)

	_, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
		"stray",
	})
	if err == nil {
		t.Fatal("expected error for stray positional argument")
	}
}

// TestCmd_HasSplitAndPinSubcommands confirms learn.go wired both new
// subcommands under the parent.
func TestCmd_HasSplitAndPinSubcommands(t *testing.T) {
	parent := Cmd()
	want := map[string]bool{"split": false, "pin": false, "observe": false}
	for _, sub := range parent.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected %q subcommand wired into `learn`", name)
		}
	}
}

func TestSplit_EmptyCandidateContent(t *testing.T) {
	dir := t.TempDir()
	cand := filepath.Join(dir, testFile)
	if err := os.WriteFile(cand, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	_, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
	})
	if err == nil {
		t.Fatal("expected error for empty candidate")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate, got %v", err)
	}
}

func TestSplit_NoRulesSection(t *testing.T) {
	dir := t.TempDir()
	cand := filepath.Join(dir, testFile)
	if err := os.WriteFile(cand, []byte("contract_version: v2.4\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
	})
	if err == nil {
		t.Fatal("expected error for missing rules section")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("expected ErrInvalidCandidate, got %v", err)
	}
}

// TestSplit_RuleWithoutNormalization confirms a rule that has no
// normalization metadata produces a 0-segment-demoted no-op rather
// than an error.
func TestSplit_RuleWithoutNormalization(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-bare
    selector:
      paths:
        - value: /static
`
	cand := writeTestCandidate(t, body)

	stdout, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-bare",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "no collapsed segments") {
		t.Errorf("expected no-op message, got %q", stdout)
	}
}

func TestSplit_RuleWithoutSelector(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-noselector
`
	cand := writeTestCandidate(t, body)

	stdout, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-noselector",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "no collapsed segments") {
		t.Errorf("expected no-op for no-selector rule, got %q", stdout)
	}
}

// TestSplit_PinnedSegmentsNullPreserved exercises the `null` pinned
// list path through ensureMappingSeq's "exists but not seq" branch.
// It is structural: pin won't crash if pinned_segments was written as
// `~` rather than `[]`.
func TestSplit_PinnedSegmentsNullPreserved(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-null-pinned
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
            pinned_segments: ~
`
	cand := writeTestCandidate(t, body)

	if _, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-null-pinned",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

// TestSplit_NormalizationWithoutCollapsed exercises the "norm exists,
// collapsed_segments absent" branch in splitNormalization.
func TestSplit_NormalizationWithoutCollapsed(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-no-collapsed
    selector:
      paths:
        - value: /static
          normalization:
            algorithm: frequency_weighted_entropy_v1
            retained_segments:
              - index: 1
                value: static
                reason: low_entropy_literal_segment
`
	cand := writeTestCandidate(t, body)

	stdout, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-no-collapsed",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "no collapsed segments") {
		t.Errorf("expected no-op message, got %q", stdout)
	}
}

func TestSplit_RequiredFlagsEnforced(t *testing.T) {
	// Missing both --candidate and --rule: cobra should fail.
	_, err := runSplitCobra(t, []string{})
	if err == nil {
		t.Fatal("expected error for missing required flags")
	}
}

func TestSplit_OutputPermissionsSecure(t *testing.T) {
	cand := writeTestCandidate(t, canonicalCandidate)
	if _, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", testRuleID,
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
