// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// goosWindows is the runtime.GOOS string for Windows. Extracted so the
// symlink-skip predicate across multiple test files can share the
// literal (goconst).
const goosWindows = "windows"

// These tests exercise low-level YAML helper functions directly so we
// hit the defensive nil/empty branches that the canonical fixture
// can't reach (e.g. nil document, scalar where a mapping is expected).
// They give the helpers ≥95% coverage without polluting the
// integration tests with synthetic structural malformations.

func TestDocumentRoot_Nil(t *testing.T) {
	if got := documentRoot(nil); got != nil {
		t.Errorf("expected nil for nil doc, got %v", got)
	}
}

func TestDocumentRoot_EmptyDocument(t *testing.T) {
	doc := &yaml.Node{Kind: yaml.DocumentNode}
	if got := documentRoot(doc); got != nil {
		t.Errorf("expected nil for empty document, got %v", got)
	}
}

func TestDocumentRoot_NonDocumentNode(t *testing.T) {
	mapping := &yaml.Node{Kind: yaml.MappingNode}
	if got := documentRoot(mapping); got != mapping {
		t.Errorf("expected pass-through for non-document node, got %v", got)
	}
}

func TestMappingValue_NilNode(t *testing.T) {
	if got := mappingValue(nil, "any"); got != nil {
		t.Errorf("expected nil for nil node, got %v", got)
	}
}

func TestMappingValue_NonMappingNode(t *testing.T) {
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Value: "bare"}
	if got := mappingValue(scalar, "any"); got != nil {
		t.Errorf("expected nil for scalar node, got %v", got)
	}
}

func TestMappingValue_AbsentKey(t *testing.T) {
	m := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "present"},
			{Kind: yaml.ScalarNode, Value: "v"},
		},
	}
	if got := mappingValue(m, "absent"); got != nil {
		t.Errorf("expected nil for absent key, got %v", got)
	}
}

func TestMappingScalar_AbsentReturnsEmpty(t *testing.T) {
	m := &yaml.Node{Kind: yaml.MappingNode}
	if got := mappingScalar(m, "absent"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestMappingScalar_NonScalarReturnsEmpty(t *testing.T) {
	m := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "k"},
			{Kind: yaml.SequenceNode}, // non-scalar value
		},
	}
	if got := mappingScalar(m, "k"); got != "" {
		t.Errorf("expected empty for non-scalar value, got %q", got)
	}
}

func TestSetMappingScalar_NilSafe(t *testing.T) {
	setMappingScalar(nil, "k", "v") // must not panic
}

func TestSetMappingScalar_NonMappingSafe(t *testing.T) {
	setMappingScalar(&yaml.Node{Kind: yaml.ScalarNode}, "k", "v") // no-op
}

func TestSetMappingScalar_ReplacesExisting(t *testing.T) {
	m := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "k"},
			{Kind: yaml.ScalarNode, Value: "old"},
		},
	}
	setMappingScalar(m, "k", "new")
	if m.Content[1].Value != "new" {
		t.Errorf("expected replaced value 'new', got %q", m.Content[1].Value)
	}
}

func TestSetMappingScalar_AppendsNew(t *testing.T) {
	m := &yaml.Node{Kind: yaml.MappingNode}
	setMappingScalar(m, "k", "v")
	if len(m.Content) != 2 {
		t.Fatalf("expected 2 content entries after append, got %d", len(m.Content))
	}
	if m.Content[0].Value != "k" || m.Content[1].Value != "v" {
		t.Errorf("expected appended k=v, got %q=%q", m.Content[0].Value, m.Content[1].Value)
	}
}

func TestEnsureMappingSeq_CreatesWhenAbsent(t *testing.T) {
	m := &yaml.Node{Kind: yaml.MappingNode}
	seq := ensureMappingSeq(m, "k")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		t.Errorf("expected new sequence node, got %v", seq)
	}
	if len(m.Content) != 2 {
		t.Errorf("expected key+seq appended, got %d entries", len(m.Content))
	}
}

func TestEnsureMappingSeq_ReplacesNonSequence(t *testing.T) {
	m := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "k"},
			{Kind: yaml.ScalarNode, Value: "scalar-was-here"},
		},
	}
	seq := ensureMappingSeq(m, "k")
	if seq.Kind != yaml.SequenceNode {
		t.Errorf("expected upgraded to sequence, got kind=%v", seq.Kind)
	}
	if seq.Value != "" {
		t.Errorf("expected scalar value cleared, got %q", seq.Value)
	}
}

func TestEnsureMappingSeq_PassesThroughExistingSeq(t *testing.T) {
	existing := &yaml.Node{Kind: yaml.SequenceNode}
	m := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "k"},
			existing,
		},
	}
	seq := ensureMappingSeq(m, "k")
	if seq != existing {
		t.Errorf("expected pass-through of existing seq")
	}
}

func TestNodeIntValue_NilReturnsFalse(t *testing.T) {
	_, ok := nodeIntValue(nil)
	if ok {
		t.Errorf("expected ok=false for nil node")
	}
}

func TestNodeIntValue_NonScalarReturnsFalse(t *testing.T) {
	_, ok := nodeIntValue(&yaml.Node{Kind: yaml.SequenceNode})
	if ok {
		t.Errorf("expected ok=false for non-scalar")
	}
}

func TestNodeIntValue_NonNumericReturnsFalse(t *testing.T) {
	_, ok := nodeIntValue(&yaml.Node{Kind: yaml.ScalarNode, Value: "not-a-number"})
	if ok {
		t.Errorf("expected ok=false for non-numeric scalar")
	}
}

func TestNodeIntValue_HappyPath(t *testing.T) {
	v, ok := nodeIntValue(&yaml.Node{Kind: yaml.ScalarNode, Value: "42"})
	if !ok || v != 42 {
		t.Errorf("expected (42,true), got (%d,%v)", v, ok)
	}
}

// TestFindRule_NonMappingRuleEntry confirms findRule skips a sequence
// entry that isn't a mapping (e.g. a stray scalar in `rules:`) without
// panicking.
func TestFindRule_NonMappingRuleEntry(t *testing.T) {
	body := `---
rules:
  - just-a-string-not-a-mapping
  - rule_id: r-test-001
    selector:
      paths: []
`
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rule, err := findRule(&doc, "r-test-001")
	if err != nil {
		t.Fatalf("expected to find rule despite stray scalar, got %v", err)
	}
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
}

// TestSplitRule_NonMappingPathEntry confirms splitRule skips a stray
// scalar in `paths:` without panicking.
func TestSplitRule_NonMappingPathEntry(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-001
    selector:
      paths:
        - just-a-string
        - value: /a/*
          normalization:
            collapsed_segments:
              - index: 2
                reason: high_entropy_identifier_segment
            retained_segments: []
`
	cand := writeTestCandidate(t, body)

	stdout, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-001",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if stdout == "" {
		t.Errorf("expected non-empty stdout")
	}
}

// TestSplitNormalization_NonMappingCollapsedEntry confirms a stray
// scalar inside collapsed_segments is preserved (kept) rather than
// lost or causing a panic.
func TestSplitNormalization_NonMappingCollapsedEntry(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-001
    selector:
      paths:
        - value: /a/*/*
          normalization:
            collapsed_segments:
              - bare-string
              - index: 2
                reason: high_entropy_identifier_segment
            retained_segments: []
`
	cand := writeTestCandidate(t, body)

	if _, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-001",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	parsed := loadParsed(t, cand)
	rule := findRuleNode(parsed, "r-test-001")
	norm := firstNorm(rule)
	collapsed, _ := norm["collapsed_segments"].([]interface{})
	// The bare string survives the demotion; mapping entry got moved.
	if len(collapsed) != 1 {
		t.Errorf("expected 1 collapsed entry kept (the bare string), got %d", len(collapsed))
	}
}

// TestPinRule_NonMappingPathEntry confirms a stray scalar in paths
// doesn't cause pin to crash.
func TestPinRule_NonMappingPathEntry(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-001
    selector:
      paths:
        - just-a-string
        - value: /a/*
          normalization:
            collapsed_segments: []
            retained_segments: []
`
	cand := writeTestCandidate(t, body)

	if _, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-001",
		"--segment", "users",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

// TestLoadCandidate_EmptyPath exercises the empty-string short
// circuit in loadCandidate. The cobra MarkFlagRequired catches
// "missing flag" but a caller passing the empty string directly
// (or the flag value being explicitly "") should still reject.
func TestLoadCandidate_EmptyPath(t *testing.T) {
	_, _, err := loadCandidate("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

// TestFindRule_NoTopLevelMapping confirms the document-without-root
// branch of findRule.
func TestFindRule_NoTopLevelMapping(t *testing.T) {
	// Document with a sequence at the root, no mapping.
	doc := &yaml.Node{
		Kind:    yaml.DocumentNode,
		Content: []*yaml.Node{{Kind: yaml.SequenceNode}},
	}
	_, err := findRule(doc, "any")
	if err == nil {
		t.Fatal("expected error for no top-level mapping")
	}
}

// TestRebuildPathValue_NoNormalization confirms the "no
// normalization block" early return in rebuildPathValue.
func TestRebuildPathValue_NoNormalization(t *testing.T) {
	p := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "value"},
			{Kind: yaml.ScalarNode, Value: "/foo"},
		},
	}
	rebuildPathValue(p) // must not panic
}

// TestRebuildPathValue_NoIndices confirms the "no indices observed"
// early return when normalization has only segments without index.
func TestRebuildPathValue_NoIndices(t *testing.T) {
	body := `---
rules:
  - rule_id: r-no-idx
    selector:
      paths:
        - value: /static
          normalization:
            collapsed_segments: []
            retained_segments:
              - value: static
                reason: low_entropy_literal_segment
`
	cand := writeTestCandidate(t, body)
	if _, err := runSplitCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-no-idx",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

// TestPinNormalization_NonMappingExistingEntry confirms a stray
// scalar in pinned_segments is skipped rather than being treated as
// the matching value.
func TestPinNormalization_NonMappingExistingEntry(t *testing.T) {
	body := `---
rules:
  - rule_id: r-test-001
    selector:
      paths:
        - value: /a/*
          normalization:
            collapsed_segments: []
            retained_segments: []
            pinned_segments:
              - bare-scalar
              - value: existing
                reason: operator_pin
`
	cand := writeTestCandidate(t, body)

	if _, err := runPinCobra(t, []string{
		"--candidate", cand,
		"--rule", "r-test-001",
		"--segment", "users",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	parsed := loadParsed(t, cand)
	rule := findRuleNode(parsed, "r-test-001")
	norm := firstNorm(rule)
	pinned, _ := norm["pinned_segments"].([]interface{})
	// bare-scalar kept, existing kept, users added.
	if len(pinned) != 3 {
		t.Errorf("expected 3 entries (bare + existing + users), got %d", len(pinned))
	}
}

// TestValidateSegmentLiteral_Grammar pins the closed grammar that both
// pin --segment input and split-time YAML reads must satisfy. Each row
// names exactly one rejection class so a future regression points at
// the offending validator branch.
func TestValidateSegmentLiteral_Grammar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        string
		wantOK    bool
		wantSubst string // substring expected in the error if !wantOK
	}{
		{name: "happy_alpha", in: "users", wantOK: true},
		{name: "happy_alphanumeric", in: "v1abc123", wantOK: true},
		{name: "happy_dash_underscore_dot", in: "release-2026.04_29", wantOK: true},
		{name: "rejects_empty", in: "", wantOK: false, wantSubst: "empty"},
		{name: "rejects_path_separator_leading", in: "/admin", wantOK: false, wantSubst: "path separator"},
		{name: "rejects_path_separator_embedded", in: "users/me", wantOK: false, wantSubst: "path separator"},
		{name: "rejects_nul_byte", in: "abc\x00def", wantOK: false, wantSubst: "control"},
		{name: "rejects_newline", in: "abc\ndef", wantOK: false, wantSubst: "control"},
		{name: "rejects_carriage_return", in: "abc\rdef", wantOK: false, wantSubst: "control"},
		{name: "rejects_tab", in: "abc\tdef", wantOK: false, wantSubst: "control"},
		{name: "rejects_del", in: "abc\x7fdef", wantOK: false, wantSubst: "control"},
		{name: "rejects_wildcard_star", in: "*", wantOK: false, wantSubst: "wildcard"},
		{name: "rejects_wildcard_question", in: "ab?", wantOK: false, wantSubst: "wildcard"},
		{name: "rejects_bracket_open", in: "ab[c", wantOK: false, wantSubst: "bracket"},
		{name: "rejects_bracket_close", in: "ab]c", wantOK: false, wantSubst: "bracket"},
		{name: "rejects_overlong", in: strings.Repeat("a", 257), wantOK: false, wantSubst: "exceeds"},
		{name: "boundary_exactly_max_len", in: strings.Repeat("a", 256), wantOK: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateSegmentLiteral(tc.in)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("validateSegmentLiteral(%q) = %v, want nil", tc.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateSegmentLiteral(%q) = nil, want error", tc.in)
			}
			if !errors.Is(err, ErrInvalidSegment) {
				t.Errorf("validateSegmentLiteral(%q): err not ErrInvalidSegment-wrapped: %v", tc.in, err)
			}
			if tc.wantSubst != "" && !strings.Contains(err.Error(), tc.wantSubst) {
				t.Errorf("validateSegmentLiteral(%q): err %q lacks expected substring %q", tc.in, err, tc.wantSubst)
			}
		})
	}
}

// TestPin_RejectsInvalidSegment proves the pin --segment input boundary
// applies validateSegmentLiteral so an operator typo cannot poison the
// candidate.
func TestPin_RejectsInvalidSegment(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cand := filepath.Join(dir, "cand.yaml")
	if err := os.WriteFile(cand, []byte(canonicalCandidate), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}

	tests := []struct {
		name    string
		segment string
	}{
		{"path_separator", "/admin"},
		{"wildcard", "*"},
		{"control_char", "ab\x00cd"},
		{"newline", "ab\ncd"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := pinCmd()
			cmd.SetArgs([]string{"--candidate", cand, "--rule", "r-test-rule-001", "--segment", tc.segment})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected ErrInvalidSegment for %q, got nil", tc.segment)
			}
			if !errors.Is(err, ErrInvalidSegment) {
				t.Errorf("err not ErrInvalidSegment-wrapped: %v", err)
			}
		})
	}
}

// TestLoadCandidate_RejectsSymlink proves the trust boundary on
// candidate input: a symlink at the candidate path is rejected up
// front rather than chased to its target.
func TestLoadCandidate_RejectsSymlink(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == goosWindows {
		t.Skip("symlink semantics differ on Windows; covered by Lstat regular-file branch")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte(canonicalCandidate), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, _, err := loadCandidate(link)
	if err == nil {
		t.Fatalf("expected ErrInvalidCandidate on symlink, got nil")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("err not ErrInvalidCandidate-wrapped: %v", err)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("err message lacks 'symlink': %v", err)
	}
}

// TestLoadCandidate_RejectsNonRegular proves the regular-file gate by
// pointing at a directory.
func TestLoadCandidate_RejectsNonRegular(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, _, err := loadCandidate(dir)
	if err == nil {
		t.Fatalf("expected ErrInvalidCandidate on directory, got nil")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("err not ErrInvalidCandidate-wrapped: %v", err)
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("err message lacks 'regular file': %v", err)
	}
}

// TestResolveOut_RejectsSymlinkOut proves the trust boundary on
// --out: an existing symlink at the destination is rejected before
// the atomic rename runs.
func TestResolveOut_RejectsSymlinkOut(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == goosWindows {
		t.Skip("symlink semantics differ on Windows")
	}

	dir := t.TempDir()
	cand := filepath.Join(dir, "cand.yaml")
	if err := os.WriteFile(cand, []byte("hi\n"), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}
	target := filepath.Join(dir, "elsewhere.yaml")
	if err := os.WriteFile(target, []byte("hi\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	out := filepath.Join(dir, "out.yaml")
	if err := os.Symlink(target, out); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := resolveOut(cand, out)
	if err == nil {
		t.Fatalf("expected ErrInvalidCandidate on --out symlink, got nil")
	}
	if !errors.Is(err, ErrInvalidCandidate) {
		t.Errorf("err not ErrInvalidCandidate-wrapped: %v", err)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("err message lacks 'symlink': %v", err)
	}
}

// TestResolveOut_AcceptsNonExistentOut proves the creation case: an
// --out path that does not exist yet is fine; the atomic-write path
// will create it without resolving any symlink.
func TestResolveOut_AcceptsNonExistentOut(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cand := filepath.Join(dir, "cand.yaml")
	out := filepath.Join(dir, "new.yaml")

	got, err := resolveOut(cand, out)
	if err != nil {
		t.Fatalf("expected nil on non-existent --out, got %v", err)
	}
	if got != out {
		t.Errorf("expected returned dest = %q, got %q", out, got)
	}
}

// TestValidateRuleSegments_RejectsMaliciousYAML proves the YAML-side
// boundary: a candidate carrying a path-separator literal in a
// retained_segments value is rejected before any mutation runs.
func TestValidateRuleSegments_RejectsMaliciousYAML(t *testing.T) {
	t.Parallel()

	const malicious = `---
contract_version: v2.4
rules:
  - rule_id: r-test-rule-001
    selector:
      paths:
        - value: /repos/*
          normalization:
            algorithm: frequency_weighted_entropy_v1
            bucket: {host: api.example.com, method: GET, parent_prefix: /repos}
            retained_segments:
              - {index: 1, value: "users/me", reason: low_entropy_literal_segment}
            collapsed_segments: []
            pinned_segments: []
`

	dir := t.TempDir()
	cand := filepath.Join(dir, "evil.yaml")
	if err := os.WriteFile(cand, []byte(malicious), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}

	cmd := splitCmd()
	cmd.SetArgs([]string{"--candidate", cand, "--rule", "r-test-rule-001"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected ErrInvalidSegment on malicious YAML, got nil")
	}
	if !errors.Is(err, ErrInvalidSegment) {
		t.Errorf("err not ErrInvalidSegment-wrapped: %v", err)
	}
	if !strings.Contains(err.Error(), "path separator") {
		t.Errorf("err message lacks 'path separator': %v", err)
	}
}

// TestEmitAuditEvent_StructuredOnStderr proves both runners write a
// JSON-formatted audit event to stderr alongside the human-readable
// stdout summary. Asserts the required fields are present and that
// the line is parseable JSON.
func TestEmitAuditEvent_StructuredOnStderr(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cand := filepath.Join(dir, "cand.yaml")
	if err := os.WriteFile(cand, []byte(canonicalCandidate), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}

	t.Run("split", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		cmd := splitCmd()
		cmd.SetArgs([]string{"--candidate", cand, "--rule", "r-test-rule-001"})
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("split: %v", err)
		}
		var ev auditEvent
		if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &ev); err != nil {
			t.Fatalf("stderr line is not JSON: %v\n%s", err, stderr.String())
		}
		if ev.Event != "learn_split" {
			t.Errorf("event = %q, want learn_split", ev.Event)
		}
		if ev.Rule != "r-test-rule-001" {
			t.Errorf("rule = %q, want r-test-rule-001", ev.Rule)
		}
		if ev.Candidate != cand {
			t.Errorf("candidate = %q, want %q", ev.Candidate, cand)
		}
		if ev.Dest != cand {
			t.Errorf("dest = %q, want %q (in-place)", ev.Dest, cand)
		}
	})

	t.Run("pin", func(t *testing.T) {
		t.Parallel()
		// Distinct candidate file so the parallel split test cannot race.
		c2 := filepath.Join(dir, "cand-pin.yaml")
		if err := os.WriteFile(c2, []byte(canonicalCandidate), 0o600); err != nil {
			t.Fatalf("write candidate: %v", err)
		}
		var stdout, stderr bytes.Buffer
		cmd := pinCmd()
		cmd.SetArgs([]string{"--candidate", c2, "--rule", "r-test-rule-001", "--segment", "production"})
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("pin: %v", err)
		}
		var ev auditEvent
		if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &ev); err != nil {
			t.Fatalf("stderr line is not JSON: %v\n%s", err, stderr.String())
		}
		if ev.Event != "learn_pin" {
			t.Errorf("event = %q, want learn_pin", ev.Event)
		}
		if ev.Segment != "production" {
			t.Errorf("segment = %q, want production", ev.Segment)
		}
		if ev.NoOp {
			t.Errorf("noop = true, want false (first pin)")
		}
	})
}
