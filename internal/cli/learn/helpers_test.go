// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"testing"

	"gopkg.in/yaml.v3"
)

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
