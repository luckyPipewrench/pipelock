// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"testing"
)

// TestCheckNoDuplicateKeys_FlatObject catches the Rook finding #1 attack:
// a duplicate key at the top object level hides a secret from redaction.
func TestCheckNoDuplicateKeys_FlatObject(t *testing.T) {
	body := []byte(`{"x":"AKIAIOSFODNN7EXAMPLE","x":"benign"}`)
	err := checkNoDuplicateKeys(body)
	if err == nil {
		t.Fatal("expected duplicate-key block, got nil")
	}
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatalf("expected *BlockError, got %T: %v", err, err)
	}
	if be.Reason != ReasonDuplicateKey {
		t.Fatalf("expected ReasonDuplicateKey, got %q", be.Reason)
	}
}

// TestCheckNoDuplicateKeys_NestedObject catches a duplicate that lives
// inside a nested object body.
func TestCheckNoDuplicateKeys_NestedObject(t *testing.T) {
	body := []byte(`{"outer":{"inner":"AKIAIOSFODNN7EXAMPLE","inner":"benign"}}`)
	err := checkNoDuplicateKeys(body)
	if err == nil {
		t.Fatal("expected duplicate-key block, got nil")
	}
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatalf("expected *BlockError, got %T: %v", err, err)
	}
	if be.Reason != ReasonDuplicateKey {
		t.Fatalf("expected ReasonDuplicateKey, got %q", be.Reason)
	}
}

// TestCheckNoDuplicateKeys_InsideArray catches a duplicate hiding inside an
// array element.
func TestCheckNoDuplicateKeys_InsideArray(t *testing.T) {
	body := []byte(`{"items":[{"k":"s1","k":"s2"}]}`)
	err := checkNoDuplicateKeys(body)
	if err == nil {
		t.Fatal("expected duplicate-key block, got nil")
	}
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatalf("expected *BlockError, got %T: %v", err, err)
	}
	if be.Reason != ReasonDuplicateKey {
		t.Fatalf("expected ReasonDuplicateKey, got %q", be.Reason)
	}
}

// TestCheckNoDuplicateKeys_DeepNesting fails closed on a duplicate buried
// several levels deep.
func TestCheckNoDuplicateKeys_DeepNesting(t *testing.T) {
	body := []byte(`{"a":{"b":{"c":{"dup":"1","dup":"2"}}}}`)
	err := checkNoDuplicateKeys(body)
	if err == nil {
		t.Fatal("expected duplicate-key block, got nil")
	}
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatalf("expected *BlockError, got %T: %v", err, err)
	}
	if be.Reason != ReasonDuplicateKey {
		t.Fatalf("expected ReasonDuplicateKey, got %q", be.Reason)
	}
}

// TestCheckNoDuplicateKeys_CleanObject passes through when every object
// has unique keys.
func TestCheckNoDuplicateKeys_CleanObject(t *testing.T) {
	cases := [][]byte{
		[]byte(`{}`),
		[]byte(`{"x":"a"}`),
		[]byte(`{"x":"a","y":"b"}`),
		[]byte(`{"outer":{"inner":"a"}}`),
		[]byte(`{"list":[{"k":"1"},{"k":"2"}]}`), // same key in different objects
		[]byte(`[]`),
		[]byte(`[{"x":"a"},{"x":"b"}]`),
		[]byte(`"bare string"`),
		[]byte(`42`),
		[]byte(`null`),
		[]byte(`true`),
	}
	for _, c := range cases {
		if err := checkNoDuplicateKeys(c); err != nil {
			t.Fatalf("unexpected block for %q: %v", string(c), err)
		}
	}
}

// TestCheckNoDuplicateKeys_MalformedJSON returns ReasonBodyUnparseable
// rather than panicking on broken input.
func TestCheckNoDuplicateKeys_MalformedJSON(t *testing.T) {
	cases := [][]byte{
		[]byte(`{`),
		[]byte(`{"x":`),
		[]byte(`{"x":,}`),
		[]byte(`[1,`),
		[]byte(``),
	}
	for _, c := range cases {
		err := checkNoDuplicateKeys(c)
		if err == nil {
			// Empty body parses to zero tokens in this walker,
			// which is not a duplicate-key case — acceptable.
			continue
		}
		var be *BlockError
		if !errors.As(err, &be) {
			t.Fatalf("expected *BlockError for %q, got %T: %v", string(c), err, err)
		}
		if be.Reason != ReasonBodyUnparseable {
			t.Fatalf("expected ReasonBodyUnparseable for %q, got %q", string(c), be.Reason)
		}
	}
}

// TestRewriteJSON_DuplicateKeyBlocks wires the dup-key check into the
// public Rewrite entry point and confirms the Rook finding #1 curl repro
// pattern fails closed, not collapses silently.
func TestRewriteJSON_DuplicateKeyBlocks(t *testing.T) {
	m := NewDefaultMatcher()
	r := NewRedactor()
	body := []byte(`{"x":"AKIAIOSFODNN7EXAMPLE","x":"benign"}`)

	out, report, err := RewriteJSON(body, m, r, Limits{})
	if err == nil {
		t.Fatalf("expected duplicate-key block, got output %q (report=%+v)", string(out), report)
	}
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatalf("expected *BlockError, got %T: %v", err, err)
	}
	if be.Reason != ReasonDuplicateKey {
		t.Fatalf("expected ReasonDuplicateKey, got %q", be.Reason)
	}
	if out != nil {
		t.Fatalf("expected nil output on block, got %q", string(out))
	}
}

// TestRewriteJSON_NoDuplicateKeys_StillRedacts confirms the happy path
// still runs redaction end-to-end once the dup-key guard is in place.
func TestRewriteJSON_NoDuplicateKeys_StillRedacts(t *testing.T) {
	m := NewDefaultMatcher()
	r := NewRedactor()
	body := []byte(`{"x":"AKIAIOSFODNN7EXAMPLE"}`)

	out, report, err := RewriteJSON(body, m, r, Limits{})
	if err != nil {
		t.Fatalf("unexpected block on clean body: %v", err)
	}
	if report == nil || report.TotalRedactions != 1 {
		t.Fatalf("expected one redaction, got report=%+v", report)
	}
	if string(out) == string(body) {
		t.Fatalf("expected rewritten body to differ from input; got %q", string(out))
	}
	if !containsPlaceholder(out, "aws-access-key") {
		t.Fatalf("expected placeholder in output, got %q", string(out))
	}
}

func containsPlaceholder(body []byte, class string) bool {
	needle := []byte("<pl:" + class + ":")
	for i := 0; i+len(needle) <= len(body); i++ {
		if string(body[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
