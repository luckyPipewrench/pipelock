// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONLeafBucketLeavesDoNotGlueSiblings(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 8, MaxPathBytes: 256}
	body := json.RawMessage(`{"content":"AKIA","decoy":"INTRUDER"}`)
	leaves, valid := JSONLeafBucketLeaves(body, limits, 1, testJSONLeafBucketKey)
	if !valid {
		t.Fatal("one-bucket document was not valid")
	}
	if len(leaves) != 1 {
		t.Fatalf("bucket count = %d, want 1", len(leaves))
	}
	var got []JSONBucketLeaf
	for _, items := range leaves {
		got = items
	}
	if len(got) != 2 {
		t.Fatalf("leaf count = %d, want 2", len(got))
	}
	if bytes.Equal(got[0].Continuity, got[1].Continuity) {
		t.Fatalf("sibling leaves share continuity %q", got[0].Continuity)
	}
	joined := append(append([]byte(nil), got[0].Value...), got[1].Value...)
	if bytes.Contains(joined, []byte("AKIAINTRUDER")) && bytes.Equal(got[0].Continuity, got[1].Continuity) {
		t.Fatal("siblings were glued")
	}
}

func TestJSONLeafBucketLeavesOrdinalCannotImpersonateAPath(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 8, MaxPathBytes: 256}
	body := json.RawMessage(`{"a#1":"other","a":"first","a":"second"}`)
	leaves, valid := JSONLeafBucketLeaves(body, limits, 1, testJSONLeafBucketKey)
	if !valid {
		t.Fatal("duplicate-key document was not valid")
	}
	var got []JSONBucketLeaf
	for _, items := range leaves {
		got = append(got, items...)
	}
	if len(got) != 3 {
		t.Fatalf("leaf count = %d, want 3", len(got))
	}
	seen := make(map[string]struct{}, len(got))
	for _, leaf := range got {
		key := string(leaf.Continuity)
		if _, ok := seen[key]; ok {
			t.Fatalf("two leaves share continuity %q", leaf.Continuity)
		}
		seen[key] = struct{}{}
	}
}

func TestJSONLeafBucketLeavesKeepFoldedFieldIdentityWhenReordered(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 1, MaxPathBytes: 256}
	forward, valid := JSONLeafBucketLeaves(json.RawMessage(`{"a":{"one":"alpha","two":"beta"}}`), limits, 1, testJSONLeafBucketKey)
	if !valid {
		t.Fatal("forward folded document was not valid")
	}
	reversed, valid := JSONLeafBucketLeaves(json.RawMessage(`{"a":{"two":"beta","one":"alpha"}}`), limits, 1, testJSONLeafBucketKey)
	if !valid {
		t.Fatal("reordered folded document was not valid")
	}
	alpha := continuityOfValue(t, forward, "alpha")
	if !bytes.Equal(alpha, continuityOfValue(t, reversed, "alpha")) {
		t.Fatal("reordering a folded object changed the field identity")
	}
	if bytes.Equal(alpha, continuityOfValue(t, forward, "beta")) {
		t.Fatal("distinct folded fields share continuity")
	}
	arrayForward, _ := JSONLeafBucketLeaves(json.RawMessage(`{"a":["alpha","beta"]}`), limits, 1, testJSONLeafBucketKey)
	arrayReversed, _ := JSONLeafBucketLeaves(json.RawMessage(`{"a":["beta","alpha"]}`), limits, 1, testJSONLeafBucketKey)
	if bytes.Equal(continuityOfValue(t, arrayForward, "alpha"), continuityOfValue(t, arrayReversed, "alpha")) {
		t.Fatal("array index was not part of the folded field identity")
	}
}

func continuityOfValue(t *testing.T, leaves map[string][]JSONBucketLeaf, value string) []byte {
	t.Helper()
	want := []byte(value)
	for _, items := range leaves {
		for _, item := range items {
			if bytes.Equal(item.Value, want) {
				return item.Continuity
			}
		}
	}
	t.Fatalf("value %q was not extracted", value)
	return nil
}

func TestJSONLeafBucketLeavesDisambiguateCollapsedPaths(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 1, MaxPathBytes: 256}
	body := json.RawMessage(`{"a":{"one":"first","two":"second"}}`)
	leaves, _ := JSONLeafBucketLeaves(body, limits, 1, testJSONLeafBucketKey)
	var got []JSONBucketLeaf
	for _, items := range leaves {
		got = append(got, items...)
	}
	if len(got) < 2 {
		t.Fatalf("over-depth leaves = %#v, want both scalars", got)
	}
	if bytes.Equal(got[0].Continuity, got[1].Continuity) {
		t.Fatalf("collapsed leaves share continuity %q", got[0].Continuity)
	}
}
