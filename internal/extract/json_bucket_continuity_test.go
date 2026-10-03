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

func TestInsertedDuplicateDoesNotMoveTheLastField(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 8, MaxPathBytes: 256}
	first, valid := JSONLeafBucketLeaves(json.RawMessage(`{"x":"PRE"}`), limits, 1, testJSONLeafBucketKey)
	if !valid {
		t.Fatal("single field was not valid")
	}
	second, valid := JSONLeafBucketLeaves(json.RawMessage(`{"x":"decoy","x":"PRE"}`), limits, 1, testJSONLeafBucketKey)
	if !valid {
		t.Fatal("duplicate field was not valid")
	}
	if !bytes.Equal(continuityOfValue(t, first, "PRE"), continuityOfValue(t, second, "PRE")) {
		t.Fatal("an earlier duplicate changed the last field identity")
	}
	if bytes.Equal(continuityOfValue(t, second, "decoy"), continuityOfValue(t, second, "PRE")) {
		t.Fatal("duplicate values share continuity")
	}
	again, _ := JSONLeafBucketLeaves(json.RawMessage(`{"x":"decoy","x":"PRE"}`), limits, 1, testJSONLeafBucketKey)
	if bytes.Equal(continuityOfValue(t, second, "decoy"), continuityOfValue(t, again, "decoy")) {
		t.Fatal("an earlier duplicate reused continuity in the next document")
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

func TestUnattributedLeavesDoNotJoinAcrossDocuments(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 0, MaxPathBytes: 512}
	firstBody := json.RawMessage(`{"w":["KEEP",1 2 "ONE","TWO"]}`)
	secondBody := json.RawMessage(`{"w":["KEEP",1 2 "INSERTED","ONE","TWO"]}`)
	first, valid := JSONLeafBucketLeaves(firstBody, limits, 1, testJSONLeafBucketKey)
	if valid {
		t.Fatal("malformed body reported complete")
	}
	second, _ := JSONLeafBucketLeaves(secondBody, limits, 1, testJSONLeafBucketKey)
	one := continuityOfValue(t, first, "ONE")
	two := continuityOfValue(t, first, "TWO")
	if bytes.Equal(one, two) {
		t.Fatal("unattributed scalars in one document share continuity")
	}
	if bytes.Equal(one, continuityOfValue(t, second, "ONE")) {
		t.Fatal("an inserted scalar kept the next document on the same continuity")
	}
	again, _ := JSONLeafBucketLeaves(firstBody, limits, 1, testJSONLeafBucketKey)
	if bytes.Equal(one, continuityOfValue(t, again, "ONE")) {
		t.Fatal("the same malformed document reused continuity")
	}
}
