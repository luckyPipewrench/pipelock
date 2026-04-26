// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMerkleRoot_Empty(t *testing.T) {
	t.Parallel()
	got, err := MerkleRoot(nil)
	if err != nil {
		t.Fatalf("MerkleRoot empty: %v", err)
	}
	want := "sha256:" + hex.EncodeToString(sha256Sum([]byte{0x00}))
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMerkleRoot_Single(t *testing.T) {
	t.Parallel()
	r := []Rule{{RuleID: "r-1", RuleKind: "http_destination"}}
	got, err := MerkleRoot(r)
	if err != nil {
		t.Fatalf("MerkleRoot single: %v", err)
	}
	if got == "" {
		t.Error("single rule produced empty root")
	}
}

func TestMerkleRoot_Deterministic(t *testing.T) {
	t.Parallel()
	r := []Rule{
		{RuleID: "r-1", RuleKind: "http_destination"},
		{RuleID: "r-2", RuleKind: "mcp_tool"},
	}
	a, err := MerkleRoot(r)
	if err != nil {
		t.Fatalf("MerkleRoot a: %v", err)
	}
	b, err := MerkleRoot(r)
	if err != nil {
		t.Fatalf("MerkleRoot b: %v", err)
	}
	if a != b {
		t.Errorf("non-deterministic: %q vs %q", a, b)
	}
}

func TestMerkleRoot_OrderSensitive(t *testing.T) {
	t.Parallel()
	r1 := []Rule{
		{RuleID: "r-1"},
		{RuleID: "r-2"},
	}
	r2 := []Rule{
		{RuleID: "r-2"},
		{RuleID: "r-1"},
	}
	a, err := MerkleRoot(r1)
	if err != nil {
		t.Fatalf("MerkleRoot r1: %v", err)
	}
	b, err := MerkleRoot(r2)
	if err != nil {
		t.Fatalf("MerkleRoot r2: %v", err)
	}
	if a == b {
		t.Error("merkle root must be order-sensitive")
	}
}

func TestMerkleRoot_OddCountHandling(t *testing.T) {
	t.Parallel()
	// 3 rules → at level 1, hash(L1+L2) and hash(L3+L3) → level 2 root.
	r := []Rule{{RuleID: "a"}, {RuleID: "b"}, {RuleID: "c"}}
	got, err := MerkleRoot(r)
	if err != nil {
		t.Fatalf("MerkleRoot odd: %v", err)
	}
	if got == "" {
		t.Error("odd-count root empty")
	}
}

// sha256Sum is a tiny test helper for empty-tree expectation.
func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
