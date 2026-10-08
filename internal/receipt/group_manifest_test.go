// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testGroupKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testGroupOpen(t *testing.T, key ed25519.PrivateKey) (ReceiptGroupOpen, []byte, string) {
	t.Helper()
	open, err := SignReceiptGroupOpen(ReceiptGroupOpen{
		GroupID:           strings.Repeat("1", 32),
		BaseSession:       "proxy",
		ShardCount:        2,
		ProcessShardIndex: 0,
		Shards: []ReceiptGroupShard{
			{ShardIndex: 0, SessionID: "proxy.run." + strings.Repeat("a", 32)},
			{ShardIndex: 1, SessionID: "proxy.run." + strings.Repeat("b", 32)},
		},
		CreatedAt: time.Unix(0, 0).UTC().Format(time.RFC3339Nano),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return open, raw, hex.EncodeToString(sum[:])
}

func testGroupHeads(open ReceiptGroupOpen) []ReceiptGroupShardHead {
	heads := make([]ReceiptGroupShardHead, len(open.Shards))
	for i, shard := range open.Shards {
		heads[i] = ReceiptGroupShardHead{
			ShardIndex: i, SessionID: shard.SessionID,
			FinalChainSeq: 3, FinalChainHash: strings.Repeat("c", 64),
			ReceiptCount: 4, SessionCloseHash: strings.Repeat("d", 64),
			TranscriptRootHash: strings.Repeat("e", 64), CheckpointHash: strings.Repeat("f", 64),
			NativeAELFinalSeq: 1, NativeAELFinalHash: strings.Repeat("a", 64), NativeAELRecordCount: 2,
		}
	}
	return heads
}

func TestVerifyGroupTransitionInventoryRejectsForkedPredecessor(t *testing.T) {
	key := testGroupKey(t)
	predecessor, _, oldHash := testGroupOpen(t, key)
	closeHash := strings.Repeat("f", 64)
	predecessors := make([]ReceiptGroupPredecessor, len(predecessor.Shards))
	for i, shard := range predecessor.Shards {
		predecessors[i] = ReceiptGroupPredecessor{
			ShardIndex: i, SessionID: shard.SessionID,
			FinalChainSeq: 3, FinalChainHash: strings.Repeat("c", 64),
		}
	}
	dir := t.TempDir()
	for n, id := range []string{strings.Repeat("2", 32), strings.Repeat("3", 32)} {
		successor, err := SignReceiptGroupOpen(ReceiptGroupOpen{
			GroupID: id, BaseSession: "proxy", ShardCount: 2, ProcessShardIndex: 0,
			PreviousGroupID: predecessor.GroupID, PreviousOpenManifestSHA256: oldHash,
			CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Shards: []ReceiptGroupShard{
				{ShardIndex: 0, SessionID: "proxy.run." + strings.Repeat(string('c'+rune(n*2)), 32)},
				{ShardIndex: 1, SessionID: "proxy.run." + strings.Repeat(string('d'+rune(n*2)), 32)},
			},
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		newHash := strings.Repeat(string('a'+rune(n)), 64)
		tr, err := SignReceiptGroupTransition(ReceiptGroupTransition{
			NewGroupID: id, NewOpenManifestSHA256: newHash,
			PreviousGroupID: predecessor.GroupID, PreviousOpenManifestSHA256: oldHash,
			PreviousCloseManifestSHA256: closeHash, Predecessors: predecessors,
			CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}, successor, predecessor, newHash, oldHash, closeHash, key)
		if err != nil {
			t.Fatal(err)
		}
		name, _ := ReceiptGroupFileName(id, "transition")
		if _, err := PublishReceiptGroupArtifact(dir, name, tr); err != nil {
			t.Fatal(err)
		}
		err = verifyGroupTransitionInventory(dir, oldHash, closeHash, []string{predecessor.SignerKey})
		if n == 0 && (err == nil || !strings.Contains(err.Error(), "successor opening missing")) {
			t.Fatalf("orphan successor transition accepted: %v", err)
		}
		if n == 1 && (err == nil || !strings.Contains(err.Error(), "multiple successor")) {
			t.Fatalf("forked predecessor accepted: %v", err)
		}
	}
}

func TestVerifyGroupTransitionInventoryRejectsMalformedSignedArtifacts(t *testing.T) {
	key := testGroupKey(t)
	open, _, openHash := testGroupOpen(t, key)
	id := strings.Repeat("2", 32)
	name, _ := ReceiptGroupFileName(id, "transition")
	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"unknown field", []byte(`{"unknown":true}`), "unknown"},
		{"wrong filename identity", mustGroupJSON(t, ReceiptGroupTransition{NewGroupID: strings.Repeat("3", 32)}), "identity"},
		{"unsigned transition", mustGroupJSON(t, ReceiptGroupTransition{NewGroupID: id, PreviousOpenManifestSHA256: openHash, SignerKey: open.SignerKey, Signature: "bad"}), "signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), tc.body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := verifyGroupTransitionInventory(dir, openHash, "", []string{open.SignerKey}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malformed transition accepted: %v", err)
			}
		})
	}
}

func mustGroupJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReceiptGroupOpenStrictSignedBytes(t *testing.T) {
	key := testGroupKey(t)
	open, raw, _ := testGroupOpen(t, key)
	trusted := []string{open.SignerKey}
	if _, err := UnmarshalReceiptGroupOpen(raw, trusted); err != nil {
		t.Fatalf("valid open rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{name: "untrusted", raw: raw},
		{name: "empty", raw: nil},
		{name: "oversize", raw: []byte(strings.Repeat("x", maxGroupFileBytes+1))},
		{name: "invalid UTF-8", raw: []byte{0xff}},
		{name: "whitespace", raw: append(append([]byte(nil), raw...), '\n')},
		{name: "trailing object", raw: append(append([]byte(nil), raw...), []byte("{}")...)},
		{name: "duplicate", raw: []byte(strings.Replace(string(raw), `"version":1,`, `"version":1,"version":1,`, 1))},
		{name: "unknown", raw: []byte(strings.Replace(string(raw), `"version":1,`, `"version":1,"extra":1,`, 1))},
		{name: "noncanonical-integer", raw: []byte(strings.Replace(string(raw), `"shard_count":2`, `"shard_count":2.0`, 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := trusted
			if tc.name == "untrusted" {
				keys = nil
			}
			if _, err := UnmarshalReceiptGroupOpen(tc.raw, keys); err == nil {
				t.Fatal("invalid group open accepted")
			}
		})
	}

	changed := open
	changed.Shards = append([]ReceiptGroupShard(nil), open.Shards...)
	changed.Shards[1].SessionID = "proxy.run." + strings.Repeat("c", 32)
	mutated, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalReceiptGroupOpen(mutated, trusted); err == nil {
		t.Fatal("changed signed membership accepted")
	}
}

func TestReceiptGroupCloseRequiresOpeningKeyAndExactShards(t *testing.T) {
	key := testGroupKey(t)
	open, _, openHash := testGroupOpen(t, key)
	manifest, err := SignReceiptGroupClose(ReceiptGroupClose{
		GroupID: open.GroupID, OpenManifestSHA256: openHash,
		Shards: testGroupHeads(open), ClosedAt: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
	}, open, openHash, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalReceiptGroupClose(raw, open, openHash, []string{open.SignerKey}); err != nil {
		t.Fatalf("valid close rejected: %v", err)
	}
	if _, err := SignReceiptGroupClose(manifest, open, openHash, testGroupKey(t)); err == nil {
		t.Fatal("different private key signed close")
	}
	missing := manifest
	missing.Shards = missing.Shards[:1]
	if _, err := SignReceiptGroupClose(missing, open, openHash, key); err == nil {
		t.Fatal("close omitted an opening shard")
	}
	if _, err := UnmarshalReceiptGroupClose(raw, open, strings.Repeat("0", 64), []string{open.SignerKey}); err == nil {
		t.Fatal("close accepted a changed opening digest")
	}
}

func TestReceiptGroupTransitionMatchesBothOpens(t *testing.T) {
	oldKey, newKey := testGroupKey(t), testGroupKey(t)
	predecessor, _, oldHash := testGroupOpen(t, oldKey)
	successor, err := SignReceiptGroupOpen(ReceiptGroupOpen{
		GroupID: strings.Repeat("2", 32), BaseSession: "proxy", ShardCount: 2,
		ProcessShardIndex: 0, Shards: []ReceiptGroupShard{
			{ShardIndex: 0, SessionID: "proxy.run." + strings.Repeat("c", 32)},
			{ShardIndex: 1, SessionID: "proxy.run." + strings.Repeat("d", 32)},
		},
		PreviousGroupID: predecessor.GroupID, PreviousOpenManifestSHA256: oldHash,
		CreatedAt: time.Unix(2, 0).UTC().Format(time.RFC3339Nano),
	}, newKey)
	if err != nil {
		t.Fatal(err)
	}
	successorRaw, err := json.Marshal(successor)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(successorRaw)
	newHash := hex.EncodeToString(sum[:])
	tr, err := SignReceiptGroupTransition(ReceiptGroupTransition{
		NewGroupID: successor.GroupID, NewOpenManifestSHA256: newHash,
		PreviousGroupID: predecessor.GroupID, PreviousOpenManifestSHA256: oldHash,
		Predecessors: []ReceiptGroupPredecessor{
			{ShardIndex: 0, SessionID: predecessor.Shards[0].SessionID, FinalChainSeq: 3, FinalChainHash: strings.Repeat("a", 64)},
			{ShardIndex: 1, SessionID: predecessor.Shards[1].SessionID, FinalChainSeq: 3, FinalChainHash: strings.Repeat("b", 64)},
		}, CreatedAt: time.Unix(3, 0).UTC().Format(time.RFC3339Nano),
	}, successor, predecessor, newHash, oldHash, "", newKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalReceiptGroupTransition(raw, successor, predecessor, newHash, oldHash, "", []string{successor.SignerKey}); err != nil {
		t.Fatalf("valid transition rejected: %v", err)
	}
	if _, err := UnmarshalReceiptGroupTransition(raw, successor, predecessor, newHash, oldHash, strings.Repeat("c", 64), []string{successor.SignerKey}); err == nil {
		t.Fatal("transition accepted different predecessor close digest")
	}
	duplicate := []byte(strings.Replace(string(raw), `"new_group_id":`, `"new_group_id":"duplicate","new_group_id":`, 1))
	if _, err := UnmarshalReceiptGroupTransition(duplicate, successor, predecessor, newHash, oldHash, "", []string{successor.SignerKey}); err == nil {
		t.Fatal("transition accepted a duplicate signed field")
	}
	dir := t.TempDir()
	name, err := ReceiptGroupFileName(successor.GroupID, "transition")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishReceiptGroupArtifact(dir, name, tr); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishReceiptGroupArtifact(dir, name, tr); err == nil {
		t.Fatal("duplicate successor transition replaced the published transition")
	}
}

func TestPublishReceiptGroupArtifactHashesPublishedBytes(t *testing.T) {
	key := testGroupKey(t)
	open, raw, wantHash := testGroupOpen(t, key)
	name, err := ReceiptGroupFileName(open.GroupID, "open")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	gotHash, err := PublishReceiptGroupArtifact(dir, name, open)
	if err != nil || gotHash != wantHash {
		t.Fatalf("publish = %q, %v; want %q", gotHash, err, wantHash)
	}
	stored, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
	if err != nil || string(stored) != string(raw) {
		t.Fatalf("published bytes differ: %v", err)
	}
	if _, err := PublishReceiptGroupArtifact(dir, name, open); err == nil {
		t.Fatal("group publication clobbered an existing file")
	}
	for _, badName := range []string{"receipt-group-invalid-open.json", "receipt-group-" + strings.Repeat("2", 32) + "-open.json", "receipt-group-" + open.GroupID + "-unknown.json"} {
		if _, err := PublishReceiptGroupArtifact(dir, badName, open); err == nil {
			t.Fatalf("accepted invalid publication name %q", badName)
		}
	}
}

func TestPublishReceiptGroupArtifactRejectsUnboundOrOversizeValues(t *testing.T) {
	key := testGroupKey(t)
	open, _, _ := testGroupOpen(t, key)
	openName, _ := ReceiptGroupFileName(open.GroupID, "open")
	closeName, _ := ReceiptGroupFileName(open.GroupID, "close")
	transitionName, _ := ReceiptGroupFileName(open.GroupID, "transition")
	closing := ReceiptGroupClose{GroupID: open.GroupID, Signature: "signed"}
	transition := ReceiptGroupTransition{NewGroupID: open.GroupID, Signature: "signed"}
	for _, tc := range []struct {
		name     string
		filename string
		value    any
	}{
		{name: "unsupported type", filename: openName, value: "signed"},
		{name: "open at close name", filename: closeName, value: open},
		{name: "unsigned open", filename: openName, value: ReceiptGroupOpen{GroupID: open.GroupID}},
		{name: "close at open name", filename: openName, value: closing},
		{name: "unsigned close", filename: closeName, value: ReceiptGroupClose{GroupID: open.GroupID}},
		{name: "transition at open name", filename: openName, value: transition},
		{name: "unsigned transition", filename: transitionName, value: ReceiptGroupTransition{NewGroupID: open.GroupID}},
		{name: "oversize body", filename: openName, value: ReceiptGroupOpen{GroupID: open.GroupID, Signature: "signed", BaseSession: strings.Repeat("x", maxGroupFileBytes)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := PublishReceiptGroupArtifact(dir, tc.filename, tc.value); err == nil {
				t.Fatal("unbound group artifact published")
			}
			if _, err := os.Stat(filepath.Join(dir, tc.filename)); !os.IsNotExist(err) {
				t.Fatalf("rejected artifact appeared on disk: %v", err)
			}
		})
	}
}
