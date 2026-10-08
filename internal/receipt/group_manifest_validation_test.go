// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestReceiptGroupOpenRejectsMalformedMembership(t *testing.T) {
	key := testGroupKey(t)
	valid, _, _ := testGroupOpen(t, key)
	if err := validateGroupOpen(valid); err != nil {
		t.Fatalf("valid opening rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*ReceiptGroupOpen)
		want string
	}{
		{"identity", func(o *ReceiptGroupOpen) { o.Version = 2 }, "identity"},
		{"kind", func(o *ReceiptGroupOpen) { o.Kind = "other" }, "identity"},
		{"group id", func(o *ReceiptGroupOpen) { o.GroupID = strings.Repeat("A", 32) }, "identity"},
		{"base session", func(o *ReceiptGroupOpen) { o.BaseSession = "bad/session" }, "base session"},
		{"too few shards", func(o *ReceiptGroupOpen) { o.ShardCount = 1 }, "shard count"},
		{"shard count", func(o *ReceiptGroupOpen) { o.ShardCount = 33 }, "shard count"},
		{"missing member", func(o *ReceiptGroupOpen) { o.Shards = o.Shards[:1] }, "shard count"},
		{"negative process index", func(o *ReceiptGroupOpen) { o.ProcessShardIndex = -1 }, "process index"},
		{"process index", func(o *ReceiptGroupOpen) { o.ProcessShardIndex = 2 }, "process index"},
		{"signer", func(o *ReceiptGroupOpen) { o.SignerKey = "unknown" }, "signer"},
		{"timestamp", func(o *ReceiptGroupOpen) { o.CreatedAt = "later" }, "timestamp"},
		{"non UTC timestamp", func(o *ReceiptGroupOpen) { o.CreatedAt = "1970-01-01T01:00:01+01:00" }, "timestamp"},
		{"unpaired predecessor", func(o *ReceiptGroupOpen) { o.PreviousGroupID = strings.Repeat("2", 32) }, "predecessor pair"},
		{"unpaired predecessor hash", func(o *ReceiptGroupOpen) { o.PreviousOpenManifestSHA256 = strings.Repeat("a", 64) }, "predecessor pair"},
		{"bad predecessor hash", func(o *ReceiptGroupOpen) {
			o.PreviousGroupID = strings.Repeat("2", 32)
			o.PreviousOpenManifestSHA256 = "bad"
		}, "invalid receipt group predecessor"},
		{"self predecessor", func(o *ReceiptGroupOpen) {
			o.PreviousGroupID = o.GroupID
			o.PreviousOpenManifestSHA256 = strings.Repeat("a", 64)
		}, "invalid receipt group predecessor"},
		{"wrong shard index", func(o *ReceiptGroupOpen) { o.Shards[1].ShardIndex = 0 }, "shard 1"},
		{"wrong run session", func(o *ReceiptGroupOpen) { o.Shards[1].SessionID = "proxy" }, "shard 1"},
		{"duplicate run session", func(o *ReceiptGroupOpen) { o.Shards[1].SessionID = o.Shards[0].SessionID }, "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := valid
			changed.Shards = append([]ReceiptGroupShard(nil), valid.Shards...)
			tc.edit(&changed)
			if err := validateGroupOpen(changed); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malformed opening accepted or misclassified: %v", err)
			}
		})
	}
}

func TestReceiptGroupCloseRejectsMalformedHeads(t *testing.T) {
	key := testGroupKey(t)
	open, _, openHash := testGroupOpen(t, key)
	valid, err := SignReceiptGroupClose(ReceiptGroupClose{
		GroupID: open.GroupID, OpenManifestSHA256: openHash,
		Shards: testGroupHeads(open), ClosedAt: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
	}, open, openHash, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*ReceiptGroupClose)
		want string
	}{
		{"opening digest", func(c *ReceiptGroupClose) { c.OpenManifestSHA256 = strings.Repeat("0", 64) }, "opening manifest"},
		{"status", func(c *ReceiptGroupClose) { c.Status = "pending" }, "opening manifest"},
		{"signer", func(c *ReceiptGroupClose) { c.SignerKey = strings.Repeat("0", 64) }, "opening manifest"},
		{"timestamp", func(c *ReceiptGroupClose) { c.ClosedAt = "later" }, "opening manifest"},
		{"missing shard", func(c *ReceiptGroupClose) { c.Shards = c.Shards[:1] }, "shard set"},
		{"wrong shard index", func(c *ReceiptGroupClose) { c.Shards[1].ShardIndex = 0 }, "shard 1 differs"},
		{"wrong session", func(c *ReceiptGroupClose) { c.Shards[1].SessionID = "other" }, "shard 1 differs"},
		{"oversize chain sequence", func(c *ReceiptGroupClose) { c.Shards[1].FinalChainSeq = maxGroupInteger + 1 }, "safe range"},
		{"oversize count", func(c *ReceiptGroupClose) { c.Shards[1].ReceiptCount = maxGroupInteger + 1 }, "safe range"},
		{"oversize native sequence", func(c *ReceiptGroupClose) { c.Shards[1].NativeAELFinalSeq = maxGroupInteger + 1 }, "safe range"},
		{"oversize native count", func(c *ReceiptGroupClose) { c.Shards[1].NativeAELRecordCount = maxGroupInteger + 1 }, "safe range"},
		{"invalid digest", func(c *ReceiptGroupClose) { c.Shards[1].CheckpointHash = "bad" }, "invalid hash"},
		{"invalid native digest", func(c *ReceiptGroupClose) { c.Shards[1].NativeAELFinalHash = "bad" }, "invalid hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := valid
			changed.Shards = append([]ReceiptGroupShardHead(nil), valid.Shards...)
			tc.edit(&changed)
			if err := validateGroupClose(changed, open, openHash); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malformed close accepted or misclassified: %v", err)
			}
		})
	}
}

func TestReceiptGroupTransitionRejectsMalformedPredecessors(t *testing.T) {
	key := testGroupKey(t)
	prior, _, oldHash := testGroupOpen(t, key)
	successor := prior
	successor.GroupID = strings.Repeat("2", 32)
	successor.PreviousGroupID = prior.GroupID
	successor.PreviousOpenManifestSHA256 = oldHash
	successor.Shards = []ReceiptGroupShard{
		{ShardIndex: 0, SessionID: "proxy.run." + strings.Repeat("c", 32)},
		{ShardIndex: 1, SessionID: "proxy.run." + strings.Repeat("d", 32)},
	}
	successor, err := SignReceiptGroupOpen(successor, key)
	if err != nil {
		t.Fatal(err)
	}
	newBytes, err := json.Marshal(successor)
	if err != nil {
		t.Fatal(err)
	}
	newSum := sha256.Sum256(newBytes)
	newHash := hex.EncodeToString(newSum[:])
	closeHash := strings.Repeat("f", 64)
	predecessors := make([]ReceiptGroupPredecessor, len(prior.Shards))
	for i, shard := range prior.Shards {
		predecessors[i] = ReceiptGroupPredecessor{ShardIndex: i, SessionID: shard.SessionID, FinalChainSeq: 3, FinalChainHash: strings.Repeat("a", 64)}
	}
	valid, err := SignReceiptGroupTransition(ReceiptGroupTransition{
		NewGroupID: successor.GroupID, NewOpenManifestSHA256: newHash,
		PreviousGroupID: prior.GroupID, PreviousOpenManifestSHA256: oldHash,
		PreviousCloseManifestSHA256: closeHash, Predecessors: predecessors,
		CreatedAt: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
	}, successor, prior, newHash, oldHash, closeHash, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*ReceiptGroupTransition)
		want string
	}{
		{"header", func(tr *ReceiptGroupTransition) { tr.Kind = "other" }, "header"},
		{"non UTC timestamp", func(tr *ReceiptGroupTransition) { tr.CreatedAt = "1970-01-01T01:00:01+01:00" }, "header"},
		{"opening binding", func(tr *ReceiptGroupTransition) { tr.NewOpenManifestSHA256 = strings.Repeat("0", 64) }, "does not match"},
		{"wrong predecessor group", func(tr *ReceiptGroupTransition) { tr.PreviousGroupID = strings.Repeat("3", 32) }, "does not match"},
		{"wrong signer", func(tr *ReceiptGroupTransition) { tr.SignerKey = strings.Repeat("0", 64) }, "predecessor set"},
		{"predecessor set", func(tr *ReceiptGroupTransition) { tr.Predecessors = tr.Predecessors[:1] }, "predecessor set"},
		{"wrong predecessor index", func(tr *ReceiptGroupTransition) { tr.Predecessors[1].ShardIndex = 0 }, "predecessor 1"},
		{"wrong predecessor", func(tr *ReceiptGroupTransition) { tr.Predecessors[1].SessionID = "other" }, "predecessor 1"},
		{"oversize predecessor sequence", func(tr *ReceiptGroupTransition) { tr.Predecessors[1].FinalChainSeq = maxGroupInteger + 1 }, "predecessor 1"},
		{"invalid predecessor hash", func(tr *ReceiptGroupTransition) { tr.Predecessors[1].FinalChainHash = "bad" }, "predecessor 1"},
		{"invalid recovery seal", func(tr *ReceiptGroupTransition) { tr.Predecessors[1].RecoverySealSHA256 = "bad" }, "predecessor 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := valid
			changed.Predecessors = append([]ReceiptGroupPredecessor(nil), valid.Predecessors...)
			tc.edit(&changed)
			if err := validateGroupTransition(changed, successor, prior, newHash, oldHash, closeHash); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malformed transition accepted or misclassified: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name      string
		newHash   string
		oldHash   string
		closeHash string
	}{
		{"invalid successor digest", "bad", oldHash, closeHash},
		{"invalid predecessor digest", newHash, "bad", closeHash},
		{"invalid close digest", newHash, oldHash, "bad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateGroupTransition(valid, successor, prior, tc.newHash, tc.oldHash, tc.closeHash); err == nil || !strings.Contains(err.Error(), "manifest digest") {
				t.Fatalf("invalid transition digest accepted: %v", err)
			}
		})
	}
}
