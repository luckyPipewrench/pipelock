// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"
	"testing"
	"time"
)

func TestFindTerminalReceiptGroupRejectsForkAndMismatchedSuccessor(t *testing.T) {
	for _, mode := range []string{"single", "disconnected", "mismatched predecessor", "fork"} {
		t.Run(mode, func(t *testing.T) {
			key := testGroupKey(t)
			dir := t.TempDir()
			initial, _, _ := testGroupOpen(t, key)
			initialHash := publishTerminalTestOpen(t, dir, initial)
			if mode == "single" {
				id, found, err := FindTerminalReceiptGroup(dir, "proxy", []string{initial.SignerKey})
				if err != nil || !found || id != initial.GroupID {
					t.Fatalf("terminal = %q, %v, %v", id, found, err)
				}
				return
			}
			makeSuccessor := func(id string, previousHash string) ReceiptGroupOpen {
				open, err := SignReceiptGroupOpen(ReceiptGroupOpen{
					GroupID: id, BaseSession: "proxy", ShardCount: 2, ProcessShardIndex: 0,
					PreviousGroupID: initial.GroupID, PreviousOpenManifestSHA256: previousHash,
					CreatedAt: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
					Shards: []ReceiptGroupShard{
						{ShardIndex: 0, SessionID: "proxy.run." + strings.Repeat("c", 32)},
						{ShardIndex: 1, SessionID: "proxy.run." + strings.Repeat("d", 32)},
					},
				}, key)
				if err != nil {
					t.Fatal(err)
				}
				return open
			}
			if mode == "disconnected" {
				other := makeSuccessor(strings.Repeat("2", 32), initialHash)
				other.PreviousGroupID = ""
				other.PreviousOpenManifestSHA256 = ""
				var err error
				other, err = SignReceiptGroupOpen(other, key)
				if err != nil {
					t.Fatal(err)
				}
				publishTerminalTestOpen(t, dir, other)
			} else {
				previousHash := initialHash
				if mode == "mismatched predecessor" {
					previousHash = strings.Repeat("f", 64)
				}
				publishTerminalTestOpen(t, dir, makeSuccessor(strings.Repeat("2", 32), previousHash))
				if mode == "fork" {
					publishTerminalTestOpen(t, dir, makeSuccessor(strings.Repeat("3", 32), initialHash))
				}
			}
			want := map[string]string{
				"disconnected":           "more than one terminal group",
				"mismatched predecessor": "mismatched predecessor",
				"fork":                   "multiple successor openings",
			}[mode]
			id, found, err := FindTerminalReceiptGroup(dir, "proxy", []string{initial.SignerKey})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s history: terminal=%q found=%v err=%v, want error containing %q", mode, id, found, err, want)
			}
		})
	}
}

func TestFindTerminalReceiptGroupRequiresConfiguredSigner(t *testing.T) {
	dir := t.TempDir()
	trustedKey := testGroupKey(t)
	foreignKey := testGroupKey(t)
	foreign, _, _ := testGroupOpen(t, foreignKey)
	publishTerminalTestOpen(t, dir, foreign)
	trusted, _, _ := testGroupOpen(t, trustedKey)
	if _, _, err := FindTerminalReceiptGroup(dir, "proxy", nil); err == nil {
		t.Fatal("terminal discovery accepted no trusted key")
	}
	if id, found, err := FindTerminalReceiptGroup(dir, "proxy", []string{trusted.SignerKey}); err == nil {
		t.Fatalf("foreign opening affected terminal discovery: id=%q found=%v", id, found)
	}
	if id, found, err := FindTerminalReceiptGroup(dir, "proxy", []string{foreign.SignerKey}); err != nil || !found || id != foreign.GroupID {
		t.Fatalf("configured signer rejected: id=%q found=%v err=%v", id, found, err)
	}
}

func publishTerminalTestOpen(t *testing.T, dir string, open ReceiptGroupOpen) string {
	t.Helper()
	name, err := ReceiptGroupFileName(open.GroupID, "open")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := PublishReceiptGroupArtifact(dir, name, open)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestReadTopologicalGroupOpenRejectsUnsafeInput(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"bad", "receipt-group-" + strings.Repeat("1", 32) + "-close.json"} {
		if _, _, err := readTopologicalGroupOpen(dir, name, []string{"key"}); err == nil {
			t.Fatalf("non-opening name %q accepted", name)
		}
	}
	key := testGroupKey(t)
	open, _, _ := testGroupOpen(t, key)
	name, _ := ReceiptGroupFileName(open.GroupID, "open")
	if _, _, err := readTopologicalGroupOpen(dir, name, []string{open.SignerKey}); err == nil {
		t.Fatal("missing opening accepted")
	}
}
