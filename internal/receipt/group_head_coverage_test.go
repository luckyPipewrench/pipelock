// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestGroupShardHeadRejectsDamagedEvidenceOrder(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func([]recorder.Entry) []recorder.Entry
	}{
		{"wrong first gate", "first entry does not match signed gate", func(entries []recorder.Entry) []recorder.Entry {
			entries[0].Type = "request"
			return entries
		}},
		{"missing gate checkpoint", "gate is not covered by next checkpoint", func(entries []recorder.Entry) []recorder.Entry {
			entries[1].Type = "request"
			return entries
		}},
		{"wrong transcript root", "hash mismatch", func(entries []recorder.Entry) []recorder.Entry {
			for i := range entries {
				if entries[i].Type == transcriptRootEntryType {
					entries[i].Detail = "damaged root"
					entries[i].RawDetail = nil
				}
			}
			return entries
		}},
		{"evidence after root", "unsupported entry version", func(entries []recorder.Entry) []recorder.Entry {
			return append(entries, recorder.Entry{Type: "request"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, open := newCoverageGroup(t, true)
			name, err := ReceiptGroupFileName(open.GroupID, "open")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
			if err != nil {
				t.Fatal(err)
			}
			openHash := fmt.Sprintf("%x", sha256.Sum256(raw))
			if _, err := VerifyGroupShardHead(dir, open, openHash, 0); err != nil {
				t.Fatalf("valid shard rejected: %v", err)
			}
			paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
			if err != nil || len(paths) != 1 {
				t.Fatalf("shard files=%v err=%v", paths, err)
			}
			entries, err := recorder.ReadEntries(paths[0])
			if err != nil {
				t.Fatal(err)
			}
			writeRecoveryStreamEntries(t, paths[0], tc.mutate(entries), nil)
			if _, err := VerifyGroupShardHead(dir, open, openHash, 0); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("damaged shard error=%v, want %q", err, tc.want)
			}
		})
	}
}
