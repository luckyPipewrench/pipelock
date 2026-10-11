// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifySessionHistoryChainAcrossShards(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	location := EvidenceLocation{Root: dir, Dir: dir}
	const session = "proxy"
	entries := historyEntries(t, session, 0, 2, "decision")
	first := filepath.Join(dir, "evidence-proxy-0.jsonl")
	second := filepath.Join(dir, "evidence-proxy-1.jsonl")
	if err := os.WriteFile(first, historyLines(t, entries[:1]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, historyLines(t, entries[1:]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySessionHistoryChain(location, session); err != nil {
		t.Fatal(err)
	}
	entries[1].PrevHash = GenesisHash
	entries[1].Hash = ComputeHash(entries[1])
	if err := os.WriteFile(second, historyLines(t, entries[1:]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySessionHistoryChain(location, session); err == nil || !strings.Contains(err.Error(), "chain break: PrevHash") {
		t.Fatalf("want predecessor chain break, got %v", err)
	}
}
