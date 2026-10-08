// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGroupLegacySpillIndexOrdersShardsAndRejectsUnreadableInventory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"evidence-legacy-20.jsonl", "evidence-legacy-3.jsonl",
		"evidence-other-0.jsonl", "receipt-group-unknown.json", "notes.txt",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	index, err := indexRecorderFilesExcludingGroupsSpill(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(index) != 2 || len(index["legacy"]) != 2 || len(index["other"]) != 1 ||
		filepath.Base(index["legacy"][0]) != "evidence-legacy-3.jsonl" ||
		filepath.Base(index["legacy"][1]) != "evidence-legacy-20.jsonl" {
		t.Fatalf("legacy spill index omitted or misordered shards: %+v", index)
	}
	if _, err := indexRecorderFilesExcludingGroupsSpill(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing evidence inventory accepted")
	}
}
