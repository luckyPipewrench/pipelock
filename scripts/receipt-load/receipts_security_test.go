// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanRecorderRejectsSymlinkedReceiptFile(t *testing.T) {
	plan := newWorkload(1, 0, 1)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, perfectReceipts(plan, modeBest))
	const name = "evidence-proxy.run.x-0.jsonl"
	path := filepath.Join(dir, name)
	target := filepath.Join(dir, "receipt-data")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := scanRecorder(dir, plan, synthSink); err == nil {
		t.Fatal("accepted symlinked receipt file")
	}
}
