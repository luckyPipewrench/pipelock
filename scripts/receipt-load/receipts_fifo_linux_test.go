// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestScanRecorderRejectsFIFOWithoutBlocking(t *testing.T) {
	plan := newWorkload(1, 0, 1)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, perfectReceipts(plan, modeBest))
	path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := scanRecorder(dir, plan, synthSink)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted FIFO receipt entry")
		}
	case <-time.After(time.Second):
		t.Fatal("scanRecorder blocked opening FIFO receipt entry")
	}
}
