// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package scanner

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO with no writer must be refused at once. A loader that opened it
// with a blocking open, or read it, would wait forever, so the call runs in
// a goroutine and the test fails if it has not returned within the deadline.
func TestReadResponsePassFixtureRefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readResponsePassFixture(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO: got %v, want a not-a-regular-file error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reading a FIFO fixture blocked")
	}
}
