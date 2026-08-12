// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestNewDurableFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		logger, err := NewDurableFile("json", path, false, false)
		if logger != nil {
			logger.Close()
		}
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("NewDurableFile accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("NewDurableFile blocked on FIFO without a reader")
	}
}
