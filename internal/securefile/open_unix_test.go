//go:build unix

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import (
	"path/filepath"
	"testing"
)

func TestOpenRegularNonblockingDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swapped-secret")
	if err := syscallMkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	file, err := openRegularNonblocking(path)
	if err != nil {
		return // Some Unix kernels reject a read-only nonblocking FIFO with no writer.
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().IsRegular() {
		t.Fatalf("FIFO mode = %v, unexpectedly regular", info.Mode())
	}
}
