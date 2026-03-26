// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"testing"
)

// NOTE: Most mcp tests in the original cli package use rootCmd() which stays
// in internal/cli. Those tests cannot be moved here until the wiring step
// connects runtime commands to the root command. Only self-contained tests
// are included in this file.

func TestSafeWriter(t *testing.T) {
	var buf bytes.Buffer
	sw := &safeWriter{w: &buf}

	data := []byte("test-safe-writer")
	n, err := sw.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
	if buf.String() != string(data) {
		t.Errorf("expected %q, got %q", string(data), buf.String())
	}
}
