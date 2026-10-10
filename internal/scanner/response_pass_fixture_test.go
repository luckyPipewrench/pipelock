// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadResponsePassFixture(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "sample.js")
	if err := os.WriteFile(regular, []byte("var x = 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readResponsePassFixture(regular); err != nil || string(got) != "var x = 1;" {
		t.Fatalf("regular file: got %q, %v", got, err)
	}

	big := filepath.Join(dir, "big.js")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), responsePassFixtureCap+10), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readResponsePassFixture(big); err != nil || len(got) != responsePassFixtureCap {
		t.Fatalf("oversized file: got %d bytes, %v; want %d", len(got), err, responsePassFixtureCap)
	}

	if _, err := readResponsePassFixture(filepath.Join(dir, "missing.js")); err == nil {
		t.Fatal("missing path was accepted")
	}
	if _, err := readResponsePassFixture(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: got %v, want a not-a-regular-file error", err)
	}
}
