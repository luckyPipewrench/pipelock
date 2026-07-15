// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadVerifierFileBoundsAndType(t *testing.T) {
	t.Run("regular", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "receipt.json")
		if err := os.WriteFile(path, []byte(`{"ok":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readVerifierFile(path)
		if err != nil {
			t.Fatalf("readVerifierFile: %v", err)
		}
		if string(got) != `{"ok":true}` {
			t.Fatalf("data = %q", got)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "oversize-*.json")
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		if err := file.Truncate(maxVerifierInputBytes + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := readVerifierFile(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversize error = %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		if _, err := readVerifierFile(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("directory error = %v", err)
		}
	})
}
