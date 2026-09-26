// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"os"
	"path/filepath"
	"testing"
)

// A write that fails after the exclusive create must not leave a partial
// archive behind, or a retry to the same path would fail as already existing.
func TestWriteArchive_RemovesPartialOutputOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	err := writeArchive(path, manifest{}, []bundleEntry{{name: "bad\x00name", data: []byte("x")}})
	if err == nil {
		t.Fatal("writeArchive accepted an entry name that tar cannot encode")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("partial archive survived a failed write: stat err=%v", statErr)
	}
	if err := writeArchive(path, manifest{}, nil); err != nil {
		t.Fatalf("retry to the same path failed: %v", err)
	}
}
