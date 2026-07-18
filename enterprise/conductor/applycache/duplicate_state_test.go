//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadJSONFileRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var dst map[string]any
	if err := readJSONFile(path, 1024, &dst); err == nil {
		t.Fatal("readJSONFile accepted duplicate keys")
	}
}
