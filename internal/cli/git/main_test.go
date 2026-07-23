// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pipelock-git-test-config-*")
	if err != nil {
		panic(err)
	}
	dirMode := os.FileMode(0o700) | 0o050
	if err := os.Chmod(dir, dirMode); err != nil {
		panic(err)
	}
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\n"), 0o600); err != nil {
		panic(err)
	}
	if err := os.Setenv("PIPELOCK_CONFIG", cfgPath); err != nil {
		panic(err)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
