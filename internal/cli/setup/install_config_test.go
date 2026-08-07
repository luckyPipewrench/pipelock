// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pipelock-setup-test-config-*")
	if err != nil {
		panic(err)
	}
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\n"), 0o600); err != nil {
		panic(err)
	}
	if err := os.Setenv("PIPELOCK_CONFIG", cfgPath); err != nil {
		panic(err)
	}
	evidenceAuditorUserConfigDir = func() (string, error) { return filepath.Join(dir, "user-config"), nil }
	evidenceAuditorExecutable = func() (string, error) { return "/usr/bin/pipelock", nil }
	evidenceAuditorSystemctl = func(_ context.Context, _ systemctlOp) error { return nil }

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
