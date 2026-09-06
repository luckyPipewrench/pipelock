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
	// Each init command needs its own auditor directory. Sharing one directory
	// makes independent test configs look like attempts to replace a durable
	// auditor target, which is precisely what production must reject.
	evidenceAuditorUserConfigDir = func() (string, error) { return os.MkdirTemp(dir, "user-config-") }
	evidenceAuditorExecutable = func() (string, error) { return "/usr/bin/pipelock", nil }
	evidenceAuditorSystemctl = func(_ context.Context, _ systemctlOp) error { return nil }

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
