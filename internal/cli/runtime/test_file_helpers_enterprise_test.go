//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"os"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
)

func writePrivateTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func writeTestQueueKeyring(t *testing.T, path string) *auditbatcher.Keyring {
	t.Helper()
	keyring, err := auditbatcher.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	if err := auditbatcher.EnsureKeyringParent(path); err != nil {
		t.Fatalf("EnsureKeyringParent() error = %v", err)
	}
	if err := keyring.Save(path); err != nil {
		t.Fatalf("Save(keyring) error = %v", err)
	}
	return keyring
}
