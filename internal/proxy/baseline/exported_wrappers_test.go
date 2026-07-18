// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateAgentKeyExportedWrapper(t *testing.T) {
	t.Parallel()
	if err := ValidateAgentKey("agent.ok-1"); err != nil {
		t.Fatalf("ValidateAgentKey valid key: %v", err)
	}
	for _, key := range []string{"", "../agent", "agent/one", "agent..one"} {
		t.Run(key, func(t *testing.T) {
			if err := ValidateAgentKey(key); err == nil {
				t.Errorf("ValidateAgentKey(%q) = nil, want error", key)
			}
		})
	}
}

func TestCheckErrRejectsUnsafeAgentKey(t *testing.T) {
	t.Parallel()
	mgr, err := NewManager(Config{Enabled: true, ProfileDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	deviations, err := mgr.CheckErr("../agent", SessionMetrics{})
	if err == nil || !strings.Contains(err.Error(), "invalid agent key") {
		t.Fatalf("CheckErr error = %v, want invalid agent key", err)
	}
	if deviations != nil {
		t.Fatalf("CheckErr deviations = %#v, want nil on validation error", deviations)
	}
}

func TestIntegrityManifestCommittedErrorUnwrap(t *testing.T) {
	t.Parallel()
	cause := errors.New("already committed")
	err := integrityManifestCommittedError{err: cause}
	if err.Error() != cause.Error() {
		t.Fatalf("Error() = %q, want %q", err.Error(), cause.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("integrityManifestCommittedError does not unwrap cause")
	}
	if !integrityManifestAlreadyCommitted(err) {
		t.Fatal("integrityManifestAlreadyCommitted = false for wrapped committed error")
	}
}
