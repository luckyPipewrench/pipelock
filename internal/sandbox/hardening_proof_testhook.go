// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build mcp_hardening_test

package sandbox

import (
	"fmt"
	"os"
)

const hardeningProofMarkerEnv = "PIPELOCK_SANDBOX_HARDENING_PROOF_MARKER"

// recordParentHardeningForTest marks the exact point after the real parent
// hardening callback returns and before sandbox-init receives its release
// byte. This build-tagged observation point lets the integration target prove
// the ordering without relying on scheduler timing.
func recordParentHardeningForTest() error {
	path := os.Getenv(hardeningProofMarkerEnv)
	if path == "" {
		return nil
	}
	if err := os.WriteFile(path, []byte("hardened\n"), 0o600); err != nil {
		return fmt.Errorf("write hardening proof marker: %w", err)
	}
	return nil
}
