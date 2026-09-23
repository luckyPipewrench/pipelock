// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// ResolveKeystoreDir returns the keystore directory using the priority:
// explicit --keystore flag > --home flag > PIPELOCK_HOME env > default.
// Delegates to internal/signing, the single source of truth for pipelock
// home resolution, so internal/config can resolve the same directory
// without importing this package (which would create an import cycle).
func ResolveKeystoreDir(explicit string) (string, error) {
	return signing.ResolveKeystoreDir(explicit)
}

// ResolveAgentName returns the agent name from the explicit flag value
// or the PIPELOCK_AGENT environment variable.
func ResolveAgentName(explicit string) (string, error) {
	name := explicit
	if name == "" {
		name = os.Getenv("PIPELOCK_AGENT")
	}
	if name == "" {
		return "", fmt.Errorf("agent name required: use --agent or set PIPELOCK_AGENT")
	}
	if err := signing.ValidateAgentName(name); err != nil {
		return "", err
	}
	return name, nil
}

// ResolvedHome returns the pipelock home directory from the --home flag
// (signing.PipelockHome) or the PIPELOCK_HOME environment variable. Returns
// empty string if neither is set.
func ResolvedHome() string {
	return signing.ResolvedHome()
}
