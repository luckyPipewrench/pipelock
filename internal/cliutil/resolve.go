// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// PipelockHome holds the --home persistent flag value. Root command binds
// this via cobra's StringVar so subpackages can read it without importing cli.
var PipelockHome string

// ResolveKeystoreDir returns the keystore directory using the priority:
// explicit --keystore flag > --home flag > PIPELOCK_HOME env > default.
func ResolveKeystoreDir(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if home := ResolvedHome(); home != "" {
		return home, nil
	}
	return signing.DefaultKeystorePath()
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
// (PipelockHome) or the PIPELOCK_HOME environment variable. Returns empty
// string if neither is set.
func ResolvedHome() string {
	if PipelockHome != "" {
		return PipelockHome
	}
	return os.Getenv("PIPELOCK_HOME")
}
