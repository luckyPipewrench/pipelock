// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import "os"

// PipelockHome holds the --home persistent flag value. The root command
// binds this via cobra's StringVar so any package can resolve the pipelock
// home directory without importing the cli layer. This lives in
// internal/signing (a leaf package) rather than internal/cliutil so that
// internal/config, which internal/cliutil imports, can resolve the same
// home directory the CLI does for its default TLS CA path.
var PipelockHome string

// ResolvedHome returns the pipelock home directory from the --home flag
// (PipelockHome) or the PIPELOCK_HOME environment variable. Returns empty
// string if neither is set.
func ResolvedHome() string {
	if PipelockHome != "" {
		return PipelockHome
	}
	return os.Getenv("PIPELOCK_HOME")
}

// ResolveKeystoreDir returns the keystore directory using the priority:
// explicit --keystore flag > --home flag > PIPELOCK_HOME env > default.
func ResolveKeystoreDir(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if home := ResolvedHome(); home != "" {
		return home, nil
	}
	return DefaultKeystorePath()
}
