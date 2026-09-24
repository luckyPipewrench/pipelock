// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import "os"

// userHomeDir is a package-level variable rather than a direct os.UserHomeDir
// call so tests can swap in a deterministic fake. Production callers should
// never reassign it.
var userHomeDir = os.UserHomeDir

// homeFlagUsage documents --home on install, verify, and rollback. It is the
// Hermes user's home: the base for the default plugin root and Hermes config,
// and the home whose agent-browser config holds the browser defaults.
const homeFlagUsage = "home directory of the Hermes user (default: the current user's home); " +
	"base for the default --plugin-root and --hermes-config and location of the agent-browser config"
