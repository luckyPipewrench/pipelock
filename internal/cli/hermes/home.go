// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import "os"

// userHomeDir is a package-level variable rather than a direct os.UserHomeDir
// call so tests can swap in a deterministic fake. Production callers should
// never reassign it.
var userHomeDir = os.UserHomeDir
