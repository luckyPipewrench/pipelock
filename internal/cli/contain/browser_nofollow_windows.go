// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

// agentBrowserNoFollow is zero on Windows, which has no O_NOFOLLOW. Contained
// installs run only on Linux; the os.Root confinement and the Lstat symlink
// check on the final component still apply wherever this code compiles.
const agentBrowserNoFollow = 0
