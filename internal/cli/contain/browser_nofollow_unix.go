// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import "syscall"

// agentBrowserNoFollow refuses a symlink as the final path component when
// opening the agent's browser config.
const agentBrowserNoFollow = syscall.O_NOFOLLOW
