// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package mcp

import (
	"os"
	"syscall"
)

// resetFileOwnedBySelf reports whether info is owned by this process's
// effective uid. This is defense-in-depth for containment, where the wrapped
// agent runs as a different uid and must not be able to plant a reset file the
// proxy honors. An unknown stat shape fails closed (not owned).
func resetFileOwnedBySelf(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Geteuid()
}
