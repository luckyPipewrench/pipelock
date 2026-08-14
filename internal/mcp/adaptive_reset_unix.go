// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package mcp

import (
	"os"
	"syscall"
)

// resetFileOwnedByOperator reports whether info is owned by root, the local
// operator authority boundary. Same-UID ownership is not authority: an agent
// co-located with an unprivileged proxy can create an indistinguishable 0600
// file and clear its own airlock or drift baseline. An unknown stat shape fails
// closed.
func resetFileOwnedByOperator(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return st.Uid == 0
}
