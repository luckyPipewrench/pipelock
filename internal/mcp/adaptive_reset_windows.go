// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package mcp

import "os"

// resetFileOwnedBySelf cannot verify ownership via fs.FileMode on Windows (the
// bits never reflect the NTFS ACL), and mode-bit checks are also no-ops there.
// The reset file authorizes a privilege DE-escalation (clearing an airlock), so
// for this control path it fails CLOSED: ownership cannot be confirmed, so it is
// not honored. The CLI also rejects --adaptive-reset-file on Windows up front,
// so this is a defense-in-depth backstop. (A real owner-SID check could make it
// fail-open-when-verified in future.)
func resetFileOwnedBySelf(_ os.FileInfo) bool {
	return false
}
