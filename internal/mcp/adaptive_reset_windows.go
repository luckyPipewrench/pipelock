// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package mcp

import "os"

// resetFileOwnedBySelf cannot inspect ownership via fs.FileMode on Windows (the
// bits never reflect the NTFS ACL). Consistent with secperm's documented
// Windows fail-open, ownership of the reset file is the deployment's ACL
// responsibility on this platform.
func resetFileOwnedBySelf(_ os.FileInfo) bool {
	return true
}
