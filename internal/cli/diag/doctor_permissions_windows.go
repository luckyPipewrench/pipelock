// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package diag

import "os"

func dirWritableExecutableByCurrentUser(info os.FileInfo) bool {
	// Go maps the Windows read-only attribute into FileMode's owner-write bit.
	// ACLs can still deny the eventual runtime create, but doctor --startup is
	// deliberately read-only and must not create probe files to test access.
	return info.Mode().Perm()&0o200 != 0
}
