// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package secperm

import "io/fs"

// Enforced reports whether file-mode permission bits are security-meaningful on
// this OS. True on Unix; false on Windows. See the package doc for why Windows
// cannot enforce mode bits.
const Enforced = false

// TooPermissive always returns false on Windows: Go's fs.FileMode reflects only
// the read-only attribute, never the NTFS ACL, so the permission bits carry no
// access-control meaning and must not be used to reject a file. Access control
// on Windows is enforced via NTFS ACLs at deployment time, which pipelock does
// not inspect.
func TooPermissive(_, _ fs.FileMode) bool {
	return false
}
