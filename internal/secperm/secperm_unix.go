// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package secperm

import "io/fs"

// Enforced reports whether file-mode permission bits are security-meaningful on
// this OS. True on Unix; false on Windows. See the package doc for why Windows
// cannot enforce mode bits.
const Enforced = true

// TooPermissive reports whether perm intersects the disallowed bit mask. The
// mask is explicit at each call site (e.g. 0o037 for key/license/secret files,
// 0o077 for salt and credential dirs, 0o137 for the CA key, 0o002 for a
// world-writable parent). On Unix this is exactly perm&disallowed != 0,
// byte-for-byte identical to the inline checks it replaced. On Windows it is
// always false (see package doc).
func TooPermissive(perm, disallowed fs.FileMode) bool {
	return perm&disallowed != 0
}
