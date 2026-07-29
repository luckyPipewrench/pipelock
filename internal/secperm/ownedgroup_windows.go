//go:build windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package secperm

import "io/fs"

// OwnedGroupWritableAllowed is a no-op on Windows, matching TooPermissive: the
// POSIX mode bits this policy reasons about are not meaningful there.
func OwnedGroupWritableAllowed(_ fs.FileInfo) error {
	return nil
}
