//go:build windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posturebinding

// proofOwnerGroup cannot derive POSIX ownership from Windows file metadata.
func proofOwnerGroup(string) (string, string, bool) {
	return "", "", false
}
