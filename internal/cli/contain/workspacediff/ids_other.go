// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package workspacediff

import "os"

// statIDs has no portable device/inode source on this platform, so mount-
// boundary detection and the TOCTOU identity re-check are both unavailable
// here (ok=false everywhere they are consulted); contain run is Linux-only
// today (see containRunSupported), so this path exists only to keep the
// package buildable on other platforms for tooling/tests.
func statIDs(_ os.FileInfo) (dev, ino uint64, ok bool) {
	return 0, 0, false
}
