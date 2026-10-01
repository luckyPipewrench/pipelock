// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package policy

import "os"

// mayHaveOtherLinks reports whether the file may be reachable under more than
// one name. This platform exposes no link count through os.FileInfo, so every
// file is treated as possibly linked.
func mayHaveOtherLinks(_ os.FileInfo) bool {
	return true
}

// onDifferentDevice reports whether a and b are known to be on different
// filesystems. This platform exposes no device through os.FileInfo, so it is
// never known.
func onDifferentDevice(_, _ os.FileInfo) bool {
	return false
}

// fileID reports no key: this platform exposes no device or inode through
// os.FileInfo, so files are compared with os.SameFile.
func fileID(_ os.FileInfo) (fileKey, bool) {
	return fileKey{}, false
}
