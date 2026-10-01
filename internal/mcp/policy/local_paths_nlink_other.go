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

// ownedByCurrentUser reports whether this process's user owns the file. File
// ownership is not exposed here, so no file is treated as owned.
func ownedByCurrentUser(_ os.FileInfo) bool {
	return false
}
