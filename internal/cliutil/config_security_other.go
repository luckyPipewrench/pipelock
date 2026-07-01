// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package cliutil

import "os"

func configPathOwnerUID(_ os.FileInfo) (int, bool) {
	return 0, false
}

func currentEUID() int {
	return 0
}

func configPathOwnerTrusted(_ int) bool {
	return false
}
