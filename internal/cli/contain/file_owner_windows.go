// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

import "os"

func fileOwnerUID(_ os.FileInfo) (uint32, bool) {
	return 0, false
}
