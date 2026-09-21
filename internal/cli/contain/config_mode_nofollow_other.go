// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

import (
	"errors"
	"os"
)

// repairLeafModeNoFollow is unsupported on Windows. Host containment is a Unix
// path, and Windows cannot express the Unix permission bits this repair exists
// to correct, so it fails closed rather than falling back to a path-resolving
// chmod the platform cannot make safe.
func setLeafModeNoFollow(path string, _ os.FileMode, _ bool) (os.FileMode, bool, error) {
	return 0, false, errors.New("config mode repair requires a Unix host: " + path)
}
