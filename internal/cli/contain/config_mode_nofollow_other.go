// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

import (
	"errors"
	"fmt"
	"os"
)

// setLeafModeNoFollow is unsupported on Windows. Host containment is a Unix
// path, and Windows cannot express the Unix permission bits this repair exists
// to correct, so an EXISTING config fails closed rather than falling back to a
// path-resolving chmod the platform cannot make safe.
//
// An ABSENT path still reports os.ErrNotExist, because absence is not a
// platform limitation: the caller treats it as the ordinary first-install case
// where promotion owns creating the file, and collapsing it into the generic
// error would turn a no-op into an install failure.
func setLeafModeNoFollow(path string, _ os.FileMode, _ bool) (os.FileMode, bool, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, false, fmt.Errorf("stat %s: %w", path, os.ErrNotExist)
		}
		return 0, false, fmt.Errorf("stat %s: %w", path, err)
	}
	return 0, false, errors.New("config mode repair requires a Unix host: " + path)
}
