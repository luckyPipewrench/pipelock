// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package signing

import (
	"path/filepath"
	"testing"
)

// syncDirectory is defined only in the linux publication path, so a test that
// calls it has to carry the same build tag. Without one the whole package fails
// to compile for GOOS=windows, which this package supports.

func TestSyncDirectory_ReportsMissingPath(t *testing.T) {
	// The fsync is what makes a completed exchange durable, so a path it cannot
	// open is reported rather than swallowed. Callers decide what to do with it;
	// silently returning nil here is what let a publication claim success while
	// remaining vulnerable to a power loss.
	if err := syncDirectory(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("syncDirectory reported success for a path it could not open")
	}
}
