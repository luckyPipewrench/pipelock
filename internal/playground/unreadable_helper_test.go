// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"os"
	"runtime"
	"testing"
)

// makeUnreadable removes read permission from path for the duration of the test
// and skips where that cannot work. Windows does not enforce Unix mode 0o000, so
// the file stays readable and the "read artifact ..." assertion fails for a
// reason that has nothing to do with the code under test. Root ignores the mode
// bits for the same reason, which matters because some CI containers run as
// root.
func makeUnreadable(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("windows does not enforce mode 0o000, so an unreadable-file case cannot be set up this way")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which bypasses the mode bits this case depends on")
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
}
