// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"os"
	"runtime"
	"testing"
)

// makeUnreadable is the playground_test copy of the helper in
// unreadable_helper_test.go. Go test helpers cannot cross the internal/external
// test package boundary, and both packages have unreadable-file cases, so the
// two copies must stay in step. See that file for why each skip exists.
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
