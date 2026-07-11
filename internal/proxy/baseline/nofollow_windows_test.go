// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package baseline

import (
	"errors"
	"testing"
)

func TestOpenRegularFileNoSymlinkBelowRootWindowsFailsClosed(t *testing.T) {
	f, err := openRegularFileNoSymlinkBelowRoot("C:\\baseline", "profile.json", "C:\\baseline\\profile.json")
	if err == nil {
		t.Fatal("openRegularFileNoSymlinkBelowRoot succeeded on Windows")
	}
	if f != nil {
		t.Fatalf("openRegularFileNoSymlinkBelowRoot file = %v, want nil", f)
	}
	if !errors.Is(err, errNoFollowUnsupported) {
		t.Fatalf("openRegularFileNoSymlinkBelowRoot error = %v, want errNoFollowUnsupported", err)
	}
}
