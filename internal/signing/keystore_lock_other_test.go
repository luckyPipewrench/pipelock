// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package signing

import (
	"errors"
	"testing"
)

// The js/wasm CI job compiles and runs this. Without it the fallback is the
// only lock implementation in the package with no test at all, and the half
// that matters is not the error value but the refusal to run the critical
// section: a fallback that returned the callback's result would hand back a
// transaction that only looks serialized.
func TestWithAgentLock_FailsClosedOnUnsupportedPlatform(t *testing.T) {
	called := false
	err := withAgentLock("ignored", func() error {
		called = true
		return nil
	})

	if !errors.Is(err, ErrUnsupportedAgentLock) {
		t.Errorf("error = %v, want ErrUnsupportedAgentLock", err)
	}
	if called {
		t.Error("the critical section ran without a lock; generation must refuse rather than race")
	}
}
