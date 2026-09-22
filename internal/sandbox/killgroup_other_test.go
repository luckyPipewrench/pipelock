// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package sandbox

import "errors"

// killProcessGroup is unavailable off Unix. The tests that need it require
// sandbox primitives and already skip on those platforms; this exists so the
// package still builds for them, because a runtime skip does not prevent
// compilation of a Unix-only syscall.
func killProcessGroup(int) error {
	return errors.New("process groups are not available on this platform")
}

// processGone is unavailable off Unix, for the same reason as
// killProcessGroup. The descendant assertion that calls it is guarded by the
// same sandbox-primitive requirement, so this only has to compile.
func processGone(int) bool {
	return false
}
