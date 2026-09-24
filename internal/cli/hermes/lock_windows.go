// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hermes

// withHermesLock on Windows runs fn without a cross-process lock: Windows has
// no flock, and concurrent install and rollback of one Hermes config remain
// unserialized there.
func withHermesLock(_ string, fn func() error) error {
	return fn()
}
