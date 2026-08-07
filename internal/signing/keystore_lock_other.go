// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package signing

import "errors"

// ErrUnsupportedAgentLock reports that this platform offers no advisory file
// lock the keystore can rely on for mutual exclusion.
var ErrUnsupportedAgentLock = errors.New("agent key locking is unsupported on this platform")

// withAgentLock fails closed where an advisory file lock is unavailable. The
// lock is what keeps two publishers from interleaving their writes to one
// agent's key directory, so running the critical section without it would give
// the caller a transaction that only appears serialized. Refusing is the safe
// direction: a keystore that cannot be locked should decline to generate rather
// than race, and callers already handle a generation error.
//
// This mirrors the securefile package, which fails closed the same way where
// its no-follow open primitives do not exist. It exists because the unix and
// windows implementations do not cover every target the module builds for, and
// js/wasm is one CI actually compiles.
func withAgentLock(_ string, _ func() error) error {
	return ErrUnsupportedAgentLock
}
