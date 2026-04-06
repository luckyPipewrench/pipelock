// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package rules

// WithFreshnessLock on Windows runs fn without file locking.
// Windows does not support flock; cross-process freshness protection
// is best-effort on this platform.
func WithFreshnessLock(_ string, fn func() error) error {
	return fn()
}
