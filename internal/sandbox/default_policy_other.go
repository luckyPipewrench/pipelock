// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux || darwin)

package sandbox

// PlatformDefaultPolicy returns the platform-appropriate default sandbox policy.
// On unsupported platforms, falls back to the Linux default (which won't be
// used since the sandbox is unavailable).
func PlatformDefaultPolicy(workspace string) Policy {
	return DefaultPolicy(workspace)
}
