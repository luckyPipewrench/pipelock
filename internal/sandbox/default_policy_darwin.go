// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

// PlatformDefaultPolicy returns the platform-appropriate default sandbox policy.
// On macOS, this uses macOS-specific paths (Homebrew, /Library, /System, etc.).
func PlatformDefaultPolicy(workspace string) Policy {
	return DefaultPolicyDarwin(workspace)
}
