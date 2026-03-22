// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

// PlatformDefaultPolicy returns the platform-appropriate default sandbox policy.
// On Linux, this uses the standard DefaultPolicy with Linux paths.
func PlatformDefaultPolicy(workspace string) Policy {
	return DefaultPolicy(workspace)
}
