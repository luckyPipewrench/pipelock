// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && mcp_hardening_test

package sandbox

// ApplyLandlock reports an active test layer in the hardening proof build.
// The fixture needs the kernel's proc access decision to be observable without
// Landlock denying the same open first. Production binaries compile the real
// Landlock implementation.
func ApplyLandlock(Policy) (LayerStatus, error) {
	return LayerStatus{Name: LayerLandlock, Active: true, Version: 1}, nil
}
