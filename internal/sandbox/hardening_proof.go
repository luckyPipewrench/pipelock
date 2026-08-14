// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !mcp_hardening_test

package sandbox

// recordParentHardeningForTest is replaced only in the hardening proof build.
func recordParentHardeningForTest() error { return nil }
