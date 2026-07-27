//go:build aix || (wasip1 && wasm)

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import "testing"

func TestCRLHighWaterLockFailsClosedOnUnsupportedPlatform(t *testing.T) {
	release, err := acquireCRLHighWaterLock("unused")
	if release != nil {
		t.Fatal("release function is non-nil on unsupported platform")
	}
	if err == nil {
		t.Fatal("acquireCRLHighWaterLock returned nil error on unsupported platform")
	}
}
