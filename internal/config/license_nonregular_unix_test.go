// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import (
	"path/filepath"
	"syscall"
	"testing"
)

// TestLicenseKeyFileNonRegular covers the FIFO case called out in
// (*Config).resolveLicenseKey: a FIFO can block the reader indefinitely, so it
// must be rejected before any read is attempted.
func TestLicenseKeyFileNonRegular(t *testing.T) {
	tmp := t.TempDir()

	fifoPath := filepath.Join(tmp, "license.token")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	requireNonRegularLicenseRejected(t, tmp)
}
