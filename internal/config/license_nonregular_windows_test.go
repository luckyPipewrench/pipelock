// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsLicenseKeyFileNonRegular is the Windows counterpart to the FIFO
// case in license_nonregular_unix_test.go. Windows has no mkfifo, but a
// directory is equally non-regular, so it exercises the same
// Mode().IsRegular() rejection in (*Config).resolveLicenseKey rather than
// skipping the coverage entirely.
func TestWindowsLicenseKeyFileNonRegular(t *testing.T) {
	tmp := t.TempDir()

	dirPath := filepath.Join(tmp, "license.token")
	if err := os.Mkdir(dirPath, 0o750); err != nil {
		t.Fatalf("create directory: %v", err)
	}

	requireNonRegularLicenseRejected(t, tmp)
}
