// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireNonRegularLicenseRejected asserts that Load rejects a license_file
// that is not a regular file. The caller creates the non-regular
// license.token inside tmp using whatever mechanism its platform supports;
// the security meaning of the rejection is identical either way.
func requireNonRegularLicenseRejected(t *testing.T, tmp string) {
	t.Helper()

	cfgPath := filepath.Join(tmp, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(testLicenseFileCfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for non-regular license_file")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("error should mention regular file, got: %v", err)
	}
}
