// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestEmitLicenseExpiryWarningIdempotent(t *testing.T) {
	home := t.TempDir()
	oldHome := cliutil.PipelockHome
	cliutil.PipelockHome = home
	t.Cleanup(func() { cliutil.PipelockHome = oldHome })

	cfg := config.Defaults()
	cfg.LicenseID = "lic_runtime"
	cfg.LicenseExpiresAt = time.Now().Add(7 * 24 * time.Hour).Unix()

	var stderr bytes.Buffer
	emitLicenseExpiryWarning(cfg, audit.NewNop(), nil, &stderr)
	first := stderr.String()
	if !strings.Contains(first, "expires in") {
		t.Fatalf("first warning missing: %q", first)
	}
	if _, err := os.Stat(filepath.Join(home, "state", licenseExpiryStateFile)); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	stderr.Reset()
	emitLicenseExpiryWarning(cfg, audit.NewNop(), nil, &stderr)
	if stderr.String() != "" {
		t.Fatalf("second warning should be suppressed, got %q", stderr.String())
	}
}

func TestLicenseExpiryStatePathEmptyWhenNoHome(t *testing.T) {
	oldHome := cliutil.PipelockHome
	cliutil.PipelockHome = ""
	t.Cleanup(func() { cliutil.PipelockHome = oldHome })
	t.Setenv("HOME", "")

	if got := licenseExpiryStatePath(); got != "" {
		t.Fatalf("licenseExpiryStatePath() = %q", got)
	}
}
