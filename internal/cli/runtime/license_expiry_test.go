// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
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
	cfg.LicenseIssuedAt = time.Now().Add(-38 * 24 * time.Hour).Unix()
	cfg.LicenseExpiresAt = time.Now().Add(7 * 24 * time.Hour).Unix()
	cfg.LicenseTier = "pro"

	var stderr bytes.Buffer
	emitLicenseExpiryWarning(cfg, audit.NewNop(), nil, &stderr)
	first := stderr.String()
	if !strings.Contains(first, "expires in") {
		t.Fatalf("first warning missing: %q", first)
	}
	if !strings.Contains(first, "check billing or token delivery") {
		t.Fatalf("first warning missing subscription action: %q", first)
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

func TestEmitLicenseExpiryWarningTrialLifetimeAndMessage(t *testing.T) {
	home := t.TempDir()
	oldHome := cliutil.PipelockHome
	cliutil.PipelockHome = home
	t.Cleanup(func() { cliutil.PipelockHome = oldHome })

	now := time.Now().UTC()
	atIssuance := config.Defaults()
	atIssuance.LicenseID = "lic_trial_new"
	atIssuance.LicenseIssuedAt = now.Unix()
	atIssuance.LicenseExpiresAt = now.Add(30 * 24 * time.Hour).Unix()
	atIssuance.LicenseTier = "trial"

	var stderr bytes.Buffer
	emitLicenseExpiryWarning(atIssuance, audit.NewNop(), nil, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("new trial emitted an expiry warning: %q", stderr.String())
	}

	approaching := config.Defaults()
	approaching.LicenseID = "lic_trial_approaching"
	approaching.LicenseIssuedAt = now.Add(-16 * 24 * time.Hour).Unix()
	approaching.LicenseExpiresAt = now.Add(14 * 24 * time.Hour).Unix()
	approaching.LicenseTier = "trial"

	emitLicenseExpiryWarning(approaching, audit.NewNop(), nil, &stderr)
	got := stderr.String()
	for _, want := range []string{
		"WARNING: trial ends in",
		"Pro features stop at expiry.",
		"Subscribe at https://pipelab.org/pricing/",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("trial warning missing %q: %q", want, got)
		}
	}
}

func TestEmitLicenseExpiryWarningStateFailuresStillEmit(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, home string)
		want  string
	}{
		{
			name:  "absent state",
			setup: func(_ *testing.T, _ string) {},
		},
		{
			name: "corrupt state",
			setup: func(t *testing.T, home string) {
				path := filepath.Join(home, "state", licenseExpiryStateFile)
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "state unavailable",
		},
		{
			name: "unreadable state path",
			setup: func(t *testing.T, home string) {
				if err := os.MkdirAll(filepath.Join(home, "state", licenseExpiryStateFile), 0o750); err != nil {
					t.Fatal(err)
				}
			},
			want: "state unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			oldHome := cliutil.PipelockHome
			cliutil.PipelockHome = home
			t.Cleanup(func() { cliutil.PipelockHome = oldHome })
			tt.setup(t, home)

			cfg := config.Defaults()
			cfg.LicenseID = "lic_state_failure"
			cfg.LicenseIssuedAt = time.Now().Add(-38 * 24 * time.Hour).Unix()
			cfg.LicenseExpiresAt = time.Now().Add(7 * 24 * time.Hour).Unix()
			cfg.LicenseTier = "pro"
			var stderr bytes.Buffer
			emitLicenseExpiryWarning(cfg, audit.NewNop(), nil, &stderr)
			if !strings.Contains(stderr.String(), "license expires in") {
				t.Fatalf("warning suppressed by %s: %q", tt.name, stderr.String())
			}
			if tt.want != "" && !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("warning missing %q: %q", tt.want, stderr.String())
			}
		})
	}
}

func TestEmitLicenseExpiryWarningNoops(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{name: "nil-config", cfg: nil},
		{name: "no-license-id", cfg: func() *config.Config { c := config.Defaults(); return c }()},
		{name: "no-expiry", cfg: func() *config.Config {
			c := config.Defaults()
			c.LicenseID = "lic_no_expiry"
			return c
		}()},
		{name: "far-expiry", cfg: func() *config.Config {
			c := config.Defaults()
			c.LicenseID = "lic_far"
			c.LicenseExpiresAt = time.Now().Add(31 * 24 * time.Hour).Unix()
			return c
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			emitLicenseExpiryWarning(tt.cfg, audit.NewNop(), nil, &stderr)
			if stderr.String() != "" {
				t.Fatalf("unexpected warning: %q", stderr.String())
			}
		})
	}
}

func TestLicenseExpiryStatePathEmptyWhenNoHome(t *testing.T) {
	oldHome := cliutil.PipelockHome
	cliutil.PipelockHome = ""
	t.Cleanup(func() { cliutil.PipelockHome = oldHome })
	t.Setenv("PIPELOCK_HOME", "")
	t.Setenv("HOME", "")

	if got := licenseExpiryStatePath(); got != "" {
		t.Fatalf("licenseExpiryStatePath() = %q", got)
	}
}

func TestStartLicenseExpiryWatcherReturnsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	(&Server{}).startLicenseExpiryWatcher(ctx)
}
