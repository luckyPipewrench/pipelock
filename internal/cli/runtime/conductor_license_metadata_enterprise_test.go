//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import "testing"

func TestNewServer_ConductorCarriesVerifiedLicenseWarningMetadata(t *testing.T) {
	t.Setenv("PIPELOCK_HOME", t.TempDir())
	s, _ := newConductorApplyTestServer(t)
	cfg := s.proxy.CurrentConfig()
	if cfg.LicenseIssuedAt == 0 || cfg.LicenseExpiresAt == 0 {
		t.Fatalf("runtime license timestamps = issued=%d expires=%d, want verified claims", cfg.LicenseIssuedAt, cfg.LicenseExpiresAt)
	}
	if cfg.LicenseTier != "enterprise" {
		t.Fatalf("LicenseTier = %q, want enterprise", cfg.LicenseTier)
	}
	stderr := s.opts.Stderr.(*stderrSyncWriter).w.(*syncBuffer)
	if !stderr.contains("license expires in 1 day(s)") {
		t.Fatalf("startup warning did not use verified license metadata: %s", stderr.String())
	}
}
