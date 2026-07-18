// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func TestLoadForInspectionRejectsMalformedTrailingDocument(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	data := []byte("mode: balanced\n---\ninvalid: [")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadForInspection(path)
	if err == nil {
		t.Fatal("malformed trailing document was accepted")
	}
	if !strings.Contains(err.Error(), "parsing config") {
		t.Fatalf("error = %q, want parse failure", err)
	}
}

func TestLoadRejectsNonRegularConfigSource(t *testing.T) {
	t.Parallel()

	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("directory was accepted as a config file")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error = %q, want non-regular-file rejection", err)
	}
}

func TestLoadRejectsUnreadableLicenseMaterial(t *testing.T) {
	t.Setenv(EnvLicenseKey, "")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "license.token")
	if err := os.WriteFile(tokenPath, []byte("configured-token"), 0o600); err != nil {
		t.Fatalf("write license file: %v", err)
	}
	if err := os.Chmod(tokenPath, 0o200); err != nil {
		t.Fatalf("remove read permission: %v", err)
	}
	if probe, err := os.Open(tokenPath); err == nil { // #nosec G304 -- fixed path inside t.TempDir.
		_ = probe.Close()
		t.Skip("current user can bypass file mode read restrictions")
	}

	configPath := filepath.Join(dir, "pipelock.yaml")
	data := []byte("mode: balanced\nlicense_file: license.token\n")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatal("unreadable license file was accepted")
	}
	if !strings.Contains(err.Error(), "reading license_file") {
		t.Fatalf("error = %q, want license read failure", err)
	}
}

func TestPolicyBundleLoadRejectsInvalidLateSecurityControl(t *testing.T) {
	t.Parallel()

	_, err := LoadPolicyBundleBytes([]byte(`
mode: balanced
airlock:
  enabled: true
`))
	if err == nil {
		t.Fatal("airlock without session profiling was accepted")
	}
	if !strings.Contains(err.Error(), "airlock.enabled requires session_profiling.enabled") {
		t.Fatalf("error = %q, want airlock dependency rejection", err)
	}
}

func TestValidateRejectsInvalidLateSecurityControls(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "airlock requires session profiling",
			mutate: func(cfg *Config) {
				cfg.Airlock.Enabled = true
				cfg.SessionProfiling.Enabled = false
			},
			wantErr: "airlock.enabled requires session_profiling.enabled",
		},
		{
			name: "browser shield rejects unknown strictness",
			mutate: func(cfg *Config) {
				cfg.BrowserShield.Enabled = true
				cfg.BrowserShield.Strictness = "unknown"
			},
			wantErr: "browser_shield.strictness",
		},
		{
			name: "redaction requires request body scanning",
			mutate: func(cfg *Config) {
				cfg.Redaction = redact.Config{
					Enabled:        true,
					DefaultProfile: "code",
					Profiles: map[string]redact.ProfileSpec{
						"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
					},
					Limits: redact.DefaultLimits(),
				}
				cfg.RequestBodyScanning.Enabled = false
			},
			wantErr: "redaction: enabled=true requires request_body_scanning.enabled=true",
		},
		{
			name: "inbound envelope requires pinned trust",
			mutate: func(cfg *Config) {
				cfg.MediationEnvelope.VerifyInbound.Enabled = true
				cfg.MediationEnvelope.VerifyInbound.TrustList = nil
			},
			wantErr: "verify_inbound.trust_list must contain at least one trusted key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := Defaults()
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("invalid config was accepted; want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestReloaderWatchSetupFailureResolvesLifecycleChannels(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing", "pipelock.yaml")
	reloader := NewReloader(path)

	err := reloader.Start(context.Background())
	if err == nil {
		t.Fatal("watching a missing parent directory succeeded")
	}
	if !strings.Contains(err.Error(), "watching directory") {
		t.Fatalf("error = %q, want watcher setup failure", err)
	}

	select {
	case <-reloader.Ready():
	default:
		t.Fatal("Ready remained blocked after watcher setup failed")
	}
	select {
	case _, ok := <-reloader.Changes():
		if ok {
			t.Fatal("Changes remained open after Start returned")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Changes did not close after Start returned")
	}
}

func TestReloadReportsSecurityControlsBeingWeakened(t *testing.T) {
	t.Parallel()

	on := true
	off := false
	old := Defaults()
	old.A2AScanning.Enabled = true
	old.A2AScanning.ScanAgentCards = true
	old.A2AScanning.DetectCardDrift = true
	old.A2AScanning.SessionSmugglingDetection = true
	old.A2AScanning.ScanRawParts = true
	old.Emit.Forwarder.URL = "https://siem.vendor.example/events"
	old.MediaPolicy.Enabled = &on
	old.MediaPolicy.StripImages = &on
	old.MediaPolicy.StripAudio = &on
	old.MediaPolicy.StripVideo = &on
	old.MediaPolicy.StripImageMetadata = &on
	old.MediaPolicy.LogMediaExposure = &on
	old.Redaction.Enabled = true

	updated := old.Clone()
	updated.A2AScanning.ScanAgentCards = false
	updated.A2AScanning.DetectCardDrift = false
	updated.A2AScanning.SessionSmugglingDetection = false
	updated.A2AScanning.ScanRawParts = false
	updated.Emit.Forwarder.URL = ""
	updated.MediaPolicy.Enabled = &off
	updated.MediaPolicy.StripImages = &off
	updated.MediaPolicy.StripAudio = &off
	updated.MediaPolicy.StripVideo = &off
	updated.MediaPolicy.StripImageMetadata = &off
	updated.MediaPolicy.LogMediaExposure = &off
	updated.Redaction.Enabled = false

	got := make(map[string]bool)
	for _, warning := range ValidateReload(old, updated) {
		got[warning.Field] = true
	}
	want := []string{
		"a2a_scanning.scan_agent_cards",
		"a2a_scanning.detect_card_drift",
		"a2a_scanning.session_smuggling_detection",
		"a2a_scanning.scan_raw_parts",
		"emit.forwarder.url",
		"media_policy.enabled",
		"media_policy.strip_images",
		"media_policy.strip_audio",
		"media_policy.strip_video",
		"media_policy.strip_image_metadata",
		"media_policy.log_media_exposure",
		"redaction.enabled",
	}
	for _, field := range want {
		if !got[field] {
			t.Errorf("missing reload warning for %s", field)
		}
	}
}
