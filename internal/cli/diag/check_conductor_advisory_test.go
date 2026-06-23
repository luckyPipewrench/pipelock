// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestCheckConductorAdvisories(t *testing.T) {
	tests := []struct {
		name             string
		mutate           func(cfg *config.Config, dir string)
		wantSubstr       string
		forbidSubstr     string
		wantNoAdvisories bool
	}{
		{
			name: "conductor enabled without fleet license emits advisory",
			mutate: func(cfg *config.Config, _ string) {
				cfg.Conductor.Enabled = true
				// No license key set -> fleet check fails.
			},
			wantSubstr: "conductor.enabled is true but no license granting the \"fleet\" feature was found",
		},
		{
			name: "conductor disabled emits no fleet advisory",
			mutate: func(cfg *config.Config, _ string) {
				cfg.Conductor.Enabled = false
				// Disable flight recorder to suppress the unrelated advisory.
				cfg.FlightRecorder.Enabled = false
			},
			wantNoAdvisories: true,
		},
		{
			name: "conductor enabled with missing signing key path emits advisory",
			mutate: func(cfg *config.Config, dir string) {
				cfg.Conductor.Enabled = true
				cfg.FlightRecorder.SigningKeyPath = filepath.Join(dir, "nonexistent-key.json")
			},
			wantSubstr: "cannot be loaded; the proxy will fail to start (required when conductor.enabled)",
		},
		{
			name: "conductor enabled with unusable signing key file emits advisory",
			mutate: func(cfg *config.Config, dir string) {
				cfg.Conductor.Enabled = true
				kp := filepath.Join(dir, "garbage-key")
				if err := os.WriteFile(kp, []byte("not a valid signing key"), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg.FlightRecorder.SigningKeyPath = kp
			},
			wantSubstr: "is not a usable signing key; the proxy will fail to start (required when conductor.enabled)",
		},
		{
			name: "conductor enabled with mismatched recorder key id emits advisory",
			mutate: func(cfg *config.Config, dir string) {
				cfg.Conductor.Enabled = true
				// Write a JSON keypair with a key_id that differs from recorder_key_id.
				kp := writeJSONSigningKey(t, dir, "file-key-id")
				cfg.FlightRecorder.SigningKeyPath = kp
				cfg.Conductor.RecorderKeyID = "different-key-id"
			},
			wantSubstr: "conductor.recorder_key_id \"different-key-id\" does not match the key_id \"file-key-id\"",
		},
		{
			name: "matching recorder key id emits no mismatch advisory",
			mutate: func(cfg *config.Config, dir string) {
				cfg.Conductor.Enabled = true
				kp := writeJSONSigningKey(t, dir, "same-id")
				cfg.FlightRecorder.SigningKeyPath = kp
				cfg.Conductor.RecorderKeyID = "same-id"
			},
			// The fleet-license advisory will still fire (no license), but no
			// recorder-key-id mismatch advisory.
			wantSubstr:   "conductor.enabled is true but no license",
			forbidSubstr: "does not match the key_id",
		},
		{
			name: "raw key file emits no mismatch advisory",
			mutate: func(cfg *config.Config, dir string) {
				cfg.Conductor.Enabled = true
				kp := filepath.Join(dir, "raw-key")
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(kp, []byte(signingPrivateKey(priv)), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg.FlightRecorder.SigningKeyPath = kp
				cfg.Conductor.RecorderKeyID = "some-id"
			},
			// Only fleet-license advisory, no recorder mismatch.
			wantSubstr:   "conductor.enabled is true but no license",
			forbidSubstr: "does not match the key_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			dir := t.TempDir()
			tt.mutate(cfg, dir)

			advisories := checkConfigAdvisories(cfg)

			if tt.wantNoAdvisories {
				if len(advisories) > 0 {
					t.Fatalf("expected no advisories, got %d: %v", len(advisories), advisories)
				}
				return
			}

			found := false
			for _, a := range advisories {
				if strings.Contains(a, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected advisory containing %q, got %v", tt.wantSubstr, advisories)
			}
			if tt.forbidSubstr != "" {
				for _, a := range advisories {
					if strings.Contains(a, tt.forbidSubstr) {
						t.Errorf("did not expect advisory containing %q, got %v", tt.forbidSubstr, advisories)
						break
					}
				}
			}
		})
	}
}

func TestCheckConductorAdvisoriesMirrorsRequireIntermediateFleetGate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := license.Issue(license.License{
		ID:        "lic_diag_require_intermediate",
		Email:     "ops@example.test",
		IssuedAt:  time.Now().Add(-time.Hour).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Features:  []string{license.FeatureFleet},
	}, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Conductor.Enabled = true
	cfg.FlightRecorder.Enabled = false
	cfg.LicenseKey = token
	cfg.LicensePublicKey = hex.EncodeToString(pub)
	cfg.LicenseRequireIntermediateResolved = true
	cfg.LicenseIntermediateCert = []byte("configured intermediate certificate unavailable")

	advisories := checkConfigAdvisories(cfg)
	for _, advisory := range advisories {
		if strings.Contains(advisory, "conductor.enabled is true but no license granting the \"fleet\" feature was found") {
			return
		}
	}
	t.Fatalf("expected require-intermediate fleet-gate advisory, got %v", advisories)
}

func writeJSONSigningKey(t *testing.T, dir, keyID string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kf := map[string]any{
		"schema_version": 1,
		"key_id":         keyID,
		"public":         hex.EncodeToString(pub),
		"private":        hex.EncodeToString(priv),
		"created_at":     "2026-01-01T00:00:00Z",
	}
	data, err := json.Marshal(kf)
	if err != nil {
		t.Fatal(err)
	}
	kp := filepath.Join(dir, keyID+".json")
	if err := os.WriteFile(kp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return kp
}

func signingPrivateKey(priv ed25519.PrivateKey) string {
	return "pipelock-ed25519-private-v1\n" + base64.StdEncoding.EncodeToString(priv) + "\n"
}
