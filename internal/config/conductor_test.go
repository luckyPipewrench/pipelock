// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyDefaults_Conductor(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()

	if cfg.Conductor.Enabled {
		t.Fatal("Conductor.Enabled = true, want false")
	}
	if cfg.Conductor.PollInterval != "30s" {
		t.Fatalf("PollInterval = %q, want 30s", cfg.Conductor.PollInterval)
	}
	if cfg.Conductor.CreatedSkewSeconds != 60 {
		t.Fatalf("CreatedSkewSeconds = %d, want 60", cfg.Conductor.CreatedSkewSeconds)
	}
	if cfg.Conductor.MaxMinVersionMinorSkew != 1 {
		t.Fatalf("MaxMinVersionMinorSkew = %d, want 1", cfg.Conductor.MaxMinVersionMinorSkew)
	}
	if cfg.Conductor.MaxCapabilityThreshold != 7 {
		t.Fatalf("MaxCapabilityThreshold = %d, want 7", cfg.Conductor.MaxCapabilityThreshold)
	}
	if !cfg.Conductor.EmergencyStreamEnabled() {
		t.Fatal("EmergencyStreamEnabled() = false, want true")
	}
	if cfg.Conductor.StalePolicy.GraceMultiplier != 1 {
		t.Fatalf("StalePolicy.GraceMultiplier = %d, want 1", cfg.Conductor.StalePolicy.GraceMultiplier)
	}
	if cfg.Conductor.StalePolicy.AfterGrace != ConductorStaleStrictDenyAll {
		t.Fatalf("StalePolicy.AfterGrace = %q, want %q", cfg.Conductor.StalePolicy.AfterGrace, ConductorStaleStrictDenyAll)
	}
}

func TestValidateConductor_DisabledStillValidatesLocalSafetyKnobs(t *testing.T) {
	cfg := Defaults()
	cfg.Conductor.CreatedSkewSeconds = 301

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "conductor.created_skew_seconds") {
		t.Fatalf("Validate() = %v, want created_skew_seconds error", err)
	}
}

func TestValidateConductor_Enabled(t *testing.T) {
	cfg := Defaults()
	cfg.Conductor = validConductorConfig(t)

	if _, err := cfg.ValidateWithWarnings(); err != nil {
		t.Fatalf("ValidateWithWarnings() error = %v", err)
	}
}

func TestValidateConductor_RejectsInvalidEnabledConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Conductor)
		want   string
	}{
		{
			name:   "missing_url",
			mutate: func(c *Conductor) { c.ConductorURL = "" },
			want:   "conductor.conductor_url required",
		},
		{
			name:   "http_url",
			mutate: func(c *Conductor) { c.ConductorURL = "http://conductor.example" },
			want:   "https URL",
		},
		{
			name:   "url_userinfo",
			mutate: func(c *Conductor) { c.ConductorURL = "https://user:pass@conductor.example" },
			want:   "must not include userinfo",
		},
		{
			name:   "url_path",
			mutate: func(c *Conductor) { c.ConductorURL = "https://conductor.example/admin" },
			want:   "must not include a path component",
		},
		{
			name:   "bad_instance_id",
			mutate: func(c *Conductor) { c.InstanceID = "-bad" },
			want:   "conductor.instance_id must start",
		},
		{
			name:   "relative_cert",
			mutate: func(c *Conductor) { c.ClientCertPath = "client.crt" },
			want:   "conductor.client_cert_path must be an absolute path",
		},
		{
			name:   "missing_server_ca",
			mutate: func(c *Conductor) { c.ServerCAFile = "" },
			want:   "conductor.server_ca_file required",
		},
		{
			name:   "relative_server_ca",
			mutate: func(c *Conductor) { c.ServerCAFile = "boss-ca.pem" },
			want:   "conductor.server_ca_file must be an absolute path",
		},
		{
			name:   "bad_poll_interval",
			mutate: func(c *Conductor) { c.PollInterval = "0s" },
			want:   "conductor.poll_interval must be > 0",
		},
		{
			// Sub-second poll interval is a trivial DoS lever. A
			// misconfigured or compromised follower could flood Conductor with
			// thousands of requests per second.
			name:   "poll_interval_below_floor",
			mutate: func(c *Conductor) { c.PollInterval = "10ms" },
			want:   "conductor.poll_interval must be >=",
		},
		{
			name:   "bad_stale_policy",
			mutate: func(c *Conductor) { c.StalePolicy.AfterGrace = "permissive" },
			want:   "conductor.stale_policy.after_grace",
		},
		{
			name:   "threshold_too_low",
			mutate: func(c *Conductor) { c.MaxCapabilityThreshold = 1 },
			want:   "conductor.max_capability_threshold",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			conductor := validConductorConfig(t)
			tc.mutate(&conductor)
			cfg.Conductor = conductor

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateConductor_RejectsWorldWritableParents(t *testing.T) {
	parent := filepath.Join(privateTempDir(t), "world")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(parent, 0o777); err != nil { //nolint:gosec // verifies rejection of unsafe parent permissions.
		t.Fatalf("Chmod() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Conductor)
	}{
		{
			name:   "bundle_cache_dir",
			mutate: func(c *Conductor) { c.BundleCacheDir = filepath.Join(parent, "bundles") },
		},
		{
			name:   "durable_audit_queue_dir",
			mutate: func(c *Conductor) { c.DurableAuditQueueDir = filepath.Join(parent, "audit-queue") },
		},
		{
			name:   "trust_roster_path",
			mutate: func(c *Conductor) { c.TrustRosterPath = filepath.Join(parent, "trust-roster.json") },
		},
		{
			name:   "server_ca_file",
			mutate: func(c *Conductor) { c.ServerCAFile = filepath.Join(parent, "boss-ca.pem") },
		},
		{
			name:   "client_cert_path",
			mutate: func(c *Conductor) { c.ClientCertPath = filepath.Join(parent, "client.crt") },
		},
		{
			name:   "client_key_path",
			mutate: func(c *Conductor) { c.ClientKeyPath = filepath.Join(parent, "client.key") },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			conductor := validConductorConfig(t)
			tc.mutate(&conductor)
			cfg.Conductor = conductor

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "world-writable parent") {
				t.Fatalf("Validate() = %v, want world-writable parent error", err)
			}
		})
	}
}

func TestValidateConductor_RejectsSymlinkResolvedWorldWritableParent(t *testing.T) {
	cfg := Defaults()
	conductor := validConductorConfig(t)
	root := privateTempDir(t)
	world := filepath.Join(root, "world")
	target := filepath.Join(world, "target")
	if err := os.Mkdir(world, 0o700); err != nil {
		t.Fatalf("Mkdir(world) error = %v", err)
	}
	if err := os.Chmod(world, 0o777); err != nil { //nolint:gosec // verifies rejection of unsafe resolved parent permissions.
		t.Fatalf("Chmod(world) error = %v", err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	conductor.BundleCacheDir = filepath.Join(link, "bundles")
	cfg.Conductor = conductor

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "world-writable parent") {
		t.Fatalf("Validate() = %v, want world-writable parent error", err)
	}
}

func TestValidateConductor_StalePolicyOverrideWarns(t *testing.T) {
	cfg := Defaults()
	conductor := validConductorConfig(t)
	conductor.StalePolicy.AfterGrace = ConductorStaleContinueLastKnownGood
	cfg.Conductor = conductor

	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings() error = %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want one warning", warnings)
	}
	if warnings[0].Field != "conductor.stale_policy.after_grace" {
		t.Fatalf("warning field = %q", warnings[0].Field)
	}
}

func TestCanonicalPolicyHash_ExcludesConductor(t *testing.T) {
	base := Defaults()
	withConductor := base.Clone()
	withConductor.Conductor = validConductorConfig(t)

	if got, want := withConductor.CanonicalPolicyHash(), base.CanonicalPolicyHash(); got != want {
		t.Fatalf("CanonicalPolicyHash() changed with conductor config: got %s want %s", got, want)
	}
}

func TestConductor_EmergencyStreamEnabled(t *testing.T) {
	enabled := true
	disabled := false
	tests := []struct {
		name string
		cfg  Conductor
		want bool
	}{
		{name: "nil_defaults_true", cfg: Conductor{}, want: true},
		{name: "explicit_true", cfg: Conductor{EmergencyStream: &enabled}, want: true},
		{name: "explicit_false", cfg: Conductor{EmergencyStream: &disabled}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.EmergencyStreamEnabled(); got != tc.want {
				t.Fatalf("EmergencyStreamEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoad_ConductorEmergencyStreamDefaulting(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{name: "omitted", yaml: "mode: balanced\n", want: true},
		{name: "null", yaml: "mode: balanced\nconductor:\n  emergency_stream: null\n", want: true},
		{name: "explicit_false", yaml: "mode: balanced\nconductor:\n  emergency_stream: false\n", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got := cfg.Conductor.EmergencyStreamEnabled(); got != tc.want {
				t.Fatalf("EmergencyStreamEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func validConductorConfig(t *testing.T) Conductor {
	t.Helper()
	root := privateTempDir(t)
	return Conductor{
		Enabled:                true,
		ConductorURL:           "https://conductor.example",
		OrgID:                  "org_main",
		FleetID:                "prod",
		InstanceID:             "pl-prod-1",
		TrustRosterPath:        filepath.Join(root, "trust-roster.json"),
		ServerCAFile:           filepath.Join(root, "boss-ca.pem"),
		ClientCertPath:         filepath.Join(root, "client.crt"),
		ClientKeyPath:          filepath.Join(root, "client.key"),
		BundleCacheDir:         filepath.Join(root, "bundles"),
		DurableAuditQueueDir:   filepath.Join(root, "audit-queue"),
		PollInterval:           "30s",
		HonorRemoteKillSwitch:  false,
		EmergencyStream:        ptrBool(true),
		CreatedSkewSeconds:     60,
		MaxMinVersionMajorSkew: 0,
		MaxMinVersionMinorSkew: 1,
		MaxCapabilityThreshold: 7,
		StalePolicy:            ConductorStalePolicy{GraceMultiplier: 1, AfterGrace: ConductorStaleStrictDenyAll},
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".conductor-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("RemoveAll(%s) error = %v", dir, err)
		}
	})
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("Abs(%s) error = %v", dir, err)
	}
	return abs
}
