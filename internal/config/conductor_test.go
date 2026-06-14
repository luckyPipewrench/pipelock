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
	if cfg.Conductor.EnrollmentTokenPath != "" {
		t.Fatalf("EnrollmentTokenPath = %q, want empty", cfg.Conductor.EnrollmentTokenPath)
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
	configureConductorRecorder(t, cfg)

	if _, err := cfg.ValidateWithWarnings(); err != nil {
		t.Fatalf("ValidateWithWarnings() error = %v", err)
	}
}

// TestValidateConductor_RequiresFingerprintRegardlessOfHonor locks in the
// contract that a pinned trust-roster root fingerprint is mandatory whenever
// conductor.enabled, INDEPENDENT of honor_remote_kill_switch. The honor flag
// only governs whether remote-kill STATE is applied; it does not relax the
// trust-material requirement, because the policy-bundle poller verifies signed
// bundles against the pinned root even when remote kill is not honored.
func TestValidateConductor_RequiresFingerprintRegardlessOfHonor(t *testing.T) {
	tests := []struct {
		name        string
		honor       bool
		fingerprint string
		want        string
	}{
		{name: "honor_false_missing_fingerprint", honor: false, fingerprint: "", want: "conductor.trust_roster_root_fingerprint required"},
		{name: "honor_true_missing_fingerprint", honor: true, fingerprint: "", want: "conductor.trust_roster_root_fingerprint required"},
		{name: "honor_false_bad_fingerprint", honor: false, fingerprint: "bad", want: "conductor.trust_roster_root_fingerprint"},
		{name: "honor_true_bad_fingerprint", honor: true, fingerprint: "bad", want: "conductor.trust_roster_root_fingerprint"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			conductor := validConductorConfig(t)
			conductor.HonorRemoteKillSwitch = tc.honor
			conductor.TrustRosterRootFingerprint = tc.fingerprint
			cfg.Conductor = conductor
			configureConductorRecorder(t, cfg)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestValidateConductor_AcceptsHonorFalseWithFingerprint is the positive
// counterpart: honor_remote_kill_switch=false is a valid configuration as long
// as the pinned fingerprint is present (audit + policy-sync still participate).
func TestValidateConductor_AcceptsHonorFalseWithFingerprint(t *testing.T) {
	cfg := Defaults()
	conductor := validConductorConfig(t)
	conductor.HonorRemoteKillSwitch = false
	cfg.Conductor = conductor
	configureConductorRecorder(t, cfg)

	if _, err := cfg.ValidateWithWarnings(); err != nil {
		t.Fatalf("ValidateWithWarnings() with honor=false + fingerprint should pass, got %v", err)
	}
}

func TestValidateConductor_RequiresSignedFlightRecorder(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "disabled",
			mutate: func(cfg *Config) { cfg.FlightRecorder.Enabled = false },
			want:   "flight_recorder.enabled must be true",
		},
		{
			name:   "unsigned_checkpoints",
			mutate: func(cfg *Config) { cfg.FlightRecorder.SignCheckpoints = false },
			want:   "flight_recorder.sign_checkpoints must be true",
		},
		{
			name:   "missing_signing_key",
			mutate: func(cfg *Config) { cfg.FlightRecorder.SigningKeyPath = "" },
			want:   "flight_recorder.signing_key_path required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Conductor = validConductorConfig(t)
			configureConductorRecorder(t, cfg)
			tc.mutate(cfg)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want substring %q", err, tc.want)
			}
		})
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
			name:   "relative_enrollment_token_path",
			mutate: func(c *Conductor) { c.EnrollmentTokenPath = "enrollment-token" },
			want:   "conductor.enrollment_token_path must be an absolute path",
		},
		{
			name:   "missing_server_ca",
			mutate: func(c *Conductor) { c.ServerCAFile = "" },
			want:   "conductor.server_ca_file required",
		},
		{
			name:   "missing_trust_roster_root_fingerprint",
			mutate: func(c *Conductor) { c.TrustRosterRootFingerprint = "" },
			want:   "conductor.trust_roster_root_fingerprint required",
		},
		{
			name:   "bad_trust_roster_root_fingerprint",
			mutate: func(c *Conductor) { c.TrustRosterRootFingerprint = "bad" },
			want:   "conductor.trust_roster_root_fingerprint",
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
			configureConductorRecorder(t, cfg)

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
			configureConductorRecorder(t, cfg)

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
	configureConductorRecorder(t, cfg)

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
	configureConductorRecorder(t, cfg)

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

func TestLoad_ConductorHonorRemoteKillSwitchDefaulting(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{name: "conductor_section_omitted", yaml: "mode: balanced\n", want: true},
		{name: "conductor_section_null", yaml: "mode: balanced\nconductor: null\n", want: true},
		{name: "field_omitted", yaml: "mode: balanced\nconductor: {}\n", want: true},
		{name: "null", yaml: "mode: balanced\nconductor:\n  honor_remote_kill_switch: null\n", want: true},
		{name: "explicit_true", yaml: "mode: balanced\nconductor:\n  honor_remote_kill_switch: true\n", want: true},
		{name: "explicit_false", yaml: "mode: balanced\nconductor:\n  honor_remote_kill_switch: false\n", want: false},
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
			if got := cfg.Conductor.HonorRemoteKillSwitch; got != tc.want {
				t.Fatalf("HonorRemoteKillSwitch = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestValidateConductor_AcceptsFollowerLabels proves a well-formed follower
// audience-labels map passes validation when conductor is enabled.
func TestValidateConductor_AcceptsFollowerLabels(t *testing.T) {
	cfg := Defaults()
	cfg.Conductor = validConductorConfig(t)
	cfg.Conductor.Labels = map[string]string{
		"ring":                         "canary",
		"region":                       "us-east",
		strings.Repeat("k", 128):       strings.Repeat("v", 256),
		"max_value_boundary_is_256_ok": strings.Repeat("v", maxConductorLabelValueBytes),
	}
	configureConductorRecorder(t, cfg)

	if _, err := cfg.ValidateWithWarnings(); err != nil {
		t.Fatalf("ValidateWithWarnings() with valid labels error = %v", err)
	}
}

// TestValidateConductor_RejectsMalformedFollowerLabels proves an empty label key
// or empty label value is a fail-closed validation error rather than a silently
// broadening config (a missing-key map lookup is the empty string, so an
// empty-valued label could spuriously match an empty-valued audience).
func TestValidateConductor_RejectsMalformedFollowerLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{name: "empty_key", labels: map[string]string{"": "canary"}, want: "must not contain an empty key"},
		{name: "blank_key", labels: map[string]string{"   ": "canary"}, want: "must not contain an empty key"},
		{name: "empty_value", labels: map[string]string{"ring": ""}, want: `conductor.labels["ring"] must not have an empty value`},
		{name: "blank_value", labels: map[string]string{"ring": "  "}, want: `conductor.labels["ring"] must not have an empty value`},
		{name: "long_key", labels: map[string]string{strings.Repeat("k", maxConductorLabelKeyBytes+1): "canary"}, want: "must be <= 128 bytes"},
		{name: "long_value", labels: map[string]string{"ring": strings.Repeat("v", maxConductorLabelValueBytes+1)}, want: "value must be <= 256 bytes"},
		// Charset must mirror the leader-side selector (isIdentifier): a label the
		// leader cannot express is silently unreachable, so reject it at startup.
		{name: "space_in_value", labels: map[string]string{"ring": "us east"}, want: "must use only alphanumerics"},
		{name: "space_in_key", labels: map[string]string{"data center": "east"}, want: "must use only alphanumerics"},
		{name: "leading_dot_key", labels: map[string]string{".ring": "canary"}, want: "must use only alphanumerics"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Conductor = validConductorConfig(t)
			cfg.Conductor.Labels = tc.labels
			configureConductorRecorder(t, cfg)

			_, err := cfg.ValidateWithWarnings()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateWithWarnings() = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestLoad_ConductorLabelsRoundTrip proves the conductor.labels map unmarshals
// from YAML through the strict (KnownFields) loader. Without the schema field a
// `labels:` key would be rejected as an unknown field; this locks in that the
// field exists and parses key/value pairs.
func TestLoad_ConductorLabelsRoundTrip(t *testing.T) {
	root := privateTempDir(t)
	cfgPath := filepath.Join(root, "cfg.yaml")
	// conductor.enabled is intentionally false so Load does not require the full
	// enterprise trust-material set; we are exercising the YAML parse of the
	// labels map, not the enabled-follower validation path.
	data := strings.Join([]string{
		"mode: balanced",
		"conductor:",
		"  labels:",
		"    ring: canary",
		"    region: us-east",
		"",
	}, "\n")
	if err := os.WriteFile(cfgPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Conductor.Labels["ring"]; got != "canary" {
		t.Fatalf("conductor.labels[ring] = %q, want canary", got)
	}
	if got := cfg.Conductor.Labels["region"]; got != "us-east" {
		t.Fatalf("conductor.labels[region] = %q, want us-east", got)
	}
}

func validConductorConfig(t *testing.T) Conductor {
	t.Helper()
	root := privateTempDir(t)
	return Conductor{
		Enabled:                    true,
		ConductorURL:               "https://conductor.example",
		OrgID:                      "org_main",
		FleetID:                    "prod",
		InstanceID:                 "pl-prod-1",
		TrustRosterPath:            filepath.Join(root, "trust-roster.json"),
		TrustRosterRootFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ServerCAFile:               filepath.Join(root, "boss-ca.pem"),
		ClientCertPath:             filepath.Join(root, "client.crt"),
		ClientKeyPath:              filepath.Join(root, "client.key"),
		BundleCacheDir:             filepath.Join(root, "bundles"),
		DurableAuditQueueDir:       filepath.Join(root, "audit-queue"),
		PollInterval:               "30s",
		HonorRemoteKillSwitch:      true,
		EmergencyStream:            ptrBool(true),
		CreatedSkewSeconds:         60,
		MaxMinVersionMajorSkew:     0,
		MaxMinVersionMinorSkew:     1,
		MaxCapabilityThreshold:     7,
		StalePolicy:                ConductorStalePolicy{GraceMultiplier: 1, AfterGrace: ConductorStaleStrictDenyAll},
	}
}

func configureConductorRecorder(t *testing.T, cfg *Config) {
	t.Helper()
	root := privateTempDir(t)
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = filepath.Join(root, "recorder")
	cfg.FlightRecorder.SignCheckpoints = true
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(root, "recorder.key")
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
