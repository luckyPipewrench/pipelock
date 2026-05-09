// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDefaults_LearnLock(t *testing.T) {
	cfg := Defaults()
	if cfg.LearnLock.Enabled {
		t.Errorf("expected LearnLock.Enabled=false, got true")
	}
	if cfg.LearnLock.Mode != LockModeShadow {
		t.Errorf("expected LearnLock.Mode=shadow (safe default), got %q", cfg.LearnLock.Mode)
	}
	if cfg.LearnLock.MinimumSignatures != 1 {
		t.Errorf("expected LearnLock.MinimumSignatures=1, got %d", cfg.LearnLock.MinimumSignatures)
	}
}

func TestLearnLock_EffectiveModeFallsBackToShadow(t *testing.T) {
	cases := map[string]string{
		"":         LockModeShadow,
		"unknown":  LockModeShadow,
		"  live  ": LockModeShadow, // strict match — no whitespace coercion
		"Live":     LockModeShadow, // strict match — case-sensitive
		"live":     LockModeLive,
		"shadow":   LockModeShadow,
		"capture":  LockModeCapture,
	}
	for input, want := range cases {
		input, want := input, want
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got := LearnLock{Mode: input}.EffectiveMode()
			if got != want {
				t.Fatalf("EffectiveMode(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestLearnLock_EffectiveMinimumSignaturesDefaultsToOne(t *testing.T) {
	cases := map[int]int{
		0:  1,
		-1: 1,
		1:  1,
		2:  2,
		7:  7,
	}
	for input, want := range cases {
		input, want := input, want
		t.Run(strconv.Itoa(input), func(t *testing.T) {
			t.Parallel()
			got := LearnLock{MinimumSignatures: input}.EffectiveMinimumSignatures()
			if got != want {
				t.Fatalf("EffectiveMinimumSignatures(%d) = %d, want %d", input, got, want)
			}
		})
	}
}

func TestValidate_LearnLockDisabledIgnoresOtherFields(t *testing.T) {
	// When Enabled is false, no other field is required. This is important
	// for the v2.3 → v2.4 upgrade path: an existing config without
	// learn_lock.* fields must still validate cleanly.
	cfg := Defaults()
	cfg.LearnLock = LearnLock{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled lock with empty fields should validate: %v", err)
	}
}

func TestValidate_LearnLockEnabledRequiresEveryField(t *testing.T) {
	t.Parallel()
	const validFP = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		mut  func(*LearnLock)
		want string
	}{
		{
			name: "missing store_dir",
			mut:  func(l *LearnLock) { l.StoreDir = "" },
			want: "learn_lock.store_dir required",
		},
		{
			name: "relative store_dir rejected",
			mut:  func(l *LearnLock) { l.StoreDir = "relative/path" },
			want: "absolute path",
		},
		{
			name: "missing roster_path",
			mut:  func(l *LearnLock) { l.RosterPath = "" },
			want: "learn_lock.roster_path required",
		},
		{
			name: "relative roster_path rejected",
			mut:  func(l *LearnLock) { l.RosterPath = "etc/roster.json" },
			want: "roster_path must be an absolute path",
		},
		{
			name: "missing environment id",
			mut:  func(l *LearnLock) { l.Environment.ID = "" },
			want: "learn_lock.environment.id required",
		},
		{
			name: "missing pinned root fingerprint",
			mut:  func(l *LearnLock) { l.PinnedRootFingerprint = "" },
			want: "pinned_root_fingerprint required",
		},
		{
			name: "wrong-length fingerprint",
			mut:  func(l *LearnLock) { l.PinnedRootFingerprint = "sha256:abc" },
			want: "sha256:<64 lowercase hex>",
		},
		{
			name: "missing fingerprint prefix",
			mut: func(l *LearnLock) {
				l.PinnedRootFingerprint = strings.TrimPrefix(validFP, "sha256:")
			},
			want: "sha256:<64 lowercase hex>",
		},
		{
			name: "uppercase fingerprint rejected",
			mut: func(l *LearnLock) {
				l.PinnedRootFingerprint = strings.ToUpper(validFP)
			},
			want: "sha256:<64 lowercase hex>",
		},
		{
			name: "non-hex fingerprint rejected",
			mut: func(l *LearnLock) {
				// Correct prefix/length but contains 'g'.
				l.PinnedRootFingerprint = "sha256:g" + strings.TrimPrefix(validFP, "sha256:")[1:]
			},
			want: "sha256:<64 lowercase hex>",
		},
		{
			name: "unknown mode rejected",
			mut:  func(l *LearnLock) { l.Mode = "preview" },
			want: "live/shadow/capture",
		},
		{
			name: "negative minimum_signatures rejected",
			mut:  func(l *LearnLock) { l.MinimumSignatures = -1 },
			want: "minimum_signatures must be >= 0",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.LearnLock = LearnLock{
				Enabled:               true,
				Mode:                  LockModeShadow,
				StoreDir:              "/var/lib/pipelock/contracts",
				RosterPath:            "/etc/pipelock/roster.json",
				Environment:           LearnLockEnvironment{ID: "production", Tenant: "acme", DeploymentID: "prod-us-1"},
				PinnedRootFingerprint: validFP,
				MinimumSignatures:     1,
			}
			tc.mut(&cfg.LearnLock)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: error %q does not contain %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestValidate_LearnLockEnabledHappyPath(t *testing.T) {
	cfg := Defaults()
	cfg.LearnLock = LearnLock{
		Enabled:               true,
		Mode:                  LockModeLive,
		StoreDir:              "/var/lib/pipelock/contracts",
		RosterPath:            "/etc/pipelock/roster.json",
		Environment:           LearnLockEnvironment{ID: "production", Tenant: "acme", DeploymentID: "prod-us-1"},
		PinnedRootFingerprint: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		MinimumSignatures:     2,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("happy-path lock should validate: %v", err)
	}
}

func TestValidate_LearnLockEnabledEmptyModeAccepted(t *testing.T) {
	// Empty Mode is accepted at validation time and resolves to "shadow"
	// at runtime via EffectiveMode. This avoids forcing every operator
	// who wants shadow-default to type "shadow" explicitly.
	cfg := Defaults()
	cfg.LearnLock = LearnLock{
		Enabled:               true,
		Mode:                  "",
		StoreDir:              "/var/lib/pipelock/contracts",
		RosterPath:            "/etc/pipelock/roster.json",
		Environment:           LearnLockEnvironment{ID: "production", Tenant: "", DeploymentID: ""},
		PinnedRootFingerprint: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty Mode at validation time: %v", err)
	}
	if cfg.LearnLock.EffectiveMode() != LockModeShadow {
		t.Fatalf("empty Mode should resolve to shadow, got %q", cfg.LearnLock.EffectiveMode())
	}
}

func TestLoad_LearnLockEnvironmentNestedSchema(t *testing.T) {
	t.Parallel()
	const validFP = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	base := `
learn_lock:
  enabled: true
  mode: live
  store_dir: /var/lib/pipelock/contracts
  roster_path: /etc/pipelock/roster.json
  pinned_root_fingerprint: ` + validFP + `
  minimum_signatures: 1
`
	cases := []struct {
		name      string
		envYAML   string
		wantID    string
		wantTen   string
		wantDep   string
		wantError string
	}{
		{
			name: "nested full tuple",
			envYAML: `  environment:
    id: production
    tenant: acme
    deployment_id: prod-us-1
`,
			wantID:  "production",
			wantTen: "acme",
			wantDep: "prod-us-1",
		},
		{
			name: "explicit empty tuple scopes",
			envYAML: `  environment:
    id: production
    tenant: ""
    deployment_id: ""
`,
			wantID: "production",
		},
		{
			name: "old string form rejected",
			envYAML: `  environment: production
`,
			wantError: "must be a mapping",
		},
		{
			name: "missing tenant rejected",
			envYAML: `  environment:
    id: production
    deployment_id: prod-us-1
`,
			wantError: "environment.tenant required",
		},
		{
			name: "missing deployment_id rejected",
			envYAML: `  environment:
    id: production
    tenant: acme
`,
			wantError: "environment.deployment_id required",
		},
		{
			name: "null tenant rejected",
			envYAML: `  environment:
    id: production
    tenant: null
    deployment_id: prod-us-1
`,
			wantError: "environment.tenant must be a string",
		},
		{
			name: "unknown nested field rejected",
			envYAML: `  environment:
    id: production
    tenant: acme
    deployment_id: prod-us-1
    cluster: acme
`,
			wantError: "environment.cluster is not supported",
		},
		{
			name: "empty mapping rejected via missing-required-key",
			envYAML: `  environment: {}
`,
			wantError: "environment.id required",
		},
		{
			name: "duplicate key rejected",
			envYAML: `  environment:
    id: production
    id: staging
    tenant: acme
    deployment_id: prod-us-1
`,
			wantError: "environment.id is duplicated",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, []byte(base+tc.envYAML), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := Load(path)
			if tc.wantError != "" {
				if err == nil {
					t.Fatalf("Load() err = nil, want %q", tc.wantError)
				}
				if !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Load() err = %q, want substring %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load(): %v", err)
			}
			got := cfg.LearnLock.Environment
			if got.ID != tc.wantID || got.Tenant != tc.wantTen || got.DeploymentID != tc.wantDep {
				t.Fatalf("environment = %+v, want id=%q tenant=%q deployment_id=%q", got, tc.wantID, tc.wantTen, tc.wantDep)
			}
		})
	}
}
