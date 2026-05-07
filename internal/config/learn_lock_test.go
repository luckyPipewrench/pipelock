// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
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
			name: "missing environment",
			mut:  func(l *LearnLock) { l.Environment = "" },
			want: "learn_lock.environment required",
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
				Environment:           "production",
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
		Environment:           "production",
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
		Environment:           "production",
		PinnedRootFingerprint: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty Mode at validation time: %v", err)
	}
	if cfg.LearnLock.EffectiveMode() != LockModeShadow {
		t.Fatalf("empty Mode should resolve to shadow, got %q", cfg.LearnLock.EffectiveMode())
	}
}
