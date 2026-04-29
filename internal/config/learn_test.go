// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	// learnYAMLOmittedPrivacy is a YAML fragment with learn enabled and a
	// capture dir but with the privacy section omitted entirely. Used to
	// exercise the "field omitted" state of the 6-state default-true
	// contract for Learn.Privacy.PublicAllowlistDefault.
	learnYAMLOmittedPrivacy = "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n"

	learnYAMLNullPrivacy = "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n" +
		"  privacy: ~\n"

	learnYAMLBlankPrivacy = "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n" +
		"  privacy:\n"

	learnYAMLExplicitFalse = "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n" +
		"  privacy:\n" +
		"    public_allowlist_default: false\n"

	learnYAMLExplicitTrue = "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n" +
		"  privacy:\n" +
		"    public_allowlist_default: true\n"

	learnYAMLEnabledOmitted = "mode: balanced\n"

	learnYAMLEnabledNull = "" +
		"mode: balanced\n" +
		"learn: ~\n"

	learnYAMLEnabledBlank = "" +
		"mode: balanced\n" +
		"learn:\n"

	learnYAMLEnabledFalse = "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: false\n"

	learnYAMLEnabledTrue = "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n"

	// learnTestCaptureDir is the canonical capture dir used in YAML
	// fixtures and the assertions that verify them. Extracted as a
	// constant to satisfy goconst across the 6-state matrix tests.
	learnTestCaptureDir = "/tmp/c"
)

// writeLearnConfig writes a YAML doc to a tempfile in t.TempDir() and
// returns the absolute path. Used by the load-path 6-state tests below.
func writeLearnConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// TestDefaults_Learn verifies the Defaults() values for the Learn section.
func TestDefaults_Learn(t *testing.T) {
	cfg := Defaults()
	if cfg.Learn.Enabled {
		t.Errorf("expected Learn.Enabled=false, got true")
	}
	if cfg.Learn.CaptureDir != "" {
		t.Errorf("expected Learn.CaptureDir=\"\", got %q", cfg.Learn.CaptureDir)
	}
	if cfg.Learn.Privacy.SaltSource != "" {
		t.Errorf("expected Learn.Privacy.SaltSource=\"\", got %q", cfg.Learn.Privacy.SaltSource)
	}
	if !cfg.Learn.Privacy.PublicAllowlistDefault {
		t.Errorf("expected Learn.Privacy.PublicAllowlistDefault=true (security default), got false")
	}
}

// TestLearn_PublicAllowlistDefault_SixStates exercises the 6-state default-true
// contract for the security-sensitive Learn.Privacy.PublicAllowlistDefault
// field through the real Load() path. Per CLAUDE.md security invariants:
// "omitted, YAML null/blank, explicit false, explicit true, reload with
// change, reload without change".
func TestLearn_PublicAllowlistDefault_SixStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{"omitted_privacy", learnYAMLOmittedPrivacy, true},
		{"null_privacy", learnYAMLNullPrivacy, true},
		{"blank_privacy", learnYAMLBlankPrivacy, true},
		{"explicit_false", learnYAMLExplicitFalse, false},
		{"explicit_true", learnYAMLExplicitTrue, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeLearnConfig(t, tt.yaml)
			cfg, err := Load(p)
			if err != nil {
				t.Fatalf("Load(%q): %v", tt.name, err)
			}
			if got := cfg.Learn.Privacy.PublicAllowlistDefault; got != tt.want {
				t.Errorf("PublicAllowlistDefault: got=%v want=%v", got, tt.want)
			}
		})
	}

	// Reload-with-change: false → true must propagate on second Load.
	t.Run("reload_with_change", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "pipelock.yaml")
		if err := os.WriteFile(p, []byte(learnYAMLExplicitFalse), 0o600); err != nil {
			t.Fatalf("write initial: %v", err)
		}
		first, err := Load(p)
		if err != nil {
			t.Fatalf("first load: %v", err)
		}
		if first.Learn.Privacy.PublicAllowlistDefault {
			t.Fatal("first load: expected false, got true")
		}
		// Overwrite with explicit true and reload.
		if err := os.WriteFile(p, []byte(learnYAMLExplicitTrue), 0o600); err != nil {
			t.Fatalf("write reload: %v", err)
		}
		second, err := Load(p)
		if err != nil {
			t.Fatalf("second load: %v", err)
		}
		if !second.Learn.Privacy.PublicAllowlistDefault {
			t.Error("second load: expected true after reload, got false")
		}
	})

	// Reload-without-change: idempotent.
	t.Run("reload_without_change", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "pipelock.yaml")
		if err := os.WriteFile(p, []byte(learnYAMLOmittedPrivacy), 0o600); err != nil {
			t.Fatalf("write initial: %v", err)
		}
		first, err := Load(p)
		if err != nil {
			t.Fatalf("first load: %v", err)
		}
		second, err := Load(p)
		if err != nil {
			t.Fatalf("second load: %v", err)
		}
		if first.Learn.Privacy.PublicAllowlistDefault != second.Learn.Privacy.PublicAllowlistDefault {
			t.Errorf("idempotency: first=%v second=%v",
				first.Learn.Privacy.PublicAllowlistDefault,
				second.Learn.Privacy.PublicAllowlistDefault)
		}
		if !first.Learn.Privacy.PublicAllowlistDefault {
			t.Error("expected true on idempotent reload")
		}
	})
}

// TestLearn_Enabled_SixStates exercises the 6-state contract for
// Learn.Enabled. Enabled defaults to false (operator must opt in to
// observation), so this is the inverse of the public_allowlist_default
// matrix above. Capture_dir is supplied only in the explicit_true cases
// because the validator requires it when enabled.
func TestLearn_Enabled_SixStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{"omitted_learn", learnYAMLEnabledOmitted, false},
		{"null_learn", learnYAMLEnabledNull, false},
		{"blank_learn", learnYAMLEnabledBlank, false},
		{"explicit_false", learnYAMLEnabledFalse, false},
		{"explicit_true", learnYAMLEnabledTrue, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeLearnConfig(t, tt.yaml)
			cfg, err := Load(p)
			if err != nil {
				t.Fatalf("Load(%q): %v", tt.name, err)
			}
			if got := cfg.Learn.Enabled; got != tt.want {
				t.Errorf("Learn.Enabled: got=%v want=%v", got, tt.want)
			}
		})
	}

	// Reload-with-change: false → true.
	t.Run("reload_with_change", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "pipelock.yaml")
		if err := os.WriteFile(p, []byte(learnYAMLEnabledFalse), 0o600); err != nil {
			t.Fatalf("write initial: %v", err)
		}
		first, err := Load(p)
		if err != nil {
			t.Fatalf("first load: %v", err)
		}
		if first.Learn.Enabled {
			t.Fatal("first load: expected Enabled=false")
		}
		if err := os.WriteFile(p, []byte(learnYAMLEnabledTrue), 0o600); err != nil {
			t.Fatalf("write reload: %v", err)
		}
		second, err := Load(p)
		if err != nil {
			t.Fatalf("second load: %v", err)
		}
		if !second.Learn.Enabled {
			t.Error("second load: expected Enabled=true")
		}
		if second.Learn.CaptureDir != learnTestCaptureDir {
			t.Errorf("second load: CaptureDir=%q, want %q", second.Learn.CaptureDir, learnTestCaptureDir)
		}
	})

	// Reload-without-change: idempotent.
	t.Run("reload_without_change", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "pipelock.yaml")
		if err := os.WriteFile(p, []byte(learnYAMLEnabledTrue), 0o600); err != nil {
			t.Fatalf("write initial: %v", err)
		}
		first, err := Load(p)
		if err != nil {
			t.Fatalf("first load: %v", err)
		}
		second, err := Load(p)
		if err != nil {
			t.Fatalf("second load: %v", err)
		}
		if first.Learn.Enabled != second.Learn.Enabled {
			t.Errorf("idempotency: first=%v second=%v",
				first.Learn.Enabled, second.Learn.Enabled)
		}
		if !first.Learn.Enabled {
			t.Error("expected Enabled=true on idempotent reload")
		}
	})
}

// TestValidate_LearnEnabledRequiresCaptureDir confirms that enabling the
// observation pipeline without a capture directory is rejected at
// config-load. This is the only top-level Learn cross-field check; the
// rest of the surface is privacy-related and validated separately.
func TestValidate_LearnEnabledRequiresCaptureDir(t *testing.T) {
	cfg := Defaults()
	cfg.Learn.Enabled = true
	cfg.Learn.CaptureDir = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when learn.enabled=true and capture_dir is empty")
	}
	if !strings.Contains(err.Error(), "learn.capture_dir required") {
		t.Errorf("error %q does not mention learn.capture_dir", err)
	}
}

// TestValidate_LearnPropagatesSaltSourceError walks the full Validate()
// pipeline with an invalid salt_source so the validateLearn → return-err
// branch is exercised at the integration level (not just through the
// validateLearnSaltSource helper). Covers the second return path inside
// validateLearn that the unit-level salt-source tests skip.
func TestValidate_LearnPropagatesSaltSourceError(t *testing.T) {
	cfg := Defaults()
	cfg.Learn.Privacy.SaltSource = "file:relative/path"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error from validateLearn through full Validate() chain")
	}
	if !strings.Contains(err.Error(), "salt_source") {
		t.Errorf("error %q does not propagate salt_source detail", err)
	}
}

// TestValidate_LearnSaltSource exercises every accepted and rejected shape
// of the salt_source resolver. File-based shapes use a fresh tempfile
// created with 0o600; the test mutates ownership/perms in subtests that
// need a rejection signal so we never depend on system files like
// /etc/passwd whose modes vary across distros.
func TestValidate_LearnSaltSource(t *testing.T) {
	t.Parallel()

	t.Run("empty_accepted", func(t *testing.T) {
		if err := validateLearnSaltSource(""); err != nil {
			t.Errorf("empty: unexpected error %v", err)
		}
	})

	t.Run("env_var_accepted", func(t *testing.T) {
		if err := validateLearnSaltSource("${PIPELOCK_REDACT_SALT}"); err != nil {
			t.Errorf("env var: unexpected error %v", err)
		}
	})

	t.Run("literal_accepted", func(t *testing.T) {
		if err := validateLearnSaltSource("literal-salt-bytes"); err != nil {
			t.Errorf("literal: unexpected error %v", err)
		}
	})

	t.Run("file_relative_rejected", func(t *testing.T) {
		err := validateLearnSaltSource("file:relative/path")
		if err == nil {
			t.Fatal("expected error for relative file path")
		}
		if !strings.Contains(err.Error(), "absolute") {
			t.Errorf("error %q does not mention absolute path", err)
		}
	})

	t.Run("file_traversal_rejected", func(t *testing.T) {
		err := validateLearnSaltSource("file:/path/with/.././traversal")
		if err == nil {
			t.Fatal("expected error for traversal path")
		}
		if !strings.Contains(err.Error(), "canonical") {
			t.Errorf("error %q does not mention canonical form", err)
		}
	})

	t.Run("file_nonexistent_rejected", func(t *testing.T) {
		// Pick a path inside the tempdir that we never create.
		dir := t.TempDir()
		nonexistent := filepath.Join(dir, "nope.salt")
		err := validateLearnSaltSource("file:" + nonexistent)
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error %q does not mention nonexistent file", err)
		}
	})

	t.Run("file_world_readable_rejected", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "salt.txt")
		if err := os.WriteFile(p, []byte("salty"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		// Loosen perms to a deliberately unsafe mode so the validator
		// must reject it. Using a constant keeps gosec G302 quiet —
		// the loose mode is the test fixture, not production behavior.
		const looseMode os.FileMode = 0o644
		if err := os.Chmod(p, looseMode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		err := validateLearnSaltSource("file:" + p)
		if err == nil {
			t.Fatal("expected error for 0o644 salt file")
		}
		if !strings.Contains(err.Error(), "0o600 or stricter") {
			t.Errorf("error %q does not mention required mode", err)
		}
	})

	t.Run("file_stat_non_enoent_rejected", func(t *testing.T) {
		// Routing through a regular file (/etc/passwd is universally
		// present and a regular file) returns ENOTDIR rather than
		// ErrNotExist, exercising the generic stat-error branch.
		err := validateLearnSaltSource("file:/etc/passwd/notreal")
		if err == nil {
			t.Fatal("expected stat error for ENOTDIR-bearing path")
		}
		if strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error %q misclassified ENOTDIR as ENOENT", err)
		}
		if !strings.Contains(err.Error(), "stat ") {
			t.Errorf("error %q does not surface generic stat failure", err)
		}
	})

	t.Run("file_strict_perms_accepted", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "salt.txt")
		if err := os.WriteFile(p, []byte("salty"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := validateLearnSaltSource("file:" + p); err != nil {
			t.Errorf("0o600 file: unexpected error %v", err)
		}
	})

	t.Run("file_directory_rejected", func(t *testing.T) {
		dir := t.TempDir()
		// Tighten the dir perms so the perms check would pass — we want
		// to be sure the IsRegular() check is what rejects the path, not
		// the mode bits. 0o700 is repo-standard for owner-only dirs.
		const ownerOnlyDir os.FileMode = 0o700
		if err := os.Chmod(dir, ownerOnlyDir); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		err := validateLearnSaltSource("file:" + dir)
		if err == nil {
			t.Fatal("expected error for directory path")
		}
		if !strings.Contains(err.Error(), "regular file") {
			t.Errorf("error %q does not mention regular file", err)
		}
	})

	t.Run("file_symlink_rejected", func(t *testing.T) {
		// A symlink at the configured path must reject at config-load even
		// when the symlink target is a perfectly valid 0o600 regular file.
		// This is the defense-in-depth half of the TOCTOU pair; the runtime
		// resolver has its own O_NOFOLLOW open + fd-stat that closes the
		// stat-then-read race on the same condition.
		dir := t.TempDir()
		target := filepath.Join(dir, "real-salt.txt")
		if err := os.WriteFile(target, []byte("salty"), 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		link := filepath.Join(dir, "link-salt.txt")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		err := validateLearnSaltSource("file:" + link)
		if err == nil {
			t.Fatal("expected error for symlink path")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error %q does not mention symlink", err)
		}
	})
}

// TestNormalizeLearn_TrimsWhitespace confirms the normalizer strips
// leading/trailing whitespace from CaptureDir and SaltSource so config
// hashing and reload-no-op detection don't drift on accidental spaces.
func TestNormalizeLearn_TrimsWhitespace(t *testing.T) {
	cases := []struct {
		name     string
		inDir    string
		inSalt   string
		wantDir  string
		wantSalt string
	}{
		{"untrimmed", "  /tmp/c  \n", "  ${VAR}  ", "/tmp/c", "${VAR}"},
		{"already_trimmed", "/tmp/c", "${VAR}", "/tmp/c", "${VAR}"},
		{"empty", "", "", "", ""},
		{"only_whitespace", "   \t\n", "\t  ", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &Learn{
				CaptureDir: tc.inDir,
				Privacy:    LearnPrivacy{SaltSource: tc.inSalt},
			}
			normalizeLearn(l)
			if l.CaptureDir != tc.wantDir {
				t.Errorf("CaptureDir=%q want %q", l.CaptureDir, tc.wantDir)
			}
			if l.Privacy.SaltSource != tc.wantSalt {
				t.Errorf("SaltSource=%q want %q", l.Privacy.SaltSource, tc.wantSalt)
			}
		})
	}
}

// TestNormalizeLearn_AppliedByApplyDefaults confirms ApplyDefaults runs
// the normalizer (so Load picks it up automatically — the round-trip
// path through Load is exercised by TestLoad_LearnNormalizes below).
func TestNormalizeLearn_AppliedByApplyDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.Learn.CaptureDir = "  /tmp/c  "
	cfg.Learn.Privacy.SaltSource = "  ${VAR}  "
	cfg.ApplyDefaults()
	if cfg.Learn.CaptureDir != "/tmp/c" {
		t.Errorf("CaptureDir=%q want /tmp/c", cfg.Learn.CaptureDir)
	}
	if cfg.Learn.Privacy.SaltSource != "${VAR}" {
		t.Errorf("SaltSource=%q want ${VAR}", cfg.Learn.Privacy.SaltSource)
	}
}

// TestLoad_LearnNormalizes confirms whitespace gets stripped during the
// real Load() path, including for fields written into the YAML with
// trailing spaces or surrounding indentation.
func TestLoad_LearnNormalizes(t *testing.T) {
	body := "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: \"   /tmp/c   \"\n" +
		"  privacy:\n" +
		"    salt_source: \"   ${SALT}   \"\n"
	p := writeLearnConfig(t, body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Learn.CaptureDir != "/tmp/c" {
		t.Errorf("CaptureDir=%q want /tmp/c", cfg.Learn.CaptureDir)
	}
	if cfg.Learn.Privacy.SaltSource != "${SALT}" {
		t.Errorf("SaltSource=%q want ${SALT}", cfg.Learn.Privacy.SaltSource)
	}
}

// TestLearn_YAMLRoundTrip confirms a Config carrying a Learn block
// marshals and unmarshals without losing fields. Reload's atomic.Pointer
// swap relies on the struct round-tripping cleanly.
func TestLearn_YAMLRoundTrip(t *testing.T) {
	cfg := Defaults()
	cfg.Learn.Enabled = true
	cfg.Learn.CaptureDir = "/var/lib/pipelock/learn"
	cfg.Learn.Privacy.SaltSource = "${PIPELOCK_REDACT_SALT}"
	cfg.Learn.Privacy.PublicAllowlistDefault = false
	cfg.Learn.Inference.Floors.MinSessions = 7
	cfg.Learn.Inference.Floors.MinEvents = 30
	cfg.Learn.Inference.Floors.MinWindows = 4

	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Config
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Learn.Enabled {
		t.Errorf("Enabled lost on round-trip")
	}
	if got.Learn.CaptureDir != "/var/lib/pipelock/learn" {
		t.Errorf("CaptureDir=%q lost on round-trip", got.Learn.CaptureDir)
	}
	if got.Learn.Privacy.SaltSource != "${PIPELOCK_REDACT_SALT}" {
		t.Errorf("SaltSource=%q lost on round-trip", got.Learn.Privacy.SaltSource)
	}
	if got.Learn.Privacy.PublicAllowlistDefault {
		t.Errorf("PublicAllowlistDefault flipped to true on round-trip")
	}
	if got.Learn.Inference.Floors.MinSessions != 7 {
		t.Errorf("Inference.Floors.MinSessions=%d lost on round-trip", got.Learn.Inference.Floors.MinSessions)
	}
	if got.Learn.Inference.Floors.MinEvents != 30 {
		t.Errorf("Inference.Floors.MinEvents=%d lost on round-trip", got.Learn.Inference.Floors.MinEvents)
	}
	if got.Learn.Inference.Floors.MinWindows != 4 {
		t.Errorf("Inference.Floors.MinWindows=%d lost on round-trip", got.Learn.Inference.Floors.MinWindows)
	}
}

// TestValidateLearnInferenceFloors_NegativeRejected exercises one row per
// field, each row setting exactly one field to -1. The error message must
// surface the exact YAML path the operator sees in pipelock.yaml plus the
// numeric value, so the operator can grep the file for the failing knob
// without translating between Go field names and YAML keys.
func TestValidateLearnInferenceFloors_NegativeRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		floors    LearnInferenceFloors
		wantPath  string
		wantValue string
	}{
		{
			name:      "min_sessions_negative",
			floors:    LearnInferenceFloors{MinSessions: -1},
			wantPath:  "learn.inference.floors.min_sessions",
			wantValue: "-1",
		},
		{
			name:      "min_events_negative",
			floors:    LearnInferenceFloors{MinEvents: -7},
			wantPath:  "learn.inference.floors.min_events",
			wantValue: "-7",
		},
		{
			name:      "min_windows_negative",
			floors:    LearnInferenceFloors{MinWindows: -42},
			wantPath:  "learn.inference.floors.min_windows",
			wantValue: "-42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateLearnInferenceFloors(tt.floors)
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantPath) {
				t.Errorf("error %q missing YAML path %q", err, tt.wantPath)
			}
			if !strings.Contains(err.Error(), tt.wantValue) {
				t.Errorf("error %q missing numeric value %q", err, tt.wantValue)
			}
			if !strings.Contains(err.Error(), "non-negative") {
				t.Errorf("error %q missing constraint phrasing", err)
			}
		})
	}
}

// TestValidateLearnInferenceFloors_ZeroOrPositiveAccepted confirms the
// validator admits the legal shapes: all-zero (defaults flow through
// inference.Floors.Resolved at runtime), all explicit defaults, all
// positive non-default, and mixed values. None of these should error.
func TestValidateLearnInferenceFloors_ZeroOrPositiveAccepted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		floors LearnInferenceFloors
	}{
		{"all_zero", LearnInferenceFloors{}},
		{"all_default", LearnInferenceFloors{MinSessions: 5, MinEvents: 20, MinWindows: 3}},
		{"all_positive", LearnInferenceFloors{MinSessions: 100, MinEvents: 500, MinWindows: 24}},
		{"mixed_zero_positive", LearnInferenceFloors{MinSessions: 0, MinEvents: 50, MinWindows: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateLearnInferenceFloors(tt.floors); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateLearnInferenceFloors_FieldOrder pins the sequential
// validation contract: when multiple fields are negative, the validator
// returns the first error in declaration order (sessions, events, windows).
// This matters because operators read the first error in their logs and
// fix it before re-running — non-deterministic ordering would force
// multiple round-trips.
func TestValidateLearnInferenceFloors_FieldOrder(t *testing.T) {
	t.Parallel()

	floors := LearnInferenceFloors{
		MinSessions: -1,
		MinEvents:   -2,
		MinWindows:  -3,
	}
	err := validateLearnInferenceFloors(floors)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "min_sessions") {
		t.Errorf("expected first error to mention min_sessions, got: %v", err)
	}
	if strings.Contains(err.Error(), "min_events") || strings.Contains(err.Error(), "min_windows") {
		t.Errorf("first error must report only min_sessions, got: %v", err)
	}
}

// TestValidate_LearnPropagatesInferenceFloorsError walks the full Validate()
// pipeline with a negative floor so the validateLearn → return-err branch
// is exercised end-to-end (mirroring the salt_source propagation test
// already in this file).
func TestValidate_LearnPropagatesInferenceFloorsError(t *testing.T) {
	cfg := Defaults()
	cfg.Learn.Inference.Floors.MinEvents = -1
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error from validateLearn through full Validate() chain")
	}
	if !strings.Contains(err.Error(), "learn.inference.floors.min_events") {
		t.Errorf("error %q does not propagate inference floors detail", err)
	}
}

// TestLoad_LearnInferenceFloors confirms YAML decoding routes the floors
// into the right struct. The Load() round-trip is the layer most likely
// to drift if the yaml tags get mistyped, so we exercise it explicitly.
func TestLoad_LearnInferenceFloors(t *testing.T) {
	body := "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n" +
		"  inference:\n" +
		"    floors:\n" +
		"      min_sessions: 11\n" +
		"      min_events: 33\n" +
		"      min_windows: 5\n"
	p := writeLearnConfig(t, body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Learn.Inference.Floors.MinSessions != 11 {
		t.Errorf("MinSessions=%d, want 11", cfg.Learn.Inference.Floors.MinSessions)
	}
	if cfg.Learn.Inference.Floors.MinEvents != 33 {
		t.Errorf("MinEvents=%d, want 33", cfg.Learn.Inference.Floors.MinEvents)
	}
	if cfg.Learn.Inference.Floors.MinWindows != 5 {
		t.Errorf("MinWindows=%d, want 5", cfg.Learn.Inference.Floors.MinWindows)
	}
}

// TestLoad_LearnInferenceFloors_NegativeRejected confirms a YAML doc with
// a negative floor fails Load() — the YAML decode must reach Validate()
// and the validator must reject it with the operator-facing path.
func TestLoad_LearnInferenceFloors_NegativeRejected(t *testing.T) {
	body := "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n" +
		"  inference:\n" +
		"    floors:\n" +
		"      min_sessions: -1\n"
	p := writeLearnConfig(t, body)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected Load error for negative floor")
	}
	if !strings.Contains(err.Error(), "learn.inference.floors.min_sessions") {
		t.Errorf("error %q missing operator-facing YAML path", err)
	}
}
