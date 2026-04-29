// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// reservedExtraInternal is the operator-supplied reserved-segment
// extension used in normalization round-trip fixtures. Extracted as a
// const to satisfy goconst across the round-trip and load tests.
const reservedExtraInternal = "internal"

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
	cfg.Learn.Inference.Normalization.Algorithm = LearnNormalizationAlgorithmV1
	cfg.Learn.Inference.Normalization.MinEvents = 12
	cfg.Learn.Inference.Normalization.MinDistinctValues = 6
	cfg.Learn.Inference.Normalization.EntropyThresholdBits = 3.5
	cfg.Learn.Inference.Normalization.ReservedSegmentsExtra = []string{"corp", reservedExtraInternal}
	cfg.Learn.Inference.Normalization.CardinalityCapPerHost = 2000
	cfg.Learn.Inference.Normalization.TailPromotionBlockPct = 7.5

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
	if got.Learn.Inference.Normalization.Algorithm != LearnNormalizationAlgorithmV1 {
		t.Errorf("Normalization.Algorithm=%q lost on round-trip", got.Learn.Inference.Normalization.Algorithm)
	}
	if got.Learn.Inference.Normalization.MinEvents != 12 {
		t.Errorf("Normalization.MinEvents=%d lost on round-trip", got.Learn.Inference.Normalization.MinEvents)
	}
	if got.Learn.Inference.Normalization.MinDistinctValues != 6 {
		t.Errorf("Normalization.MinDistinctValues=%d lost on round-trip", got.Learn.Inference.Normalization.MinDistinctValues)
	}
	if got.Learn.Inference.Normalization.EntropyThresholdBits != 3.5 {
		t.Errorf("Normalization.EntropyThresholdBits=%v lost on round-trip", got.Learn.Inference.Normalization.EntropyThresholdBits)
	}
	if len(got.Learn.Inference.Normalization.ReservedSegmentsExtra) != 2 ||
		got.Learn.Inference.Normalization.ReservedSegmentsExtra[0] != "corp" ||
		got.Learn.Inference.Normalization.ReservedSegmentsExtra[1] != reservedExtraInternal {
		t.Errorf("Normalization.ReservedSegmentsExtra=%v lost on round-trip", got.Learn.Inference.Normalization.ReservedSegmentsExtra)
	}
	if got.Learn.Inference.Normalization.CardinalityCapPerHost != 2000 {
		t.Errorf("Normalization.CardinalityCapPerHost=%d lost on round-trip", got.Learn.Inference.Normalization.CardinalityCapPerHost)
	}
	if got.Learn.Inference.Normalization.TailPromotionBlockPct != 7.5 {
		t.Errorf("Normalization.TailPromotionBlockPct=%v lost on round-trip", got.Learn.Inference.Normalization.TailPromotionBlockPct)
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

// TestValidateLearnInferenceNormalization_Algorithm pins the algorithm
// gate. Empty is accepted (defaults flow through Resolved at runtime),
// the canonical algorithm value is accepted, and any other value
// rejects with the operator-facing YAML path. A future algorithm bump
// must extend this test, never weaken it.
func TestValidateLearnInferenceNormalization_Algorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		algorithm  string
		wantErr    bool
		wantInPath string
	}{
		{"empty_accepted", "", false, ""},
		{"canonical_v1_accepted", LearnNormalizationAlgorithmV1, false, ""},
		{"unknown_rejected", "frequency_weighted_entropy_v2", true, "learn.inference.normalization.algorithm"},
		{"misspelled_rejected", "frequency-weighted-entropy-v1", true, "learn.inference.normalization.algorithm"},
		{"random_string_rejected", "naive", true, "learn.inference.normalization.algorithm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n := LearnInferenceNormalization{Algorithm: tt.algorithm}
			err := validateLearnInferenceNormalization(n)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for algorithm=%q", tt.algorithm)
				}
				if !strings.Contains(err.Error(), tt.wantInPath) {
					t.Errorf("error %q missing YAML path %q", err, tt.wantInPath)
				}
			} else if err != nil {
				t.Errorf("unexpected error for algorithm=%q: %v", tt.algorithm, err)
			}
		})
	}
}

// TestValidateLearnInferenceNormalization_NumericFields_RejectNegative
// exercises one row per numeric knob, each row setting exactly one field
// to -1. The error message must surface the YAML path the operator sees
// in pipelock.yaml plus the numeric value.
func TestValidateLearnInferenceNormalization_NumericFields_RejectNegative(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mut       func(*LearnInferenceNormalization)
		wantPath  string
		wantValue string
	}{
		{
			name:      "min_events_negative",
			mut:       func(n *LearnInferenceNormalization) { n.MinEvents = -1 },
			wantPath:  "learn.inference.normalization.min_events",
			wantValue: "-1",
		},
		{
			name:      "min_distinct_values_negative",
			mut:       func(n *LearnInferenceNormalization) { n.MinDistinctValues = -1 },
			wantPath:  "learn.inference.normalization.min_distinct_values",
			wantValue: "-1",
		},
		{
			name:      "entropy_threshold_bits_negative",
			mut:       func(n *LearnInferenceNormalization) { n.EntropyThresholdBits = -1 },
			wantPath:  "learn.inference.normalization.entropy_threshold_bits",
			wantValue: "-1",
		},
		{
			name:      "cardinality_cap_per_host_negative",
			mut:       func(n *LearnInferenceNormalization) { n.CardinalityCapPerHost = -1 },
			wantPath:  "learn.inference.normalization.cardinality_cap_per_host",
			wantValue: "-1",
		},
		{
			name:      "tail_promotion_block_pct_negative",
			mut:       func(n *LearnInferenceNormalization) { n.TailPromotionBlockPct = -1 },
			wantPath:  "learn.inference.normalization.tail_promotion_block_pct",
			wantValue: "-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var n LearnInferenceNormalization
			tt.mut(&n)
			err := validateLearnInferenceNormalization(n)
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

// TestValidateLearnInferenceNormalization_EntropyThresholdBitsBand pins
// the [0, 8.0] band for entropy_threshold_bits. Boundary cases at 0 and
// 8.0 accept; anything outside rejects.
func TestValidateLearnInferenceNormalization_EntropyThresholdBitsBand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		bits    float64
		wantErr bool
	}{
		{"at_zero_accepted", 0, false},
		{"just_above_zero_accepted", 0.001, false},
		{"at_eight_accepted", 8.0, false},
		{"just_above_eight_rejected", 8.0001, true},
		{"just_below_zero_rejected", -0.001, true},
		{"way_too_high_rejected", 1000.0, true},
		{"way_too_low_rejected", -100.0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n := LearnInferenceNormalization{EntropyThresholdBits: tt.bits}
			err := validateLearnInferenceNormalization(n)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for bits=%v", tt.bits)
				}
				if !strings.Contains(err.Error(), "learn.inference.normalization.entropy_threshold_bits") {
					t.Errorf("error %q missing YAML path", err)
				}
			} else if err != nil {
				t.Errorf("unexpected error for bits=%v: %v", tt.bits, err)
			}
		})
	}
}

// TestValidateLearnInferenceNormalization_TailPctBand pins the [0, 100]
// band for tail_promotion_block_pct. 0 and 100 both accept (defaults
// land at 5.0, but operators may dial to either extreme).
func TestValidateLearnInferenceNormalization_TailPctBand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pct     float64
		wantErr bool
	}{
		{"at_zero_accepted", 0, false},
		{"at_hundred_accepted", 100.0, false},
		{"just_above_hundred_rejected", 100.0001, true},
		{"just_below_zero_rejected", -0.001, true},
		{"middle_default_accepted", 5.0, false},
		{"way_too_high_rejected", 1000.0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n := LearnInferenceNormalization{TailPromotionBlockPct: tt.pct}
			err := validateLearnInferenceNormalization(n)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for pct=%v", tt.pct)
				}
				if !strings.Contains(err.Error(), "learn.inference.normalization.tail_promotion_block_pct") {
					t.Errorf("error %q missing YAML path", err)
				}
			} else if err != nil {
				t.Errorf("unexpected error for pct=%v: %v", tt.pct, err)
			}
		})
	}
}

// TestValidateLearnInferenceNormalization_ReservedExtras_RejectsEmpty
// confirms an empty string anywhere in reserved_segments_extra trips
// the validator with the index in the error so the operator can find
// the offending entry without counting list items by hand.
func TestValidateLearnInferenceNormalization_ReservedExtras_RejectsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		extras    []string
		wantErr   bool
		wantIndex string
	}{
		{"all_valid_accepted", []string{"valid", "also-valid", "third"}, false, ""},
		{"empty_at_zero_rejected", []string{"", "valid"}, true, "[0]"},
		{"empty_at_one_rejected", []string{"valid", "", "also-valid"}, true, "[1]"},
		{"empty_at_two_rejected", []string{"valid", "also-valid", ""}, true, "[2]"},
		{"nil_accepted", nil, false, ""},
		{"empty_slice_accepted", []string{}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n := LearnInferenceNormalization{ReservedSegmentsExtra: tt.extras}
			err := validateLearnInferenceNormalization(n)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for extras=%v", tt.extras)
				}
				if !strings.Contains(err.Error(), "learn.inference.normalization.reserved_segments_extra") {
					t.Errorf("error %q missing YAML path", err)
				}
				if !strings.Contains(err.Error(), tt.wantIndex) {
					t.Errorf("error %q missing index %q", err, tt.wantIndex)
				}
			} else if err != nil {
				t.Errorf("unexpected error for extras=%v: %v", tt.extras, err)
			}
		})
	}
}

// TestValidateLearnInferenceNormalization_AllZeroAccepted confirms a
// fully-zero struct (operator omitted the entire normalization block)
// validates clean. Zero is the "use default" sentinel: the runtime
// applies normalize.DefaultDecideConfig / DefaultCapConfig at use time
// via Resolved().
func TestValidateLearnInferenceNormalization_AllZeroAccepted(t *testing.T) {
	t.Parallel()

	if err := validateLearnInferenceNormalization(LearnInferenceNormalization{}); err != nil {
		t.Errorf("unexpected error on zero-value struct: %v", err)
	}
}

// TestValidateLearnInferenceNormalization_FieldOrder pins the sequential
// validation contract: when multiple fields are bad, the validator
// returns the first error in declaration order. Operators read the
// first error in their logs and fix it before re-running — non-
// deterministic ordering would force multiple round-trips. Algorithm
// is checked first; numeric fields follow in struct declaration order.
func TestValidateLearnInferenceNormalization_FieldOrder(t *testing.T) {
	t.Parallel()

	t.Run("algorithm_before_numeric", func(t *testing.T) {
		t.Parallel()
		// Bad algorithm + multiple bad numerics: algorithm error wins.
		n := LearnInferenceNormalization{
			Algorithm:             "bogus",
			MinEvents:             -1,
			MinDistinctValues:     -1,
			EntropyThresholdBits:  -1,
			CardinalityCapPerHost: -1,
			TailPromotionBlockPct: -1,
		}
		err := validateLearnInferenceNormalization(n)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "algorithm") {
			t.Errorf("expected algorithm error first, got: %v", err)
		}
	})

	t.Run("min_events_before_other_numerics", func(t *testing.T) {
		t.Parallel()
		// Algorithm clean: first bad numeric (min_events) wins.
		n := LearnInferenceNormalization{
			MinEvents:             -1,
			MinDistinctValues:     -2,
			EntropyThresholdBits:  -3,
			CardinalityCapPerHost: -4,
			TailPromotionBlockPct: -5,
		}
		err := validateLearnInferenceNormalization(n)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "min_events") {
			t.Errorf("expected min_events error first, got: %v", err)
		}
		if strings.Contains(err.Error(), "min_distinct_values") ||
			strings.Contains(err.Error(), "entropy_threshold_bits") ||
			strings.Contains(err.Error(), "cardinality_cap_per_host") ||
			strings.Contains(err.Error(), "tail_promotion_block_pct") {
			t.Errorf("first error must report only min_events, got: %v", err)
		}
	})
}

// TestValidateLearn_PropagatesNormalizationError walks the full
// Validate() pipeline with a bad Normalization sub-block so the
// validateLearn → return-err branch is exercised end-to-end (mirrors
// the salt-source and floor propagation tests already in this file).
func TestValidateLearn_PropagatesNormalizationError(t *testing.T) {
	cfg := Defaults()
	cfg.Learn.Inference.Normalization.CardinalityCapPerHost = -1
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error from validateLearn through full Validate() chain")
	}
	if !strings.Contains(err.Error(), "learn.inference.normalization.cardinality_cap_per_host") {
		t.Errorf("error %q does not propagate normalization detail", err)
	}
}

// TestLoad_LearnInferenceNormalization_RoundTrip confirms YAML decoding
// routes the normalization knobs into the right struct. The Load()
// round-trip is the layer most likely to drift if the yaml tags get
// mistyped, so we exercise it explicitly through the public API.
func TestLoad_LearnInferenceNormalization_RoundTrip(t *testing.T) {
	body := "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n" +
		"  inference:\n" +
		"    normalization:\n" +
		"      algorithm: frequency_weighted_entropy_v1\n" +
		"      min_events: 25\n" +
		"      min_distinct_values: 8\n" +
		"      entropy_threshold_bits: 4.2\n" +
		"      reserved_segments_extra:\n" +
		"        - corp\n" +
		"        - tenant\n" +
		"      cardinality_cap_per_host: 1500\n" +
		"      tail_promotion_block_pct: 8.0\n"
	p := writeLearnConfig(t, body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	n := cfg.Learn.Inference.Normalization
	if n.Algorithm != LearnNormalizationAlgorithmV1 {
		t.Errorf("Algorithm=%q lost on Load", n.Algorithm)
	}
	if n.MinEvents != 25 {
		t.Errorf("MinEvents=%d, want 25", n.MinEvents)
	}
	if n.MinDistinctValues != 8 {
		t.Errorf("MinDistinctValues=%d, want 8", n.MinDistinctValues)
	}
	if n.EntropyThresholdBits != 4.2 {
		t.Errorf("EntropyThresholdBits=%v, want 4.2", n.EntropyThresholdBits)
	}
	if len(n.ReservedSegmentsExtra) != 2 ||
		n.ReservedSegmentsExtra[0] != "corp" ||
		n.ReservedSegmentsExtra[1] != "tenant" {
		t.Errorf("ReservedSegmentsExtra=%v lost on Load", n.ReservedSegmentsExtra)
	}
	if n.CardinalityCapPerHost != 1500 {
		t.Errorf("CardinalityCapPerHost=%d, want 1500", n.CardinalityCapPerHost)
	}
	if n.TailPromotionBlockPct != 8.0 {
		t.Errorf("TailPromotionBlockPct=%v, want 8.0", n.TailPromotionBlockPct)
	}
}

// TestLoad_LearnInferenceNormalization_Negative_Rejected confirms a YAML
// doc with a negative normalization knob fails Load() — the YAML
// decode must reach Validate() and the validator must reject it with
// the operator-facing YAML path so a misconfigured deployment cannot
// silently widen the wildcard surface.
func TestLoad_LearnInferenceNormalization_Negative_Rejected(t *testing.T) {
	body := "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: /tmp/c\n" +
		"  inference:\n" +
		"    normalization:\n" +
		"      cardinality_cap_per_host: -1\n"
	p := writeLearnConfig(t, body)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected Load error for negative cardinality_cap_per_host")
	}
	if !strings.Contains(err.Error(), "learn.inference.normalization.cardinality_cap_per_host") {
		t.Errorf("error %q missing operator-facing YAML path", err)
	}
}

// TestCanonicalPolicyHash_OmittedFloorsHashAsExplicitDefaults proves the
// hash invariant policySemanticView promises: a config with omitted
// learn.inference.floors and a config with explicit 5/20/3 must produce
// identical canonical policy hashes. Without the Resolved() pre-pass,
// these would diverge despite describing the same effective policy,
// causing spurious verifier rejections on PRs that just clarify
// defaults.
func TestCanonicalPolicyHash_OmittedFloorsHashAsExplicitDefaults(t *testing.T) {
	t.Parallel()

	omitted := Defaults()
	if got := omitted.Learn.Inference.Floors; (got != LearnInferenceFloors{}) {
		t.Fatalf("Defaults() should leave inference.floors at zero, got %+v", got)
	}

	explicit := Defaults()
	explicit.Learn.Inference.Floors = LearnInferenceFloors{
		MinSessions: defaultLearnFloorMinSessions,
		MinEvents:   defaultLearnFloorMinEvents,
		MinWindows:  defaultLearnFloorMinWindows,
	}

	if h1, h2 := omitted.CanonicalPolicyHash(), explicit.CanonicalPolicyHash(); h1 != h2 {
		t.Errorf("omitted floors and explicit defaults produced different hashes; the Resolved() pre-pass should make them identical\n  omitted:  %s\n  explicit: %s", h1, h2)
	}
}

// TestCanonicalPolicyHash_OmittedNormalizationHashAsExplicitDefaults is
// the parallel invariant for the normalization substruct.
func TestCanonicalPolicyHash_OmittedNormalizationHashAsExplicitDefaults(t *testing.T) {
	t.Parallel()

	omitted := Defaults()
	if got := omitted.Learn.Inference.Normalization; !reflect.DeepEqual(got, LearnInferenceNormalization{}) {
		t.Fatalf("Defaults() should leave inference.normalization at zero, got %+v", got)
	}

	explicit := Defaults()
	explicit.Learn.Inference.Normalization = LearnInferenceNormalization{
		Algorithm:             LearnNormalizationAlgorithmV1,
		MinEvents:             defaultLearnNormMinEvents,
		MinDistinctValues:     defaultLearnNormMinDistinctValues,
		EntropyThresholdBits:  defaultLearnNormEntropyThresholdBits,
		CardinalityCapPerHost: defaultLearnNormCardinalityCapPerHost,
		TailPromotionBlockPct: defaultLearnNormTailPromotionBlockPct,
	}

	if h1, h2 := omitted.CanonicalPolicyHash(), explicit.CanonicalPolicyHash(); h1 != h2 {
		t.Errorf("omitted normalization and explicit defaults produced different hashes; the Resolved() pre-pass should make them identical\n  omitted:  %s\n  explicit: %s", h1, h2)
	}
}

// TestLearnInferenceFloors_Resolved exercises the Resolved() canonical
// pre-pass directly. Each row pins one input/output expectation so a
// future regression in the zero-fill logic surfaces with a precise
// failure message.
func TestLearnInferenceFloors_Resolved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   LearnInferenceFloors
		want LearnInferenceFloors
	}{
		{
			name: "all_zero_resolves_to_defaults",
			in:   LearnInferenceFloors{},
			want: LearnInferenceFloors{MinSessions: 5, MinEvents: 20, MinWindows: 3},
		},
		{
			name: "partial_zero_only_zero_fields_default",
			in:   LearnInferenceFloors{MinSessions: 0, MinEvents: 50, MinWindows: 0},
			want: LearnInferenceFloors{MinSessions: 5, MinEvents: 50, MinWindows: 3},
		},
		{
			name: "all_set_passes_through",
			in:   LearnInferenceFloors{MinSessions: 99, MinEvents: 999, MinWindows: 9},
			want: LearnInferenceFloors{MinSessions: 99, MinEvents: 999, MinWindows: 9},
		},
		{
			name: "explicit_defaults_pass_through",
			in:   LearnInferenceFloors{MinSessions: 5, MinEvents: 20, MinWindows: 3},
			want: LearnInferenceFloors{MinSessions: 5, MinEvents: 20, MinWindows: 3},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.Resolved(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Resolved(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestLearnInferenceNormalization_Resolved is the parallel test for the
// normalization substruct.
func TestLearnInferenceNormalization_Resolved(t *testing.T) {
	t.Parallel()

	defaults := LearnInferenceNormalization{
		Algorithm:             LearnNormalizationAlgorithmV1,
		MinEvents:             10,
		MinDistinctValues:     5,
		EntropyThresholdBits:  3.0,
		CardinalityCapPerHost: 1000,
		TailPromotionBlockPct: 5.0,
	}

	tests := []struct {
		name string
		in   LearnInferenceNormalization
		want LearnInferenceNormalization
	}{
		{name: "all_zero_resolves_to_defaults", in: LearnInferenceNormalization{}, want: defaults},
		{
			name: "partial_set_only_zero_fields_default",
			in: LearnInferenceNormalization{
				MinEvents:             100,
				CardinalityCapPerHost: 5000,
			},
			want: LearnInferenceNormalization{
				Algorithm:             LearnNormalizationAlgorithmV1,
				MinEvents:             100,
				MinDistinctValues:     5,
				EntropyThresholdBits:  3.0,
				CardinalityCapPerHost: 5000,
				TailPromotionBlockPct: 5.0,
			},
		},
		{
			name: "all_set_passes_through",
			in: LearnInferenceNormalization{
				Algorithm:             LearnNormalizationAlgorithmV1,
				MinEvents:             50,
				MinDistinctValues:     8,
				EntropyThresholdBits:  4.0,
				CardinalityCapPerHost: 2000,
				TailPromotionBlockPct: 2.5,
			},
			want: LearnInferenceNormalization{
				Algorithm:             LearnNormalizationAlgorithmV1,
				MinEvents:             50,
				MinDistinctValues:     8,
				EntropyThresholdBits:  4.0,
				CardinalityCapPerHost: 2000,
				TailPromotionBlockPct: 2.5,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.Resolved(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Resolved(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}
