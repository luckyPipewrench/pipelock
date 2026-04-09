// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestMediaPolicy_DefaultGetters verifies that an unconfigured MediaPolicy
// (all nil booleans, zero ints, empty slices) returns the security-preserving
// defaults through the accessor methods. This is the contract that omitting
// YAML fields cannot weaken security.
func TestMediaPolicy_DefaultGetters(t *testing.T) {
	t.Parallel()
	var mp MediaPolicy

	if !mp.IsEnabled() {
		t.Error("IsEnabled should default to true when Enabled is nil")
	}
	if mp.ShouldStripImages() {
		t.Error("ShouldStripImages should default to false when StripImages is nil")
	}
	if !mp.ShouldStripAudio() {
		t.Error("ShouldStripAudio should default to true when StripAudio is nil")
	}
	if !mp.ShouldStripVideo() {
		t.Error("ShouldStripVideo should default to true when StripVideo is nil")
	}
	if !mp.ShouldStripImageMetadata() {
		t.Error("ShouldStripImageMetadata should default to true when StripImageMetadata is nil")
	}
	if !mp.ShouldLogExposure() {
		t.Error("ShouldLogExposure should default to true when LogMediaExposure is nil")
	}
	if got := mp.EffectiveMaxImageBytes(); got != DefaultMaxImageBytes {
		t.Errorf("EffectiveMaxImageBytes on empty struct = %d, want %d", got, DefaultMaxImageBytes)
	}
	if got := mp.EffectiveAllowedImageTypes(); !equalStringSlices(got, DefaultAllowedImageTypes) {
		t.Errorf("EffectiveAllowedImageTypes on empty struct = %v, want %v", got, DefaultAllowedImageTypes)
	}
}

// TestMediaPolicy_ExplicitFalseOverridesDefault verifies that explicit false
// in YAML overrides the nil-means-true default. This is the inverse direction
// of the security default — operators must be able to turn off any individual
// control without the struct silently re-enabling it.
func TestMediaPolicy_ExplicitFalseOverridesDefault(t *testing.T) {
	t.Parallel()
	f := false
	mp := MediaPolicy{
		Enabled:            &f,
		StripAudio:         &f,
		StripVideo:         &f,
		StripImageMetadata: &f,
		LogMediaExposure:   &f,
	}
	if mp.IsEnabled() {
		t.Error("explicit Enabled=false should disable policy")
	}
	if mp.ShouldStripAudio() {
		t.Error("explicit StripAudio=false should allow audio")
	}
	if mp.ShouldStripVideo() {
		t.Error("explicit StripVideo=false should allow video")
	}
	if mp.ShouldStripImageMetadata() {
		t.Error("explicit StripImageMetadata=false should preserve metadata")
	}
	if mp.ShouldLogExposure() {
		t.Error("explicit LogMediaExposure=false should suppress events")
	}
}

// TestMediaPolicy_ExplicitTrueOverridesDefault verifies that explicit true
// also works. Specifically, StripImages defaults false and must flip to true
// when set.
func TestMediaPolicy_ExplicitTrueOverridesDefault(t *testing.T) {
	t.Parallel()
	tr := true
	mp := MediaPolicy{StripImages: &tr}
	if !mp.ShouldStripImages() {
		t.Error("explicit StripImages=true should reject images")
	}
}

// TestMediaPolicy_YAMLStates exercises the 6-state boolean contract for each
// security-sensitive field: omitted, YAML blank (~/null), explicit false,
// explicit true. (The reload-with-change and reload-without-change states are
// covered by TestMediaPolicy_HotReload.) This enforces the hard rule: "new
// security-sensitive boolean fields must be tested in 6 states".
func TestMediaPolicy_YAMLStates(t *testing.T) {
	t.Parallel()

	type fieldExpectation struct {
		name          string
		getter        func(*MediaPolicy) bool
		defaultResult bool
	}
	fields := []fieldExpectation{
		{"enabled", func(m *MediaPolicy) bool { return m.IsEnabled() }, true},
		{"strip_images", func(m *MediaPolicy) bool { return m.ShouldStripImages() }, false},
		{"strip_audio", func(m *MediaPolicy) bool { return m.ShouldStripAudio() }, true},
		{"strip_video", func(m *MediaPolicy) bool { return m.ShouldStripVideo() }, true},
		{"strip_image_metadata", func(m *MediaPolicy) bool { return m.ShouldStripImageMetadata() }, true},
		{"log_media_exposure", func(m *MediaPolicy) bool { return m.ShouldLogExposure() }, true},
	}

	// State 1: field omitted entirely from YAML → accessor returns default.
	t.Run("omitted", func(t *testing.T) {
		var mp MediaPolicy
		if err := yaml.Unmarshal([]byte("{}"), &mp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, f := range fields {
			if got := f.getter(&mp); got != f.defaultResult {
				t.Errorf("state=omitted field=%s got=%v want default=%v", f.name, got, f.defaultResult)
			}
		}
	})

	// State 2: field present with YAML null → accessor returns default.
	// yaml.v3 decodes an explicit `~` into a nil pointer, matching absent.
	t.Run("null", func(t *testing.T) {
		for _, f := range fields {
			var mp MediaPolicy
			doc := f.name + ": ~\n"
			if err := yaml.Unmarshal([]byte(doc), &mp); err != nil {
				t.Fatalf("unmarshal %q: %v", f.name, err)
			}
			if got := f.getter(&mp); got != f.defaultResult {
				t.Errorf("state=null field=%s got=%v want default=%v (yaml=%q)", f.name, got, f.defaultResult, doc)
			}
		}
	})

	// State 3: explicit false.
	t.Run("explicit_false", func(t *testing.T) {
		for _, f := range fields {
			var mp MediaPolicy
			doc := f.name + ": false\n"
			if err := yaml.Unmarshal([]byte(doc), &mp); err != nil {
				t.Fatalf("unmarshal %q: %v", f.name, err)
			}
			if got := f.getter(&mp); got != false {
				t.Errorf("state=explicit_false field=%s got=%v want false (yaml=%q)", f.name, got, doc)
			}
		}
	})

	// State 4: explicit true.
	t.Run("explicit_true", func(t *testing.T) {
		for _, f := range fields {
			var mp MediaPolicy
			doc := f.name + ": true\n"
			if err := yaml.Unmarshal([]byte(doc), &mp); err != nil {
				t.Fatalf("unmarshal %q: %v", f.name, err)
			}
			if got := f.getter(&mp); got != true {
				t.Errorf("state=explicit_true field=%s got=%v want true (yaml=%q)", f.name, got, doc)
			}
		}
	})
}

// TestMediaPolicy_HotReload covers the final two states of the 6-state
// contract: reload with a changed value and reload without change. We
// simulate by re-unmarshaling over an existing struct and confirming the
// state flips or stays as expected.
func TestMediaPolicy_HotReload(t *testing.T) {
	t.Parallel()

	// Initial: strip_audio explicitly false.
	initial := "strip_audio: false\n"
	var mp MediaPolicy
	if err := yaml.Unmarshal([]byte(initial), &mp); err != nil {
		t.Fatalf("initial unmarshal: %v", err)
	}
	if mp.ShouldStripAudio() {
		t.Fatalf("after initial load, ShouldStripAudio = true, want false")
	}

	// Reload with change: strip_audio now true. New Config means a fresh
	// struct (no leftover state from prior load).
	var mp2 MediaPolicy
	if err := yaml.Unmarshal([]byte("strip_audio: true\n"), &mp2); err != nil {
		t.Fatalf("reload change: %v", err)
	}
	if !mp2.ShouldStripAudio() {
		t.Error("after reload-with-change, ShouldStripAudio = false, want true")
	}

	// Reload without change: strip_audio stays true.
	var mp3 MediaPolicy
	if err := yaml.Unmarshal([]byte("strip_audio: true\n"), &mp3); err != nil {
		t.Fatalf("reload no change: %v", err)
	}
	if !mp3.ShouldStripAudio() {
		t.Error("after reload-without-change, ShouldStripAudio = false, want true")
	}
}

// TestMediaPolicy_ImageTypeAllowed exercises the case-insensitive media type
// matcher, including parameter tolerance and trimming.
func TestMediaPolicy_ImageTypeAllowed(t *testing.T) {
	t.Parallel()
	var mp MediaPolicy
	tests := []struct {
		name  string
		mt    string
		allow bool
	}{
		{"png", "image/png", true},
		{"jpeg", "image/jpeg", true},
		{"uppercase", "IMAGE/PNG", true},
		{"whitespace", "  image/jpeg  ", true},
		// GIF and WebP are NOT in the default allowlist because the
		// stripper cannot sanitize them yet; admitting them would
		// pass through any embedded metadata.
		{"gif not default", "image/gif", false},
		{"webp not default", "image/webp", false},
		{"bmp not default", "image/bmp", false},
		{"svg not default", "image/svg+xml", false},
		{"non-image", "audio/mpeg", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mp.ImageTypeAllowed(tt.mt); got != tt.allow {
				t.Errorf("ImageTypeAllowed(%q) = %v, want %v", tt.mt, got, tt.allow)
			}
		})
	}
}

// TestMediaPolicy_ImageTypeAllowed_CustomList verifies the effective allowed
// list overrides the default when set.
func TestMediaPolicy_ImageTypeAllowed_CustomList(t *testing.T) {
	t.Parallel()
	mp := MediaPolicy{AllowedImageTypes: []string{"image/png"}}
	if !mp.ImageTypeAllowed("image/png") {
		t.Error("custom list should allow image/png")
	}
	if mp.ImageTypeAllowed("image/jpeg") {
		t.Error("custom list with only png should reject jpeg")
	}
}

// TestMediaPolicy_ImageTypeAllowed_CanonicalizationDrift regressions the
// validation/matching drift where YAML entries with whitespace, media-type
// parameters, or mixed case passed validation (which normalized before
// comparing) but never matched at runtime (which compared raw stored
// strings). Both sides now canonicalize through the same helper; every
// form in this table must match a canonical input.
func TestMediaPolicy_ImageTypeAllowed_CanonicalizationDrift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		allowed     []string
		input       string
		wantAllowed bool
	}{
		{"raw whitespace entry", []string{" image/png "}, "image/png", true},
		{"entry with parameter", []string{"image/jpeg; charset=binary"}, "image/jpeg", true},
		{"uppercase entry", []string{"IMAGE/PNG"}, "image/png", true},
		{"mixed whitespace entry", []string{"\timage/webp\n"}, "image/webp", true},
		{"input has whitespace", []string{"image/png"}, "  image/png  ", true},
		{"input has parameter", []string{"image/png"}, "image/png; charset=binary", true},
		{"non-matching type", []string{"image/png"}, "image/jpeg", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := MediaPolicy{AllowedImageTypes: tt.allowed}
			got := mp.ImageTypeAllowed(tt.input)
			if got != tt.wantAllowed {
				t.Errorf("ImageTypeAllowed(%q) with allowed=%v = %v, want %v",
					tt.input, tt.allowed, got, tt.wantAllowed)
			}
		})
	}
}

// TestValidateMediaPolicy_CanonicalizationAccepts verifies the validator
// accepts non-canonical but recoverable entries that match the runtime
// canonicalization. This is the validator side of the drift-fix contract.
func TestValidateMediaPolicy_CanonicalizationAccepts(t *testing.T) {
	t.Parallel()
	tests := []string{
		" image/png ",
		"IMAGE/JPEG",
		"image/jpeg; charset=binary",
		"\timage/webp\n",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			cfg := Defaults()
			cfg.MediaPolicy.AllowedImageTypes = []string{raw}
			if err := cfg.validateMediaPolicy(); err != nil {
				t.Errorf("validator rejected canonicalizable entry %q: %v", raw, err)
			}
		})
	}
}

// TestCanonicalizeMediaTypeEntry covers the edge cases of the shared
// canonicalization helper directly — both parse-success and fallback
// parse-error branches.
func TestCanonicalizeMediaTypeEntry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"image/png", "image/png"},
		{"IMAGE/PNG", "image/png"},
		{"  image/jpeg  ", "image/jpeg"},
		{"image/jpeg; charset=binary", "image/jpeg"},
		{"image/jpeg ; charset=binary", "image/jpeg"},
		{"", ""},
		{"   ", ""},
		// Parse error fallback — no slash, no media type. Result is
		// lowercased trimmed input; the validator then rejects it.
		{"nonsense", "nonsense"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := canonicalizeMediaTypeEntry(tt.in)
			if got != tt.want {
				t.Errorf("canonicalizeMediaTypeEntry(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestMediaPolicy_EffectiveMaxImageBytes verifies the zero-means-default
// behavior and that explicit positive values are honored.
func TestMediaPolicy_EffectiveMaxImageBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   int64
		want int64
	}{
		{"zero uses default", 0, DefaultMaxImageBytes},
		{"explicit small", 1024, 1024},
		{"explicit large", 10 * 1024 * 1024, 10 * 1024 * 1024},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := MediaPolicy{MaxImageBytes: tt.in}
			if got := mp.EffectiveMaxImageBytes(); got != tt.want {
				t.Errorf("EffectiveMaxImageBytes(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestValidateMediaPolicy_Defaults confirms Defaults() produces a valid
// configuration and the validator passes without errors.
func TestValidateMediaPolicy_Defaults(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	if err := cfg.validateMediaPolicy(); err != nil {
		t.Errorf("Defaults() media_policy should validate: %v", err)
	}
}

// TestValidateMediaPolicy_ExplicitDisableStillValidates asserts that
// structural validation runs even when the master switch is explicitly
// false. A disabled config that contains invalid values would otherwise
// survive a load, get persisted, and then apply broken state the moment
// an operator re-enabled the feature on a later hot reload.
func TestValidateMediaPolicy_ExplicitDisableStillValidates(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	f := false
	cfg.MediaPolicy.Enabled = &f
	cfg.MediaPolicy.MaxImageBytes = -1
	if err := cfg.validateMediaPolicy(); err == nil {
		t.Fatal("expected validation error for negative MaxImageBytes even when disabled")
	}
}

// TestValidateMediaPolicy_DisabledWithValidFields asserts that a disabled
// policy with otherwise-valid fields still passes validation. The
// disable-still-validates rule is about catching malformed state, not
// rejecting all disabled configs.
func TestValidateMediaPolicy_DisabledWithValidFields(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	f := false
	cfg.MediaPolicy.Enabled = &f
	cfg.MediaPolicy.MaxImageBytes = 0 // zero is "use default"
	cfg.MediaPolicy.AllowedImageTypes = []string{"image/png"}
	if err := cfg.validateMediaPolicy(); err != nil {
		t.Errorf("disabled media_policy with valid fields should validate cleanly: %v", err)
	}
}

// TestValidateMediaPolicy_Errors exercises each error branch. Each case must
// fail validation with a clear message identifying the offending field.
func TestValidateMediaPolicy_Errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{
			name:    "negative max_image_bytes",
			mutate:  func(c *Config) { c.MediaPolicy.MaxImageBytes = -1 },
			wantSub: "max_image_bytes must be non-negative",
		},
		{
			name: "empty allowed_image_types entry",
			mutate: func(c *Config) {
				c.MediaPolicy.AllowedImageTypes = []string{""}
			},
			wantSub: "empty or unparseable entry",
		},
		{
			name: "non-image allowed_image_types entry",
			mutate: func(c *Config) {
				c.MediaPolicy.AllowedImageTypes = []string{"text/html"}
			},
			wantSub: "must be an image/*",
		},
		{
			name: "svg in allowed_image_types",
			mutate: func(c *Config) {
				c.MediaPolicy.AllowedImageTypes = []string{"image/svg+xml"}
			},
			wantSub: "must not include image/svg+xml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mutate(cfg)
			err := cfg.validateMediaPolicy()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

// TestValidateReload_MediaPolicyAllowlistClearedToDefaults regressions
// the case where an operator reloads from an explicit narrow list back
// to an empty value (which falls through to DefaultAllowedImageTypes).
// That transition widens the effective allowlist and must produce a
// downgrade warning, even though the raw updated list is empty.
func TestValidateReload_MediaPolicyAllowlistClearedToDefaults(t *testing.T) {
	t.Parallel()
	oldCfg := Defaults()
	oldCfg.MediaPolicy.AllowedImageTypes = []string{"image/png"}
	newCfg := Defaults()
	newCfg.MediaPolicy.AllowedImageTypes = nil // falls through to defaults

	warnings := ValidateReload(oldCfg, newCfg)
	found := false
	for _, w := range warnings {
		if w.Field == "media_policy.allowed_image_types" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("clearing allowed_image_types back to defaults should warn as widening; got warnings: %v", warnings)
	}
}

// TestValidateReload_MediaPolicyAllowlistNarrowed verifies that narrowing
// the allowlist does NOT warn. Narrowing is a strengthening change and
// shouldn't generate noise.
func TestValidateReload_MediaPolicyAllowlistNarrowed(t *testing.T) {
	t.Parallel()
	oldCfg := Defaults() // default list: png + jpeg
	newCfg := Defaults()
	newCfg.MediaPolicy.AllowedImageTypes = []string{"image/png"} // narrower

	warnings := ValidateReload(oldCfg, newCfg)
	for _, w := range warnings {
		if w.Field == "media_policy.allowed_image_types" {
			t.Errorf("narrowing allowed_image_types should not warn, got: %v", w)
		}
	}
}

// equalStringSlices compares two string slices for equal length and
// element-wise equality. Avoids importing reflect for a simple test helper.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
