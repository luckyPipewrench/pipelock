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

// loadSSEConfig writes the given YAML to a temp file and returns the loaded
// config so tests can exercise the real Load + ApplyDefaults + applyDefaults
// (lowercase) raw-map inspection path.
func loadSSEConfig(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// State 1 (omitted from YAML): the entire response_scanning block is missing.
func TestSSEStreamingEnabled_Omitted(t *testing.T) {
	cfg := loadSSEConfig(t, "version: 1\n")
	if !cfg.ResponseScanning.SSEStreaming.Enabled {
		t.Errorf("omitted sse_streaming must default to enabled=true, got false")
	}
}

// State 1b (response_scanning present, sse_streaming block absent): same expectation.
func TestSSEStreamingEnabled_ParentPresentChildAbsent(t *testing.T) {
	cfg := loadSSEConfig(t, `
version: 1
response_scanning:
  enabled: true
`)
	if !cfg.ResponseScanning.SSEStreaming.Enabled {
		t.Errorf("absent sse_streaming child must default to enabled=true, got false")
	}
}

// State 2 (YAML null/blank): explicit null on enabled means "use the secure default".
func TestSSEStreamingEnabled_YAMLNull(t *testing.T) {
	cfg := loadSSEConfig(t, `
version: 1
response_scanning:
  sse_streaming:
    enabled:
`)
	if !cfg.ResponseScanning.SSEStreaming.Enabled {
		t.Errorf("YAML null enabled must fail closed to true, got false")
	}
}

// State 3 (explicit false): operator opts out, must be respected.
func TestSSEStreamingEnabled_ExplicitFalse(t *testing.T) {
	cfg := loadSSEConfig(t, `
version: 1
response_scanning:
  sse_streaming:
    enabled: false
`)
	if cfg.ResponseScanning.SSEStreaming.Enabled {
		t.Errorf("explicit false must be preserved, got true")
	}
}

// State 4 (explicit true): also preserved.
func TestSSEStreamingEnabled_ExplicitTrue(t *testing.T) {
	cfg := loadSSEConfig(t, `
version: 1
response_scanning:
  sse_streaming:
    enabled: true
`)
	if !cfg.ResponseScanning.SSEStreaming.Enabled {
		t.Errorf("explicit true must be preserved, got false")
	}
}

// State 5 (reload with change): rewrite the file with a different value, reload, observe change.
func TestSSEStreamingEnabled_ReloadWithChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")

	if err := os.WriteFile(path, []byte("version: 1\nresponse_scanning:\n  sse_streaming:\n    enabled: true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	first, err := Load(path)
	if err != nil {
		t.Fatalf("Load #1: %v", err)
	}
	if !first.ResponseScanning.SSEStreaming.Enabled {
		t.Fatalf("first load should have enabled=true")
	}

	if err := os.WriteFile(path, []byte("version: 1\nresponse_scanning:\n  sse_streaming:\n    enabled: false\n"), 0o600); err != nil {
		t.Fatalf("WriteFile #2: %v", err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if second.ResponseScanning.SSEStreaming.Enabled {
		t.Fatalf("reload with change should observe enabled=false")
	}
}

// State 6 (reload without change): the second load preserves the same secure default.
func TestSSEStreamingEnabled_ReloadWithoutChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")

	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	first, err := Load(path)
	if err != nil {
		t.Fatalf("Load #1: %v", err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if first.ResponseScanning.SSEStreaming.Enabled != second.ResponseScanning.SSEStreaming.Enabled {
		t.Errorf("reload without change must produce identical Enabled, got %v vs %v",
			first.ResponseScanning.SSEStreaming.Enabled, second.ResponseScanning.SSEStreaming.Enabled)
	}
	if !first.ResponseScanning.SSEStreaming.Enabled {
		t.Errorf("default must remain enabled=true across reloads")
	}
}

// --- Defaults() coverage ---

func TestDefaults_GenericSSEScanning(t *testing.T) {
	cfg := Defaults()
	sse := cfg.ResponseScanning.SSEStreaming
	if !sse.Enabled {
		t.Errorf("Defaults().ResponseScanning.SSEStreaming.Enabled = false, want true")
	}
	if sse.Action != ActionBlock {
		t.Errorf("default Action = %q, want %q", sse.Action, ActionBlock)
	}
	if sse.MaxEventBytes != 64*1024 {
		t.Errorf("default MaxEventBytes = %d, want 65536", sse.MaxEventBytes)
	}
}

// --- Validation ---

func TestValidateResponseScanning_SSEStreamingActionWarn(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.SSEStreaming.Action = ActionWarn
	if err := cfg.validateResponseScanning(); err != nil {
		t.Errorf("warn must validate, got %v", err)
	}
}

func TestValidateResponseScanning_SSEStreamingActionBlock(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.SSEStreaming.Action = ActionBlock
	if err := cfg.validateResponseScanning(); err != nil {
		t.Errorf("block must validate, got %v", err)
	}
}

func TestValidateResponseScanning_SSEStreamingActionEmpty(t *testing.T) {
	// Empty action is allowed and falls through to the scanner's downstream
	// default. Validation must not reject it.
	cfg := Defaults()
	cfg.ResponseScanning.SSEStreaming.Action = ""
	if err := cfg.validateResponseScanning(); err != nil {
		t.Errorf("empty action must validate (downstream default), got %v", err)
	}
}

func TestValidateResponseScanning_SSEStreamingActionInvalid(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.SSEStreaming.Action = ActionStrip
	err := cfg.validateResponseScanning()
	if err == nil {
		t.Fatalf("expected validation error for strip")
	}
	if !strings.Contains(err.Error(), "sse_streaming") {
		t.Errorf("error should reference sse_streaming, got %q", err.Error())
	}
}

func TestValidateResponseScanning_SSEStreamingNegativeMax(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.SSEStreaming.MaxEventBytes = -1
	if err := cfg.validateResponseScanning(); err == nil {
		t.Errorf("negative max_event_bytes must fail validation")
	}
}

func TestValidateResponseScanning_SSEStreamingDisabledIgnoresInvalid(t *testing.T) {
	// When sse_streaming.enabled=false, validation must not reject sub-fields.
	// Operators may have stale config that is meant to remain dormant.
	cfg := Defaults()
	cfg.ResponseScanning.SSEStreaming.Enabled = false
	cfg.ResponseScanning.SSEStreaming.Action = ActionStrip // would be rejected if Enabled=true
	if err := cfg.validateResponseScanning(); err != nil {
		t.Errorf("disabled sse_streaming must not validate sub-fields, got %v", err)
	}
}

// --- YAML round-trip ---

func TestSSEStreamingYAMLRoundTrip(t *testing.T) {
	src := GenericSSEScanning{
		Enabled:       true,
		Action:        ActionWarn,
		MaxEventBytes: 12345,
	}
	out, err := yaml.Marshal(src)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{"enabled: true", "action: warn", "max_event_bytes: 12345"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("YAML output missing %q:\n%s", want, out)
		}
	}

	var round GenericSSEScanning
	if err := yaml.Unmarshal(out, &round); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if round != src {
		t.Errorf("round trip drift: src=%+v round=%+v", src, round)
	}
}
