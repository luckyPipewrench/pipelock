// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_FlightRecorderEvidenceHealthEnabledStates(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{name: "omitted", yaml: "flight_recorder:\n  enabled: true\n", want: true},
		{name: "null", yaml: "flight_recorder:\n  enabled: true\n  evidence_health:\n    enabled: null\n", want: true},
		{name: "false", yaml: "flight_recorder:\n  enabled: true\n  evidence_health:\n    enabled: false\n", want: false},
		{name: "true", yaml: "flight_recorder:\n  enabled: true\n  evidence_health:\n    enabled: true\n", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadEvidenceHealthYAML(t, tt.yaml)
			if got := cfg.FlightRecorder.EvidenceHealthEnabled(); got != tt.want {
				t.Fatalf("EvidenceHealthEnabled = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoad_FlightRecorderEvidenceHealthReloadStates(t *testing.T) {
	first := loadEvidenceHealthYAML(t, "flight_recorder:\n  enabled: true\n")
	if !first.FlightRecorder.EvidenceHealthEnabled() {
		t.Fatal("first load EvidenceHealthEnabled = false, want true")
	}
	second := loadEvidenceHealthYAML(t, "flight_recorder:\n  enabled: true\n  evidence_health:\n    enabled: false\n")
	if second.FlightRecorder.EvidenceHealthEnabled() {
		t.Fatal("reload with change EvidenceHealthEnabled = true, want false")
	}
	third := loadEvidenceHealthYAML(t, "flight_recorder:\n  enabled: true\n  evidence_health:\n    enabled: false\n")
	if third.FlightRecorder.EvidenceHealthEnabled() != second.FlightRecorder.EvidenceHealthEnabled() {
		t.Fatalf("reload without change EvidenceHealthEnabled = %v, want %v",
			third.FlightRecorder.EvidenceHealthEnabled(), second.FlightRecorder.EvidenceHealthEnabled())
	}
}

func TestLoad_FlightRecorderEvidenceMaxAnchorLagDuration(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want time.Duration
	}{
		{
			name: "omitted uses default",
			yaml: "flight_recorder:\n  enabled: true\n",
			want: DefaultEvidenceHealthMaxAnchorLag,
		},
		{
			name: "null uses default",
			yaml: "flight_recorder:\n  enabled: true\n  evidence_health:\n    max_anchor_lag: null\n",
			want: DefaultEvidenceHealthMaxAnchorLag,
		},
		{
			name: "explicit zero is preserved",
			yaml: "flight_recorder:\n  enabled: true\n  evidence_health:\n    max_anchor_lag: 0s\n",
			want: 0,
		},
		{
			name: "whitespace-padded duration",
			yaml: "flight_recorder:\n  enabled: true\n  evidence_health:\n    max_anchor_lag: ' 90m '\n",
			want: 90 * time.Minute,
		},
		{
			name: "blank uses default",
			yaml: "flight_recorder:\n  enabled: true\n  evidence_health:\n    max_anchor_lag: ''\n",
			want: DefaultEvidenceHealthMaxAnchorLag,
		},
		{
			name: "valid duration",
			yaml: "flight_recorder:\n  enabled: true\n  evidence_health:\n    max_anchor_lag: 90m\n",
			want: 90 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadEvidenceHealthYAML(t, tt.yaml)
			if got := cfg.FlightRecorder.EvidenceMaxAnchorLagDuration(); got != tt.want {
				t.Fatalf("EvidenceMaxAnchorLagDuration = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestFlightRecorderEvidenceMaxAnchorLagDurationFallback(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "blank", raw: " \t", want: DefaultEvidenceHealthMaxAnchorLag},
		{name: "trimmed valid duration", raw: " 90m ", want: 90 * time.Minute},
		{name: "malformed", raw: "not-a-duration", want: DefaultEvidenceHealthMaxAnchorLag},
		{name: "negative", raw: "-1s", want: DefaultEvidenceHealthMaxAnchorLag},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := FlightRecorder{EvidenceHealth: FlightRecorderEvidenceHealth{MaxAnchorLag: tt.raw}}
			if got := f.EvidenceMaxAnchorLagDuration(); got != tt.want {
				t.Fatalf("EvidenceMaxAnchorLagDuration(%q) = %s, want %s", tt.raw, got, tt.want)
			}
		})
	}
}

func TestValidateFlightRecorderEvidenceHealthDurations(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{name: "too_short", mut: func(c *Config) { c.FlightRecorder.EvidenceHealth.SelfAuditInterval = "1s" }},
		{name: "too_long", mut: func(c *Config) { c.FlightRecorder.EvidenceHealth.SelfAuditInterval = "11m" }},
		{name: "negative_anchor_lag", mut: func(c *Config) { c.FlightRecorder.EvidenceHealth.MaxAnchorLag = "-1s" }},
		{name: "unparseable_self_audit_interval", mut: func(c *Config) { c.FlightRecorder.EvidenceHealth.SelfAuditInterval = "not-a-duration" }},
		{name: "unparseable_max_anchor_lag", mut: func(c *Config) { c.FlightRecorder.EvidenceHealth.MaxAnchorLag = "not-a-duration" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.FlightRecorder.Dir = t.TempDir()
			tt.mut(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate succeeded, want error")
			}
		})
	}
}

func loadEvidenceHealthYAML(t *testing.T, body string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}
