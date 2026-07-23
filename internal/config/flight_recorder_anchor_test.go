// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFlightRecorderAnchorDefaultsAndExplicitZeros(t *testing.T) {
	tests := []struct {
		name          string
		anchorYAML    string
		wantInterval  time.Duration
		wantThreshold uint64
		wantActive    bool
	}{
		{name: "omitted", wantInterval: time.Hour, wantThreshold: 1000},
		{name: "yaml_null", anchorYAML: "  anchor: null\n", wantInterval: time.Hour, wantThreshold: 1000},
		{name: "empty_values", anchorYAML: "  anchor:\n    interval: \"\"\n    receipt_threshold: null\n", wantInterval: time.Hour, wantThreshold: 1000},
		{name: "explicit_zeros", anchorYAML: "  anchor:\n    interval: \"0\"\n    receipt_threshold: 0\n", wantInterval: 0, wantThreshold: 0},
		{name: "explicit_values", anchorYAML: "  anchor:\n    local_log: /tmp/anchor-log.jsonl\n    interval: 2h\n    receipt_threshold: 25\n", wantInterval: 2 * time.Hour, wantThreshold: 25, wantActive: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadFlightRecorderAnchorYAML(t, tt.anchorYAML)
			if got := cfg.FlightRecorder.AnchorIntervalDuration(); got != tt.wantInterval {
				t.Fatalf("AnchorIntervalDuration = %s, want %s", got, tt.wantInterval)
			}
			if got := cfg.FlightRecorder.AnchorReceiptThreshold(); got != tt.wantThreshold {
				t.Fatalf("AnchorReceiptThreshold = %d, want %d", got, tt.wantThreshold)
			}
			if got := cfg.FlightRecorder.AnchorConfigured(); got != tt.wantActive {
				t.Fatalf("AnchorConfigured = %v, want %v", got, tt.wantActive)
			}
		})
	}
}

func TestLoadFlightRecorderAnchorReloadStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	load := func(body string) *Config {
		t.Helper()
		if err := os.WriteFile(path, []byte("mode: balanced\nflight_recorder:\n"+body), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return cfg
	}

	first := load("  anchor: null\n")
	if first.FlightRecorder.AnchorConfigured() {
		t.Fatal("first load unexpectedly configured anchoring")
	}
	second := load("  anchor:\n    local_log: /tmp/anchor-log.jsonl\n    interval: 0\n    receipt_threshold: 2\n")
	if !second.FlightRecorder.AnchorConfigured() || second.FlightRecorder.AnchorReceiptThreshold() != 2 {
		t.Fatalf("reload with change = %+v, want active threshold 2", second.FlightRecorder.Anchor)
	}
	third := load("  anchor:\n    local_log: /tmp/anchor-log.jsonl\n    interval: 0\n    receipt_threshold: 2\n")
	if third.FlightRecorder.AnchorConfigured() != second.FlightRecorder.AnchorConfigured() ||
		third.FlightRecorder.AnchorReceiptThreshold() != second.FlightRecorder.AnchorReceiptThreshold() {
		t.Fatalf("reload without change = %+v, want %+v", third.FlightRecorder.Anchor, second.FlightRecorder.Anchor)
	}
	fourth := load("  anchor: null\n")
	if fourth.FlightRecorder.AnchorConfigured() {
		t.Fatal("reload removal left anchoring configured")
	}
}

func TestValidateFlightRecorderAnchor(t *testing.T) {
	zero := uint64(0)
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "rekor_and_local", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "https://rekor.internal.example"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
			c.FlightRecorder.Anchor.LocalLog = "/tmp/anchor.jsonl"
		}, wantErr: "mutually exclusive"},
		{name: "rekor_missing_key", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "https://rekor.internal.example"
		}, wantErr: "rekor_key_path is required"},
		{name: "rekor_invalid_url", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "://broken"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: "valid URL"},
		{name: "rekor_remote_plaintext", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "http://rekor.internal.example"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: "must use https"},
		{name: "rekor_wrong_scheme", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "ftp://rekor.internal.example"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: "must use http or https"},
		{name: "rekor_url_components", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "https://user@rekor.internal.example?debug=true"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: "must not contain"},
		{name: "invalid_interval", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.Interval = "later"
		}, wantErr: "must parse as a duration"},
		{name: "negative_interval", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.Interval = "-1s"
		}, wantErr: "must be non-negative"},
		{name: "no_trigger", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.LocalLog = "/tmp/anchor.jsonl"
			c.FlightRecorder.Anchor.Interval = "0"
			c.FlightRecorder.Anchor.ReceiptThreshold = &zero
		}, wantErr: "no trigger"},
		{name: "local_valid", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.LocalLog = "/tmp/anchor.jsonl"
		}, wantErr: ""},
		{name: "rekor_valid", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "https://rekor.internal.example"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: ""},
		{name: "rekor_local_http_valid", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "http://127.0.0.1:3000"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: ""},
		{name: "rekor_uppercase_https_valid", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "HTTPS://REKOR.INTERNAL.EXAMPLE"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: ""},
		{name: "rekor_ipv6_loopback_http_valid", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "http://[::1]:3000"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: ""},
		{name: "rekor_localhost_suffix_rejected", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "http://localhost.evil.example"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: "must use https"},
		{name: "rekor_loopback_suffix_rejected", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "http://127.0.0.1.evil.example"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: "must use https"},
		{name: "rekor_localhost_trailing_dot_rejected", mutate: func(c *Config) {
			c.FlightRecorder.Anchor.RekorURL = "http://localhost.:3000"
			c.FlightRecorder.Anchor.RekorKeyPath = "/tmp/rekor.key"
		}, wantErr: "must use https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFlightRecorderAnchorWarnsWithoutAnchorPoint(t *testing.T) {
	cfg := loadFlightRecorderAnchorYAML(t, "  anchor:\n    interval: 2h\n")
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	for _, warning := range warnings {
		if warning.Field == "flight_recorder.anchor" && strings.Contains(warning.Message, "no anchor point") {
			if err := cfg.validateFlightRecorderAnchor(nil); err != nil {
				t.Fatalf("validateFlightRecorderAnchor without warning sink: %v", err)
			}
			return
		}
	}
	t.Fatalf("missing no-anchor-point warning in %+v", warnings)
}

func TestFlightRecorderAnchorAccessorFallbacks(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "empty", want: time.Hour},
		{name: "invalid", raw: "later", want: time.Hour},
		{name: "negative", raw: "-1s", want: time.Hour},
		{name: "zero", raw: "0", want: 0},
		{name: "valid", raw: "2h", want: 2 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fr := FlightRecorder{Anchor: FlightRecorderAnchor{Interval: tt.raw}}
			if got := fr.AnchorIntervalDuration(); got != tt.want {
				t.Fatalf("AnchorIntervalDuration = %s, want %s", got, tt.want)
			}
		})
	}
	if got := (FlightRecorder{}).AnchorReceiptThreshold(); got != DefaultFlightRecorderAnchorThreshold {
		t.Fatalf("nil AnchorReceiptThreshold = %d, want default", got)
	}
	zero := uint64(0)
	if got := (FlightRecorder{Anchor: FlightRecorderAnchor{ReceiptThreshold: &zero}}).AnchorReceiptThreshold(); got != 0 {
		t.Fatalf("explicit-zero AnchorReceiptThreshold = %d, want 0", got)
	}
}

func TestFlightRecorderAnchorExplicitSettingsMalformedRawIsSafe(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "none"},
		{name: "malformed", raw: []byte("{")},
		{name: "empty_document", raw: []byte("---\n")},
		{name: "scalar_document", raw: []byte("value\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{rawBytes: tt.raw}
			if cfg.flightRecorderAnchorHasExplicitSettings() {
				t.Fatal("malformed/empty raw config reported explicit anchor settings")
			}
		})
	}
}

func loadFlightRecorderAnchorYAML(t *testing.T, anchorYAML string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := "mode: balanced\nflight_recorder:\n  enabled: true\n  dir: /tmp/recorder\n" + anchorYAML
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}
