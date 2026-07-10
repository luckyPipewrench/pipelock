// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadForwarderDefaultsAndNulls(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		extra string
	}{
		{name: "omitted"},
		{name: "blank", extra: "    min_severity:\n    timeout_seconds:\n    queue_size:\n"},
		{name: "null", extra: "    min_severity: null\n    timeout_seconds: null\n    queue_size: null\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			yaml := "version: 1\nemit:\n  forwarder:\n" + tc.extra
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Emit.Forwarder.MinSeverity != SeverityWarn || cfg.Emit.Forwarder.TimeoutSeconds != 5 || cfg.Emit.Forwarder.QueueSize != 256 {
				t.Fatalf("forwarder defaults = %+v", cfg.Emit.Forwarder)
			}
		})
	}
}

func TestValidateForwarderFailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		mutate    func(*ForwarderConfig)
		wantError string
	}{
		{name: "no allowlist", mutate: func(c *ForwarderConfig) { c.DestinationAllowlist = nil }, wantError: "exactly present"},
		{name: "wrong host", mutate: func(c *ForwarderConfig) { c.DestinationAllowlist = []string{"other.vendor.example"} }, wantError: "exactly present"},
		{name: "wildcard", mutate: func(c *ForwarderConfig) { c.DestinationAllowlist = []string{"*.vendor.example"} }, wantError: "exact hostnames"},
		{name: "missing spool", mutate: func(c *ForwarderConfig) { c.SpoolFile = "" }, wantError: "spool_file"},
		{name: "userinfo", mutate: func(c *ForwarderConfig) { c.URL = "https://user:pass@api.vendor.example/events" }, wantError: "userinfo"},
		{name: "bad severity", mutate: func(c *ForwarderConfig) { c.MinSeverity = "debug" }, wantError: "min_severity"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Emit.Forwarder = ForwarderConfig{
				URL: "https://api.vendor.example/events", DestinationAllowlist: []string{"api.vendor.example"},
				SpoolFile: "/var/lib/pipelock/siem.spool", CursorFile: "/var/lib/pipelock/siem.cursor",
				MinSeverity: SeverityWarn, TimeoutSeconds: 5, QueueSize: 256,
			}
			tc.mutate(&cfg.Emit.Forwarder)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Validate error = %v, want substring %q", err, tc.wantError)
			}
		})
	}
}

func TestValidateForwarderValid(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Emit.Forwarder = ForwarderConfig{
		URL: "https://api.vendor.example/events", DestinationAllowlist: []string{"API.VENDOR.EXAMPLE."},
		SpoolFile: "/var/lib/pipelock/siem.spool", CursorFile: "/var/lib/pipelock/siem.cursor",
		MinSeverity: SeverityWarn, TimeoutSeconds: 5, QueueSize: 256,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
