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
			if cfg.Emit.Forwarder.MaxSpoolBytes != defaultForwarderMaxSpoolBytes {
				t.Fatalf("forwarder max_spool_bytes = %d, want default %d", cfg.Emit.Forwarder.MaxSpoolBytes, defaultForwarderMaxSpoolBytes)
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
		{name: "missing cursor", mutate: func(c *ForwarderConfig) { c.CursorFile = "" }, wantError: "cursor_file"},
		{name: "zero timeout", mutate: func(c *ForwarderConfig) { c.TimeoutSeconds = 0 }, wantError: "must be positive"},
		{name: "negative queue", mutate: func(c *ForwarderConfig) { c.QueueSize = -1 }, wantError: "must be positive"},
		{name: "invalid scheme", mutate: func(c *ForwarderConfig) { c.URL = "ftp://api.vendor.example/events" }, wantError: "must be http:// or https://"},
		{name: "fragment", mutate: func(c *ForwarderConfig) { c.URL = "https://api.vendor.example/events#secret" }, wantError: "fragment"},
		{name: "userinfo", mutate: func(c *ForwarderConfig) { c.URL = "https://user:pass@api.vendor.example/events" }, wantError: "userinfo"},
		{name: "bad severity", mutate: func(c *ForwarderConfig) { c.MinSeverity = "debug" }, wantError: "min_severity"},
		{name: "http remote without flag", mutate: func(c *ForwarderConfig) { c.URL = "http://api.vendor.example/events" }, wantError: "allow_insecure_http"},
		{name: "http remote with token", mutate: func(c *ForwarderConfig) {
			c.URL = "http://api.vendor.example/events"
			c.AuthToken = "bearer"
		}, wantError: "requires an https"},
		{name: "http remote token ignores insecure flag", mutate: func(c *ForwarderConfig) {
			c.URL = "http://api.vendor.example/events"
			c.AuthToken = "bearer"
			c.AllowInsecureHTTP = true
		}, wantError: "requires an https"},
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

func TestValidateForwarderCanonicalIPAllowlistEquality(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Emit.Forwarder = ForwarderConfig{
		URL: "https://0x08080808/events", DestinationAllowlist: []string{"8.8.8.8"},
		SpoolFile: "/var/lib/pipelock/siem.spool", CursorFile: "/var/lib/pipelock/siem.cursor",
		MinSeverity: SeverityWarn, TimeoutSeconds: 5, QueueSize: 256,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate canonical target/allowlist equality: %v", err)
	}
}

func TestValidateForwarderCanonicalizationMatchesRuntimeForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		rawURL    string
		allowlist string
		wantError bool
	}{
		{name: "standard IPv4", rawURL: "https://8.8.8.8/events", allowlist: "8.8.8.8"},
		{name: "full hex IPv4", rawURL: "https://0x08080808/events", allowlist: "8.8.8.8"},
		{name: "dotted hex IPv4", rawURL: "https://0x08.0x08.0x08.0x08/events", allowlist: "8.8.8.8"},
		{name: "dotted octal IPv4", rawURL: "https://010.010.010.010/events", allowlist: "8.8.8.8"},
		{name: "mixed radix IPv4", rawURL: "https://0x08.010.8.0x08/events", allowlist: "8.8.8.8"},
		{name: "two component IPv4 matches same address", rawURL: "https://8.8/events", allowlist: "8.0.0.8"},
		{name: "three component IPv4 matches same address", rawURL: "https://8.8.8/events", allowlist: "8.8.0.8"},
		{name: "full octal IPv4", rawURL: "https://01002004010/events", allowlist: "8.8.8.8"},
		{name: "decimal IPv4", rawURL: "https://134744072/events", allowlist: "8.8.8.8"},
		{name: "IPv4 mapped IPv6", rawURL: "https://[::ffff:8.8.8.8]/events", allowlist: "8.8.8.8"},
		{name: "IPv6 zone", rawURL: "https://[2001:db8::1%25eth0]/events", allowlist: "2001:db8::1"},
		{name: "trailing root dot", rawURL: "https://8.8.8.8./events", allowlist: "8.8.8.8"},
		{name: "two component IPv4 does not match different address", rawURL: "https://8.8/events", allowlist: "8.8.8.8", wantError: true},
		{name: "binary short component rejected as nonmatching hostname", rawURL: "https://0b1000.8/events", allowlist: "8.0.0.8", wantError: true},
		{name: "explicit octal short component rejected as nonmatching hostname", rawURL: "https://0o10.8/events", allowlist: "8.0.0.8", wantError: true},
		{name: "IPv4 bogus zone allowlist", rawURL: "https://10.0.0.1/events", allowlist: "10.0.0.1%x"},
		{name: "hostname percent rejected", rawURL: "https://api.vendor.example/events", allowlist: "api%zone.vendor.example", wantError: true},
		{name: "only one trailing root dot stripped", rawURL: "https://8.8.8.8../events", allowlist: "8.8.8.8", wantError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Emit.Forwarder = ForwarderConfig{
				URL: tc.rawURL, DestinationAllowlist: []string{tc.allowlist},
				SpoolFile: "/var/lib/pipelock/siem.spool", CursorFile: "/var/lib/pipelock/siem.cursor",
				MinSeverity: SeverityWarn, TimeoutSeconds: 5, QueueSize: 256,
			}
			err := cfg.Validate()
			if tc.wantError && err == nil {
				t.Fatal("Validate succeeded, want canonicalization rejection")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("Validate canonicalization: %v", err)
			}
		})
	}
}

func TestValidateForwarderTransportPolicyAllowsSafe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ForwarderConfig)
	}{
		{name: "loopback http with token", mutate: func(c *ForwarderConfig) {
			c.URL = "http://127.0.0.1/events"
			c.DestinationAllowlist = []string{"127.0.0.1"}
			c.AuthToken = "bearer"
		}},
		{name: "localhost http", mutate: func(c *ForwarderConfig) {
			c.URL = "http://localhost/events"
			c.DestinationAllowlist = []string{"localhost"}
		}},
		{name: "remote http with explicit insecure flag", mutate: func(c *ForwarderConfig) {
			c.URL = "http://api.vendor.example/events"
			c.AllowInsecureHTTP = true
		}},
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
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}
