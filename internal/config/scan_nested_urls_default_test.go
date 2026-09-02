// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// scan_nested_urls decides whether URL-shaped query values are evaluated as
// destinations, so its zero value is a security posture rather than a
// convenience default. The repo requires the full matrix for a field like
// this: omitted, YAML null, blank, explicit false, explicit true, and a
// reload in both directions.
func TestScanNestedURLsParsingMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		yaml string
		want bool
	}{
		{name: "omitted defaults to enabled", yaml: "mode: balanced\nfetch_proxy:\n  monitoring:\n    entropy_threshold: 4.5\n", want: true},
		{name: "yaml null defaults to enabled", yaml: "mode: balanced\nfetch_proxy:\n  monitoring:\n    scan_nested_urls:\n", want: true},
		{name: "explicit false disables", yaml: "mode: balanced\nfetch_proxy:\n  monitoring:\n    scan_nested_urls: false\n", want: false},
		{name: "explicit true enables", yaml: "mode: balanced\nfetch_proxy:\n  monitoring:\n    scan_nested_urls: true\n", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.FetchProxy.Monitoring.NestedURLScanningEnabled(); got != tc.want {
				t.Fatalf("NestedURLScanningEnabled = %v, want %v (ptr=%v)", got, tc.want, cfg.FetchProxy.Monitoring.ScanNestedURLs)
			}
		})
	}
}

// A reload must move the value in both directions. Re-enabling matters most:
// an operator who disabled nested URL scanning to get past one endpoint and
// then removed the override should not keep the relaxed posture until the
// process restarts.
func TestScanNestedURLsReloadBothDirections(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")

	write := func(body string) *Config {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return cfg
	}

	if got := write("mode: balanced\nfetch_proxy:\n  monitoring:\n    scan_nested_urls: false\n").FetchProxy.Monitoring.NestedURLScanningEnabled(); got {
		t.Fatalf("initial load = %v, want false", got)
	}
	if got := write("mode: balanced\nfetch_proxy:\n  monitoring:\n    scan_nested_urls: true\n").FetchProxy.Monitoring.NestedURLScanningEnabled(); !got {
		t.Fatalf("reload to true = %v, want true", got)
	}
	if got := write("mode: balanced\nfetch_proxy:\n  monitoring:\n    scan_nested_urls: true\n").FetchProxy.Monitoring.NestedURLScanningEnabled(); !got {
		t.Fatalf("reload with no change = %v, want true", got)
	}
	if got := write("mode: balanced\nfetch_proxy:\n  monitoring:\n    scan_nested_urls: false\n").FetchProxy.Monitoring.NestedURLScanningEnabled(); got {
		t.Fatalf("reload back to false = %v, want false; a relaxed posture must not persist", got)
	}
}

func TestValidateReload_ScanNestedURLsDisabled(t *testing.T) {
	t.Parallel()

	old := Defaults()
	updated := Defaults()
	disabled := false
	updated.FetchProxy.Monitoring.ScanNestedURLs = &disabled

	var found bool
	for _, warning := range ValidateReload(old, updated) {
		if warning.Field == "fetch_proxy.monitoring.scan_nested_urls" {
			found = true
			if warning.Message == "" {
				t.Fatal("reload warning message is empty")
			}
		}
	}
	if !found {
		t.Fatal("disabling nested URL scanning must warn as a security downgrade")
	}

	same := Defaults()
	for _, warning := range ValidateReload(old, same) {
		if warning.Field == "fetch_proxy.monitoring.scan_nested_urls" {
			t.Fatalf("unchanged nested URL scanning warned: %+v", warning)
		}
	}

	enabled := true
	old.FetchProxy.Monitoring.ScanNestedURLs = &disabled
	updated.FetchProxy.Monitoring.ScanNestedURLs = &enabled
	for _, warning := range ValidateReload(old, updated) {
		if warning.Field == "fetch_proxy.monitoring.scan_nested_urls" {
			t.Fatalf("re-enabling nested URL scanning warned: %+v", warning)
		}
	}
}
