// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestCheckConfigAdvisoriesTLSInterceptionCoverage proves the HTTPS coverage-gap
// advisory reaches the check/doctor surface (not just the startup warning)
// whenever the forward proxy accepts CONNECT tunnels with interception off, and
// stays silent otherwise. It fires regardless of which content scanners are on.
func TestCheckConfigAdvisoriesTLSInterceptionCoverage(t *testing.T) {
	const marker = "does not inspect HTTPS request paths, bodies, or responses"

	tests := []struct {
		name   string
		mutate func(c *config.Config)
		want   bool
	}{
		{
			name:   "forward proxy off (default) does not advise",
			mutate: func(c *config.Config) {},
			want:   false,
		},
		{
			name:   "forward proxy on, interception off advises",
			mutate: func(c *config.Config) { c.ForwardProxy.Enabled = true },
			want:   true,
		},
		{
			name: "forward proxy on, interception on does not advise",
			mutate: func(c *config.Config) {
				c.ForwardProxy.Enabled = true
				c.TLSInterception.Enabled = true
			},
			want: false,
		},
		{
			name: "forward proxy on, interception off, content scanners off still advises",
			mutate: func(c *config.Config) {
				c.ForwardProxy.Enabled = true
				c.RequestBodyScanning.Enabled = false
				c.ResponseScanning.Enabled = false
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			tt.mutate(cfg)
			var found bool
			for _, advisory := range checkConfigAdvisories(cfg) {
				if strings.Contains(advisory, marker) {
					found = true
					break
				}
			}
			if found != tt.want {
				t.Fatalf("tls interception coverage advisory present = %v, want %v", found, tt.want)
			}
		})
	}
}

// TestDoctorTLSInterceptionCoverageAdvisory proves the dedicated doctor check
// warns with an accurate detail when interception is off, and clears to OK when
// interception is enabled.
func TestDoctorTLSInterceptionCoverageAdvisory(t *testing.T) {
	cfg := config.Defaults()
	cfg.ForwardProxy.Enabled = true

	report := buildDoctorReport(cfg, configLabelDefaults)
	check := doctorCheckFor(report, "tls_interception_coverage")
	if check.Status != doctorStatusWarn {
		t.Fatalf("doctor tls_interception_coverage status = %q, want %q; check=%+v", check.Status, doctorStatusWarn, check)
	}
	for _, want := range []string{"request_body_scanning", "response_scanning", "data budget", "require tls_interception"} {
		if !strings.Contains(check.Detail, want) {
			t.Fatalf("doctor tls_interception_coverage detail missing %q: %s", want, check.Detail)
		}
	}

	cfg.TLSInterception.Enabled = true
	report = buildDoctorReport(cfg, configLabelDefaults)
	check = doctorCheckFor(report, "tls_interception_coverage")
	if check.Status != doctorStatusOK {
		t.Fatalf("doctor tls_interception_coverage status with interception = %q, want %q; check=%+v", check.Status, doctorStatusOK, check)
	}
}
