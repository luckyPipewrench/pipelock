// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func pathEntropyFindings(t *testing.T, mutate func(*config.Config)) []ConfigSemanticFinding {
	t.Helper()
	cfg := config.Defaults()
	cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
		Reason:     "service-issued document identifier",
		Owner:      "platform",
		Expires:    "2099-01-01",
	}}
	if mutate != nil {
		mutate(cfg)
	}
	return analyzeDoctorPathEntropyExclusions(cfg)
}

func findingDetails(findings []ConfigSemanticFinding) string {
	var b strings.Builder
	for _, f := range findings {
		b.WriteString(f.Kind)
		b.WriteString(": ")
		b.WriteString(f.Detail)
		b.WriteString("\n")
	}
	return b.String()
}

// Control. A complete, live entry produces nothing, so every finding below is
// attributable to the one thing that case changed rather than to the fixture.
func TestDoctorPathEntropyExclusions_CompleteEntryIsQuiet(t *testing.T) {
	t.Parallel()
	if got := pathEntropyFindings(t, nil); len(got) != 0 {
		t.Fatalf("a fully specified unexpired entry produced findings:\n%s", findingDetails(got))
	}
	if got := analyzeDoctorPathEntropyExclusions(config.Defaults()); len(got) != 0 {
		t.Fatalf("an unconfigured list produced findings:\n%s", findingDetails(got))
	}
}

func TestDoctorPathEntropyExclusions_ReportsStaleAndInertEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*config.Config)
		want   string
		why    string
	}{
		{
			name:   "entropy disabled makes the exemption inert",
			mutate: func(c *config.Config) { c.FetchProxy.Monitoring.EntropyThreshold = 0 },
			want:   "is inert",
			why:    "an exemption from a gate that never runs is dead config the operator should see",
		},
		{
			name: "a host-wide subdomain exclusion already covers the path gate",
			mutate: func(c *config.Config) {
				c.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"*.vendor.example"}
			},
			want: "redundant because subdomain_entropy_exclusions",
			why:  "that list drives the path gate too, so the broad one is the entry to remove",
		},
		{
			name:   "a missing owner leaves nobody to revalidate",
			mutate: func(c *config.Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].Owner = "" },
			want:   "missing advisory owner",
		},
		{
			name:   "a missing reason loses why the route was exempted",
			mutate: func(c *config.Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].Reason = "" },
			want:   "missing advisory reason",
		},
		{
			name:   "no expiry means no review date",
			mutate: func(c *config.Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].Expires = "" },
			want:   "missing advisory expires",
		},
		{
			name:   "an unparseable expiry is reported rather than ignored",
			mutate: func(c *config.Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].Expires = "next year" },
			want:   "invalid expires",
		},
		{
			name:   "a passed expiry is reported and the entry still applies",
			mutate: func(c *config.Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].Expires = "2020-01-01" },
			want:   "expired on 2020-01-01; it is still in force",
			why:    "nothing revokes an expired exemption, so the wording must not imply it lapsed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := findingDetails(pathEntropyFindings(t, tt.mutate))
			if !strings.Contains(got, tt.want) {
				t.Fatalf("expected a finding containing %q (%s), got:\n%s", tt.want, tt.why, got)
			}
		})
	}
}
