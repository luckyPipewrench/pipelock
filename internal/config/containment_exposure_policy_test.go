// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net"
	"strings"
	"testing"
	"time"
)

func validExposure(now time.Time) *ContainmentMetricsExposure {
	return &ContainmentMetricsExposure{
		AllowFullMetrics:   true,
		AllowedSourceCIDRs: []string{"10.20.0.42/32"},
		Owner:              "observability",
		Reason:             "workstation scrape",
		ExpiresAt:          now.Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
}

// TestContainmentMetricsExposureRejectsUnusablePolicy pins each way a declared
// exposure fails to be a real declaration.
//
// This policy widens a containment control, so the value of the fields is the
// whole point: an exposure with no owner, no reason or no expiry is an
// exception nobody can review later, and one that names every source is not an
// exception at all.
func TestContainmentMetricsExposureRejectsUnusablePolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const listen = "10.20.0.20:9091"
	const proxyPort = 8888

	tests := []struct {
		name   string
		mutate func(p *ContainmentMetricsExposure)
		want   string
	}{
		{
			name:   "a source that is not a CIDR",
			mutate: func(p *ContainmentMetricsExposure) { p.AllowedSourceCIDRs = []string{"10.20.0.42"} },
			want:   "is invalid",
		},
		{
			name:   "a host address written as a network",
			mutate: func(p *ContainmentMetricsExposure) { p.AllowedSourceCIDRs = []string{"10.20.0.42/24"} },
			want:   "must use a network address",
		},
		{
			// An exposure open to everything is indistinguishable from no rule,
			// which is the state this vocabulary exists to replace.
			name:   "every IPv4 source",
			mutate: func(p *ContainmentMetricsExposure) { p.AllowedSourceCIDRs = []string{"0.0.0.0/0"} },
			want:   "must not allow every source",
		},
		{
			name:   "every IPv6 source",
			mutate: func(p *ContainmentMetricsExposure) { p.AllowedSourceCIDRs = []string{"::/0"} },
			want:   "must not allow every source",
		},
		{
			name:   "no sources at all",
			mutate: func(p *ContainmentMetricsExposure) { p.AllowedSourceCIDRs = nil },
			want:   "must name at least one source",
		},
		{
			name:   "expiry that already passed",
			mutate: func(p *ContainmentMetricsExposure) { p.ExpiresAt = now.Add(-time.Hour).UTC().Format(time.RFC3339) },
			want:   "expired at",
		},
		{
			name:   "expiry that is not a timestamp",
			mutate: func(p *ContainmentMetricsExposure) { p.ExpiresAt = "next tuesday" },
			want:   "RFC3339",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := validExposure(now)
			tt.mutate(policy)
			err := ValidateContainmentMetricsExposure(listen, proxyPort, policy, now)
			if err == nil {
				t.Fatal("an unusable exposure policy was accepted")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tt.want)
			}
		})
	}

	t.Run("a complete policy is accepted", func(t *testing.T) {
		if err := ValidateContainmentMetricsExposure(listen, proxyPort, validExposure(now), now); err != nil {
			t.Fatalf("a complete policy was refused: %v", err)
		}
	})
}

// TestContainmentMetricsExposureRefusesAPolicyOnALoopbackListener covers the
// combination that means the operator misunderstood the feature: an exposure
// declared for a listener nothing remote can reach anyway.
func TestContainmentMetricsExposureRefusesAPolicyOnALoopbackListener(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	err := ValidateContainmentMetricsExposure("127.0.0.1:9091", 8888, validExposure(now), now)
	if err == nil {
		t.Fatal("an exposure policy was accepted for a loopback listener")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Errorf("error = %q, want it to say the policy needs a non-loopback listener", err.Error())
	}
}

// TestContainmentMetricsExposureAllowsSourceDeniesOnAnythingUnusable pins the
// runtime side. It answers a per-request question, so anything it cannot
// evaluate has to mean no.
func TestContainmentMetricsExposureAllowsSourceDeniesOnAnythingUnusable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	policy := validExposure(now)

	tests := []struct {
		name   string
		policy *ContainmentMetricsExposure
		source net.IP
		want   bool
	}{
		{"nil policy", nil, net.ParseIP("10.20.0.42"), false},
		{"nil source", policy, nil, false},
		{"source outside every range", policy, net.ParseIP("10.20.0.99"), false},
		{"source inside a range", policy, net.ParseIP("10.20.0.42"), true},
		{
			// A malformed entry is skipped rather than treated as a wildcard, and
			// a later valid entry still decides.
			name: "an unparsable entry does not open the range",
			policy: &ContainmentMetricsExposure{
				AllowedSourceCIDRs: []string{"not-a-cidr", "10.20.0.42/32"},
			},
			source: net.ParseIP("10.20.0.99"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainmentMetricsExposureAllowsSource(tt.policy, tt.source); got != tt.want {
				t.Errorf("allowed = %v, want %v", got, tt.want)
			}
		})
	}
}
