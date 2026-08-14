// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// TestValidateContainmentMetricsListenRefusals covers every refusal branch.
//
// The error paths are the point of this validator: each one is a distinct way an
// operator edit can leave the containment contract, and each returns different
// remediation text. The empty case matters most, because deleting the key does not
// disable metrics, it moves them onto the agent-accessible proxy port.
func TestValidateContainmentMetricsListenRefusals(t *testing.T) {
	const proxyPort = 8888

	tests := []struct {
		name       string
		listen     string
		wantErr    bool
		wantDetail string
	}{
		{
			name:       "empty is refused and says not to delete the key",
			listen:     "",
			wantErr:    true,
			wantDetail: "do not delete the key",
		},
		{
			name:       "whitespace only is treated as empty",
			listen:     "   ",
			wantErr:    true,
			wantDetail: "do not delete the key",
		},
		{
			name:       "unparseable address",
			listen:     "not-a-host-port",
			wantErr:    true,
			wantDetail: "unsafe for containment",
		},
		{
			name:       "LAN address",
			listen:     "192.0.2.20:9091",
			wantErr:    true,
			wantDetail: "metrics_exposure",
		},
		{
			name:       "wildcard address",
			listen:     "0.0.0.0:9091",
			wantErr:    true,
			wantDetail: "wildcard binds",
		},
		{
			name:       "hostname rather than a numeric address",
			listen:     "localhost:9091",
			wantErr:    true,
			wantDetail: "numeric address, not a hostname",
		},
		{
			name:       "loopback on the proxy port is refused",
			listen:     "127.0.0.1:8888",
			wantErr:    true,
			wantDetail: "other than the agent-accessible proxy port",
		},
		{
			name:       "port zero",
			listen:     "127.0.0.1:0",
			wantErr:    true,
			wantDetail: "other than the agent-accessible proxy port",
		},
		{
			name:       "non-numeric port",
			listen:     "127.0.0.1:metrics",
			wantErr:    true,
			wantDetail: "unsafe for containment",
		},
		{name: "loopback IPv4 on a dedicated port", listen: "127.0.0.1:9091"},
		{name: "loopback IPv6 on a dedicated port", listen: "[::1]:9091"},
		{name: "an alternate loopback address", listen: "127.0.0.2:9091"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainmentMetricsListen(tt.listen, proxyPort)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateContainmentMetricsListen(%q) = nil, want a refusal", tt.listen)
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("ValidateContainmentMetricsListen(%q) = %v, want nil", tt.listen, err)
				}
				return
			}
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Errorf("error %q does not carry the remediation %q; an operator reads this to know what to change",
					err.Error(), tt.wantDetail)
			}
		})
	}
}

func TestValidateContainmentMetricsExposurePolicy(t *testing.T) {
	now := time.Date(2026, time.August, 14, 12, 0, 0, 0, time.UTC)
	valid := &ContainmentMetricsExposure{
		AllowFullMetrics:   true,
		AllowedSourceCIDRs: []string{"192.0.2.42/32"},
		Owner:              "observability",
		Reason:             "Prometheus scrape",
		ExpiresAt:          "2026-08-15T12:00:00Z",
	}
	tests := []struct {
		name       string
		policy     *ContainmentMetricsExposure
		wantDetail string
	}{
		{name: "complete current policy", policy: valid},
		{name: "absent policy", wantDetail: "requires containment.metrics_exposure"},
		{name: "allow is not explicit", policy: &ContainmentMetricsExposure{AllowedSourceCIDRs: valid.AllowedSourceCIDRs, Owner: valid.Owner, Reason: valid.Reason, ExpiresAt: valid.ExpiresAt}, wantDetail: "allow_full_metrics"},
		{name: "missing owner", policy: &ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: valid.AllowedSourceCIDRs, Reason: valid.Reason, ExpiresAt: valid.ExpiresAt}, wantDetail: "owner is required"},
		{name: "missing reason", policy: &ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: valid.AllowedSourceCIDRs, Owner: valid.Owner, ExpiresAt: valid.ExpiresAt}, wantDetail: "reason is required"},
		{name: "malformed expiry", policy: &ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: valid.AllowedSourceCIDRs, Owner: valid.Owner, Reason: valid.Reason, ExpiresAt: "tomorrow"}, wantDetail: "expires_at must use RFC3339"},
		{name: "expired", policy: &ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: valid.AllowedSourceCIDRs, Owner: valid.Owner, Reason: valid.Reason, ExpiresAt: "2026-08-14T12:00:00Z"}, wantDetail: "expired at"},
		{name: "malformed source CIDR", policy: &ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: []string{"not-a-cidr"}, Owner: valid.Owner, Reason: valid.Reason, ExpiresAt: valid.ExpiresAt}, wantDetail: "is invalid"},
		{name: "source CIDR with host bits", policy: &ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: []string{"192.0.2.42/24"}, Owner: valid.Owner, Reason: valid.Reason, ExpiresAt: valid.ExpiresAt}, wantDetail: "network address"},
		{name: "all sources", policy: &ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: []string{"0.0.0.0/0"}, Owner: valid.Owner, Reason: valid.Reason, ExpiresAt: valid.ExpiresAt}, wantDetail: "must not allow every source"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainmentMetricsExposure("192.0.2.20:9091", 8888, tt.policy, now)
			if tt.wantDetail == "" {
				if err != nil {
					t.Fatalf("ValidateContainmentMetricsExposure = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantDetail) {
				t.Fatalf("ValidateContainmentMetricsExposure = %v, want error containing %q", err, tt.wantDetail)
			}
		})
	}
}
