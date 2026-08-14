// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestContainmentMetricsRequestAllowedRefusesUnusableInput covers every way the
// decision can fail to establish that a request is permitted.
//
// This function answers one question, may this caller read the metrics, and its
// only safe default is no. Each branch below returns false because something
// could not be determined rather than because a rule said deny, and an
// undetermined answer resolving to yes is how a policy check becomes decoration.
func TestContainmentMetricsRequestAllowedRefusesUnusableInput(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	valid := &config.ContainmentMetricsExposure{
		AllowFullMetrics:   true,
		AllowedSourceCIDRs: []string{"10.20.0.42/32"},
		Owner:              "observability",
		Reason:             "workstation scrape",
		ExpiresAt:          now.Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}

	withConfig := func(fetchListen, metricsListen string, policy *config.ContainmentMetricsExposure) *config.Config {
		c := config.Defaults()
		c.ApplyDefaults()
		c.FetchProxy.Listen = fetchListen
		c.MetricsListen = metricsListen
		c.Containment.MetricsExposure = policy
		return c
	}

	tests := []struct {
		name   string
		cfg    *config.Config
		remote string
		want   bool
	}{
		{"nil config", nil, "10.20.0.42:5000", false},
		{
			"unparsable proxy listener",
			withConfig("not-a-host-port", "10.20.0.20:9091", valid),
			"10.20.0.42:5000", false,
		},
		{
			"non-numeric proxy port",
			withConfig("127.0.0.1:proxy", "10.20.0.20:9091", valid),
			"10.20.0.42:5000", false,
		},
		{
			"proxy port out of range",
			withConfig("127.0.0.1:70000", "10.20.0.20:9091", valid),
			"10.20.0.42:5000", false,
		},
		{
			"no exposure policy for a routable listener",
			withConfig("127.0.0.1:8888", "10.20.0.20:9091", nil),
			"10.20.0.42:5000", false,
		},
		{
			"remote address is not host:port",
			withConfig("127.0.0.1:8888", "10.20.0.20:9091", valid),
			"garbage", false,
		},
		{
			"remote host is not an IP",
			withConfig("127.0.0.1:8888", "10.20.0.20:9091", valid),
			"scraper.internal:5000", false,
		},
		{
			"metrics listener is not host:port",
			withConfig("127.0.0.1:8888", "not-a-host-port", valid),
			"10.20.0.42:5000", false,
		},
		{
			"metrics host is not an IP",
			withConfig("127.0.0.1:8888", "localhost:9091", valid),
			"10.20.0.42:5000", false,
		},
		{
			// A loopback listener answers loopback callers and nobody else,
			// whatever the policy says. The policy governs a routable listener.
			"loopback listener refuses a remote caller",
			withConfig("127.0.0.1:8888", "127.0.0.1:9091", valid),
			"10.20.0.42:5000", false,
		},
		{
			"loopback listener allows a loopback caller",
			withConfig("127.0.0.1:8888", "127.0.0.1:9091", nil),
			"127.0.0.1:5000", true,
		},
		{
			"routable listener allows a declared source",
			withConfig("127.0.0.1:8888", "10.20.0.20:9091", valid),
			"10.20.0.42:5000", true,
		},
		{
			"routable listener refuses an undeclared source",
			withConfig("127.0.0.1:8888", "10.20.0.20:9091", valid),
			"10.20.0.99:5000", false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containmentMetricsRequestAllowed(tt.cfg, tt.remote, now); got != tt.want {
				t.Errorf("allowed = %v, want %v", got, tt.want)
			}
		})
	}
}
