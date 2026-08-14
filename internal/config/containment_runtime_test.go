// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestConfigClone_ContainmentMetricsExposureDoesNotAlias(t *testing.T) {
	original := Defaults()
	original.Containment.MetricsExposure = &ContainmentMetricsExposure{
		AllowFullMetrics:   true,
		AllowedSourceCIDRs: []string{"192.0.2.42/32"},
		Owner:              "observability",
		Reason:             "Prometheus scrape",
		ExpiresAt:          "2026-08-15T12:00:00Z",
	}

	clone := original.Clone()
	clone.Containment.MetricsExposure.Owner = "platform"
	clone.Containment.MetricsExposure.AllowedSourceCIDRs[0] = "192.0.2.43/32"

	if original.Containment.MetricsExposure.Owner != "observability" {
		t.Fatalf("original owner = %q, want observability", original.Containment.MetricsExposure.Owner)
	}
	if original.Containment.MetricsExposure.AllowedSourceCIDRs[0] != "192.0.2.42/32" {
		t.Fatalf("original allowed source = %q, want independent clone", original.Containment.MetricsExposure.AllowedSourceCIDRs[0])
	}
}
