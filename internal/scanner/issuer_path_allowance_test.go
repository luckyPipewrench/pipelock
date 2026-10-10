// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"
)

// An issuer path allowance relieves path-segment entropy for the exact escaped
// path it names and nothing else: DLP, SSRF and query entropy still run.
func TestScan_IssuerPathAllowanceRelievesOnlyPathEntropy(t *testing.T) {
	cfg := queryEntropyParamExclusionTestConfig()
	cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = nil
	s := MustNew(cfg)
	defer s.Close()

	const segment = "img-headshot-PriscillaMontgomery.Zk93mQ4vR7xT.webp"
	const highEntropy = "Zx9KqWvB3nMpLrT7yFhJ2dGsQ8aEcVbN4uXoIzPwRmKtYgD5fHl"
	secret := "AK" + "IA" + "Q9W8E7R6T5Y4U3I2"
	var asked []string
	allowing := func(want string) context.Context {
		return WithIssuerPathAllowance(context.Background(), func(escaped string) bool {
			asked = append(asked, escaped)
			return escaped == want
		})
	}
	tests := []struct {
		name      string
		ctx       context.Context
		url       string
		wantAllow bool
	}{
		{"no allowance", context.Background(), "https://www.vendor.example/media/" + segment, false},
		{"allowance for the exact path", allowing("/media/" + segment), "https://www.vendor.example/media/" + segment, true},
		{"allowance for another path", allowing("/media/other"), "https://www.vendor.example/media/" + segment, false},
		{"allowance for a prefix", allowing("/media/"), "https://www.vendor.example/media/" + segment, false},
		{"allowance does not relieve query entropy", allowing("/media/" + segment), "https://www.vendor.example/media/" + segment + "?x=" + highEntropy, false},
		{"allowance does not relieve DLP", allowing("/media/" + secret), "https://www.vendor.example/media/" + secret, false},
		{"allowance does not relieve SSRF", allowing("/media/" + segment), "https://169.254.169.254/media/" + segment, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Scan(tt.ctx, tt.url)
			if got.Allowed != tt.wantAllow {
				t.Fatalf("Allowed = %v (%s %s), want %v", got.Allowed, got.Scanner, got.Reason, tt.wantAllow)
			}
		})
	}
	if len(asked) == 0 {
		t.Fatal("the allowance was never consulted")
	}
}
