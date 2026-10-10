// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The validator accepts one trailing slash and the matcher compares the
// escaped request path exactly, so /_next/image/ and /_next/image are two
// different endpoints and an exclusion names only the spelling it was given.
func TestScan_QueryEntropyParamExclusion_TrailingSlashAgreesWithValidator(t *testing.T) {
	const highEntropy = "Zx9KqWvB3nMpLrT7yFhJ2dGsQ8aEcVbN4uXoIzPwRmKtYgD5fHl"
	tests := []struct {
		name      string
		configure string
		url       string
		wantAllow bool
	}{
		{"slash exclusion allows slash route", "/_next/image/", "https://www.vendor.example/_next/image/?url=" + highEntropy, true},
		{"slash exclusion does not cover slashless route", "/_next/image/", "https://www.vendor.example/_next/image?url=" + highEntropy, false},
		{"slashless exclusion does not cover slash route", "/_next/image", "https://www.vendor.example/_next/image/?url=" + highEntropy, false},
		{"slashless exclusion allows slashless route", "/_next/image", "https://www.vendor.example/_next/image?url=" + highEntropy, true},
		{"slash exclusion does not cover a child route", "/_next/image/", "https://www.vendor.example/_next/image/x?url=" + highEntropy, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.DLP.Patterns = nil
			cfg.FetchProxy.Monitoring.Blocklist = nil
			cfg.FetchProxy.Monitoring.EntropyThreshold = 4.5
			entries := []config.QueryEntropyParamExclusion{{Host: "www.vendor.example", Path: tt.configure, Param: "url"}}
			// Run the real validator first: the exclusion must be one an
			// operator can actually write, which used to be impossible.
			cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = entries
			if err := cfg.Validate(); err != nil {
				t.Fatalf("validator refused %q: %v", tt.configure, err)
			}
			s := MustNew(cfg)
			defer s.Close()
			got := s.Scan(context.Background(), tt.url)
			if got.Allowed != tt.wantAllow {
				t.Fatalf("Allowed = %v (%s), want %v", got.Allowed, got.Reason, tt.wantAllow)
			}
		})
	}
}
