// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type mapResolver map[string][]string

func (m mapResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return m[host], nil
}

// A DNS filter answers a blocked name with the unspecified address. That
// answer is still refused, but as an infrastructure result that adaptive
// enforcement does not score, so a filtered tracker retrying in a browser
// cannot escalate the session. Any other floor address keeps the threat
// verdict.
func TestScanURL_DNSSinkholeAnswer(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8"}
	s := MustNew(cfg)
	defer s.Close()
	s.resolver = mapResolver{
		"v4.sinkhole.example":    {"0.0.0.0"},
		"v6.sinkhole.example":    {"::"},
		"both.sinkhole.example":  {"0.0.0.0", "::"},
		"metadata.mixed.example": {"0.0.0.0", "169.254.169.254"},
		"loopback.mixed.example": {"::", "127.0.0.1"},
		"public.mixed.example":   {"0.0.0.0", "93.184.216.34"},
	}
	for _, tc := range []struct {
		host       string
		wantInfra  bool
		wantKind   DNSErrorKind
		wantThreat bool
	}{
		{"v4.sinkhole.example", true, DNSErrorSinkhole, false},
		{"v6.sinkhole.example", true, DNSErrorSinkhole, false},
		{"both.sinkhole.example", true, DNSErrorSinkhole, false},
		{"metadata.mixed.example", false, "", true},
		{"loopback.mixed.example", false, "", true},
		{"public.mixed.example", false, "", true},
	} {
		t.Run(tc.host, func(t *testing.T) {
			r := s.Scan(context.Background(), "https://"+tc.host+"/")
			if r.Allowed {
				t.Fatalf("%s must stay blocked: %+v", tc.host, r)
			}
			if r.IsInfrastructureError() != tc.wantInfra || r.DNSErrorKind != tc.wantKind {
				t.Fatalf("%s: infra=%v kind=%q reason=%q", tc.host, r.IsInfrastructureError(), r.DNSErrorKind, r.Reason)
			}
			if tc.wantThreat && r.IsAdaptiveNeutral() {
				t.Fatalf("%s must still score as a threat: %q", tc.host, r.Reason)
			}
		})
	}
	// A literal unspecified address in the URL is not a DNS answer and keeps
	// the threat verdict.
	if r := s.Scan(context.Background(), "https://0.0.0.0/"); r.Allowed || r.IsAdaptiveNeutral() {
		t.Fatalf("literal 0.0.0.0 must block as a threat: %+v", r)
	}
}
