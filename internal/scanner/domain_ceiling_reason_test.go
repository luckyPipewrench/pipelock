// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
)

// TestDomainCeilingReason covers the reason text for base domains,
// subdomains, public suffixes, IP literals, and single-label hosts.
func TestDomainCeilingReason(t *testing.T) {
	tests := []struct {
		name, host, want string
	}{
		{"base domain", "example.com", "rate limit exceeded for example.com"},
		{"subdomain", "cable.example.com", "rate limit exceeded for example.com (shared by example.com and all its subdomains; request to cable.example.com)"},
		{"public suffix", "a.b.example.co.uk", "rate limit exceeded for example.co.uk (shared by example.co.uk and all its subdomains; request to a.b.example.co.uk)"},
		{"ipv4", "192.0.2.10", "rate limit exceeded for 192.0.2.10"},
		{"single label", "localhost", "rate limit exceeded for localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domainCeilingReason("rate limit", tt.host); got != tt.want {
				t.Fatalf("got %q\nwant %q", got, tt.want)
			}
		})
	}
}

// A sibling subdomain exhausts the shared budget; the block must name the
// base domain that was counted, not only the host that happened to be refused.
func TestCheckRateLimit_SubdomainsShareBaseDomainBudget(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 1
	s := MustNew(cfg)
	defer s.Close()

	if r := s.Scan(context.Background(), "https://api.example.com/v1"); !r.Allowed {
		t.Fatalf("first request should be allowed: %s", r.Reason)
	}
	r := s.Scan(context.Background(), "https://cable.example.com/socket")
	if r.Allowed {
		t.Fatal("sibling subdomain should share the exhausted budget")
	}
	if r.Scanner != ScannerRateLimit {
		t.Fatalf("scanner = %q, want %q", r.Scanner, ScannerRateLimit)
	}
	if !strings.Contains(r.Reason, "exceeded for example.com (shared by example.com") ||
		!strings.Contains(r.Reason, "request to cable.example.com") {
		t.Fatalf("reason does not name the counted base domain and requested host: %q", r.Reason)
	}
}

// The data budget counts by base domain too: bytes recorded through one
// subdomain exhaust the budget a sibling subdomain then hits, and the block
// names the counted base domain and the requested host.
func TestCheckDataBudget_SubdomainsShareBaseDomainBudget(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 100
	s := MustNew(cfg)
	defer s.Close()

	s.RecordRequest("api.example.com", 150)
	r := s.Scan(context.Background(), "https://cable.example.com/socket")
	if r.Allowed {
		t.Fatal("sibling subdomain should share the exhausted data budget")
	}
	if r.Scanner != ScannerDataBudget {
		t.Fatalf("scanner = %q, want %q", r.Scanner, ScannerDataBudget)
	}
	if !strings.Contains(r.Reason, "data budget exceeded for example.com (shared by example.com") ||
		!strings.Contains(r.Reason, "request to cable.example.com") {
		t.Fatalf("reason does not name the counted base domain and requested host: %q", r.Reason)
	}
}

// TestRateLimitHintsNamePerAgentOverride checks both ceiling hints name the
// base-domain scope and the per-agent override.
func TestRateLimitHintsNamePerAgentOverride(t *testing.T) {
	for _, sc := range []string{ScannerRateLimit, ScannerDataBudget} {
		hint := OperatorHintForResult(sc, "")
		for _, want := range []string{"base domain", "agents.<name>.rate_limit", "replaces both"} {
			if !strings.Contains(hint, want) {
				t.Errorf("%s hint missing %q: %s", sc, want, hint)
			}
		}
	}
}
