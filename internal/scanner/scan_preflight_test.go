// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScanPreflight_RateLimitDoesNotReserve(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 2
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for range 2 {
		for range 3 {
			if got := s.ScanPreflight(t.Context(), "https://preview.vendor.example/page"); !got.Allowed {
				t.Fatalf("preflight consumed a slot: %+v", got)
			}
		}
		if got := s.Scan(t.Context(), "https://api.vendor.example/page"); !got.Allowed {
			t.Fatalf("actual request should fit the shared limit: %+v", got)
		}
	}
	preflight := s.ScanPreflight(t.Context(), "https://preview.vendor.example/page")
	actual := s.Scan(t.Context(), "https://preview.vendor.example/page")
	if preflight.Allowed || preflight.Scanner != ScannerRateLimit || preflight.Class != ClassProtective || preflight.Hint == "" || !reflect.DeepEqual(preflight, actual) {
		t.Fatalf("exhausted shared domain: preflight=%+v actual=%+v", preflight, actual)
	}
}

func TestScanPreflight_PreservesURLChecks(t *testing.T) {
	const target = "https://api.vendor.example/page"
	for _, tc := range []struct {
		name, target, want string
		configure          func(*config.Config)
		prepare            func(*Scanner)
	}{
		{name: "length", target: target + strings.Repeat("a", 200), want: ScannerLength},
		{name: "parser", target: ":invalid", want: ScannerParser},
		{name: "scheme", target: "ftp://api.vendor.example/page", want: ScannerScheme},
		{name: "allowlist", target: target, want: ScannerAllowlist, configure: func(cfg *config.Config) {
			cfg.Mode = config.ModeStrict
			cfg.APIAllowlist = []string{"other.example"}
		}},
		{name: "blocklist", target: target, want: ScannerBlocklist, configure: func(cfg *config.Config) {
			cfg.FetchProxy.Monitoring.Blocklist = []string{"api.vendor.example"}
		}},
		{name: "configured_dlp", target: target, want: ScannerDLP, configure: func(cfg *config.Config) {
			cfg.DLP.Patterns = []config.DLPPattern{{Name: "Synthetic page marker", Regex: "page"}}
		}},
		{name: "dns_policy", target: target, want: ScannerSSRF, configure: func(cfg *config.Config) {
			cfg.Internal = []string{"127.0.0.0/8"}
			cfg.SSRF.IPAllowlist = nil
		}, prepare: func(s *Scanner) {
			s.resolver = mapResolver{"api.vendor.example": {"127.0.0.1"}}
		}},
		{name: "data_budget", target: target, want: ScannerDataBudget, configure: func(cfg *config.Config) {
			cfg.FetchProxy.Monitoring.MaxDataPerMinute = 1
		}, prepare: func(s *Scanner) {
			s.RecordRequest("api.vendor.example", 1)
		}},
		{name: "allowed_dns_snapshot", target: target, want: ScannerAll, configure: func(cfg *config.Config) {
			cfg.Internal = []string{"127.0.0.0/8"}
		}, prepare: func(s *Scanner) {
			s.resolver = mapResolver{"api.vendor.example": {"93.184.216.34"}}
		}},
		{name: "rate_limit_disabled", target: target, want: ScannerAll, configure: func(cfg *config.Config) {
			cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.DLP.ScanEnv = false
			if tc.configure != nil {
				tc.configure(cfg)
			}
			s := MustNew(cfg)
			t.Cleanup(s.Close)
			if tc.prepare != nil {
				tc.prepare(s)
			}
			preflight := s.ScanPreflight(t.Context(), tc.target)
			actual := s.Scan(t.Context(), tc.target)
			if preflight.Scanner != tc.want || !reflect.DeepEqual(preflight, actual) {
				t.Fatalf("want %s, preflight=%+v actual=%+v", tc.want, preflight, actual)
			}
			if tc.want == ScannerAll && !preflight.Allowed {
				t.Fatal("clean destination blocked")
			}
			if tc.name == "allowed_dns_snapshot" && !reflect.DeepEqual(preflight.SSRFResolvedIPs, []string{"93.184.216.34"}) {
				t.Fatalf("preflight lost resolved addresses: %+v", preflight)
			}
		})
	}
}

func TestScanPreflight_ContextAndHeartbeat(t *testing.T) {
	s := MustNew(testConfig())
	t.Cleanup(s.Close)
	beats := 0
	s.SetHeartbeat(func() { beats++ })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		got := s.ScanPreflight(ctx, "https://api.vendor.example/page")
		if got.Allowed || got.Scanner != ScannerContext || got.Hint == "" {
			t.Fatalf("unavailable context did not fail closed with guidance: %+v", got)
		}
	}
	if got := s.ScanPreflight(t.Context(), "https://api.vendor.example/page"); !got.Allowed {
		t.Fatalf("valid context blocked: %+v", got)
	}
	if beats != 3 {
		t.Fatalf("heartbeat calls=%d, want 3", beats)
	}
}
