// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
)

const configGrantHost = "preview.vendor.example"

func configGrantFixture() *config.Config {
	cfg := config.Defaults()
	cfg.DestinationGrants = []config.DestinationGrant{{Protocol: "tcp", Host: configGrantHost, Port: 8443}}
	cfg.DNS.HostOverrides = map[string][]string{configGrantHost: {"127.0.0.1"}, "other.vendor.example": {"127.0.0.1"}}
	return cfg
}

func TestConfigDestinationGrantExactAndScannersRemainActive(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw          string
		mode               string
		noGrant, blocklist bool
		wantAllowed        bool
	}{
		{"exact", "https://preview.vendor.example:8443/", config.ModeBalanced, false, false, true},
		{"strict exact", "https://preview.vendor.example:8443/", config.ModeStrict, false, false, true},
		{"normalized", "https://PREVIEW.VENDOR.EXAMPLE.:8443/", config.ModeBalanced, false, false, true},
		{"wrong port", "https://preview.vendor.example:8444/", config.ModeBalanced, false, false, false},
		{"default port", "https://preview.vendor.example/", config.ModeBalanced, false, false, false},
		{"wrong host", "https://other.vendor.example:8443/", config.ModeBalanced, false, false, false},
		{"no grant", "https://preview.vendor.example:8443/", config.ModeBalanced, true, false, false},
		{"zero port", "https://preview.vendor.example:0/", config.ModeBalanced, false, false, false},
		{"blocklist", "https://preview.vendor.example:8443/", config.ModeBalanced, false, true, false},
		{"traversal", "https://preview.vendor.example:8443/../secret", config.ModeBalanced, false, false, false},
		{"CRLF", "https://preview.vendor.example:8443/?q=%0d%0aX-Test", config.ModeBalanced, false, false, false},
		{"DLP", "https://preview.vendor.example:8443/?key=" + "AKIA" + "IOSFODNN7EXAMPLE", config.ModeBalanced, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := configGrantFixture()
			cfg.Mode = tc.mode
			cfg.APIAllowlist = []string{"public.vendor.example"}
			if tc.noGrant {
				cfg.DestinationGrants = nil
			}
			if tc.blocklist {
				cfg.FetchProxy.Monitoring.Blocklist = []string{configGrantHost}
			}
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			result := s.Scan(context.Background(), tc.raw)
			if result.Allowed != tc.wantAllowed {
				t.Fatalf("Scan = %+v, want allowed=%t", result, tc.wantAllowed)
			}
			if result.Allowed && len(result.SSRFResolvedIPs) != 1 {
				t.Fatal("granted DNS answer missing from dial snapshot")
			}
		})
	}
}

func TestConfigDestinationGrantDNSFloor(t *testing.T) {
	t.Parallel()
	for _, ips := range [][]string{
		{"169.254.169.254"},
		{"::ffff:169.254.169.254"},
		{"169.254.1.2"},
		{"fe80::1"},
		{"224.0.0.1"},
		{"0.0.0.0"},
		{"::"},
		{"127.0.0.1", "169.254.169.254"},
	} {
		t.Run(ips[0], func(t *testing.T) {
			cfg := configGrantFixture()
			cfg.Internal = nil
			cfg.DNS.HostOverrides[configGrantHost] = ips
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if got := s.Scan(context.Background(), "https://preview.vendor.example:8443/"); got.Allowed {
				t.Fatalf("grant overrode protected DNS answer: %+v", got)
			}
		})
	}
}

func TestConfigDestinationGrantConstructionFailsClosed(t *testing.T) {
	t.Parallel()
	cfg := configGrantFixture()
	cfg.DestinationGrants = append(cfg.DestinationGrants, config.DestinationGrant{Protocol: "tcp", Host: "*.vendor.example", Port: 8443})
	if s, err := New(cfg); err == nil {
		s.Close()
		t.Fatal("unvalidated malformed config installed a partial grant set")
	}
}

func TestConfigDestinationGrantLiteralIsExact(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.DestinationGrants = []config.DestinationGrant{{Protocol: "tcp", Host: "127.0.0.1", Port: 8443}}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tc := range []struct {
		raw     string
		allowed bool
	}{
		{"https://127.0.0.1:8443/", true},
		{"https://127.0.0.1:8444/", false},
		{"https://127.0.0.2:8443/", false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			if got := s.Scan(context.Background(), tc.raw); got.Allowed != tc.allowed {
				t.Fatalf("literal scan=%+v, allowed=%t", got, tc.allowed)
			}
		})
	}
}

func TestConfigDestinationGrantRuntimeOverlayIsImmutable(t *testing.T) {
	t.Parallel()
	cfg := configGrantFixture()
	g, err := destination.NewGrant(destination.NetworkTCP, "runtime.vendor.example", 5432)
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := destination.NewGrantSet(g)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithOptions(cfg, Options{DestinationGrants: overlay})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, dest := range []destination.Destination{
		{Network: destination.NetworkTCP, Host: configGrantHost, Port: 8443},
		g.Destination(),
	} {
		if !s.IsDestinationGranted(dest.Network, dest.Host, dest.Port) {
			t.Fatalf("missing grant: %+v", dest)
		}
	}
	plain, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if plain.IsDestinationGranted(destination.NetworkTCP, "runtime.vendor.example", 5432) {
		t.Fatal("runtime overlay mutated ordinary configuration")
	}
	if overlay.Len() != 1 || len(cfg.DestinationGrants) != 1 {
		t.Fatal("union mutated inputs")
	}
}

// An empty internal list disables ordinary SSRF resolution. A grant must not
// switch it back on for destinations that carry no grant.
func TestConfigDestinationGrantDoesNotEnableSSRFForOtherHosts(t *testing.T) {
	t.Parallel()
	cfg := configGrantFixture()
	cfg.Internal = nil
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.Scan(context.Background(), "https://other.vendor.example/"); !got.Allowed {
		t.Fatalf("grant for another destination enabled SSRF blocking: %+v", got)
	}
	if got := s.Scan(context.Background(), "https://preview.vendor.example:8443/"); !got.Allowed || len(got.SSRFResolvedIPs) != 1 {
		t.Fatalf("granted destination lost its dial snapshot: %+v", got)
	}
}
