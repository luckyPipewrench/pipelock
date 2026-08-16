// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestEffectiveURLPortDefaults(t *testing.T) {
	t.Parallel()

	if got := effectiveURLPort(nil); got != "" {
		t.Fatalf("nil URL port = %q", got)
	}
	must := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", raw, err)
		}
		return u
	}
	if got := effectiveURLPort(must("https://api.vendor.example/x")); got != "443" {
		t.Fatalf("https default = %q", got)
	}
	if got := effectiveURLPort(must("http://api.vendor.example/x")); got != "80" {
		t.Fatalf("http default = %q", got)
	}
	if got := effectiveURLPort(must("wss://api.vendor.example/x")); got != "443" {
		t.Fatalf("wss default = %q", got)
	}
	if got := effectiveURLPort(must("ws://api.vendor.example/x")); got != "80" {
		t.Fatalf("ws default = %q", got)
	}
	if got := effectiveURLPort(must("ftp://api.vendor.example/x")); got != "" {
		t.Fatalf("unknown scheme = %q", got)
	}
	if got := effectiveURLPort(must("https://api.vendor.example:8443/x")); got != "8443" {
		t.Fatalf("explicit port = %q", got)
	}
}

func TestWithAllowedSSRFDialScanSnapshotClearsOnDeny(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var parent context.Context
	if got := withAllowedSSRFDialScanSnapshot(parent, nil, "api.vendor.example", "443", scanner.Result{}); got != nil {
		t.Fatal("nil parent must stay nil")
	}
	cleared := withAllowedSSRFDialScanSnapshot(ctx, new(scanner.Scanner), "api.vendor.example", "443", scanner.Result{
		Allowed:         false,
		SSRFResolvedIPs: []string{"203.0.113.10"},
	})
	if isSSRFDNSRebind(cleared, "api.vendor.example", net.ParseIP("127.0.0.1")) {
		t.Fatal("denied snapshot still labeled a rebind")
	}
	if ssrfDialSnapshotContains(cleared, "api.vendor.example", net.ParseIP("203.0.113.10")) {
		t.Fatal("denied snapshot still contained the scan IP")
	}
}

func TestSSRFDialPortMismatchDoesNotVouch(t *testing.T) {
	t.Parallel()

	ctx := withSSRFDialScanSnapshot(context.Background(), "api.vendor.example", "443", []string{"203.0.113.10"})
	ctx = withSSRFDialPort(ctx, "6443")
	if isSSRFDNSRebind(ctx, "api.vendor.example", net.ParseIP("127.0.0.1")) {
		t.Fatal("port-mismatched snapshot labeled a rebind")
	}
	if ssrfDialSnapshotContains(ctx, "api.vendor.example", net.ParseIP("203.0.113.10")) {
		t.Fatal("port-mismatched snapshot still authorized the IP")
	}
}

func TestNewSSRFDialBlockErrorMetadata(t *testing.T) {
	t.Parallel()

	ip := net.ParseIP("169.254.169.254")
	err := newSSRFDialBlockError(context.Background(), "metadata.vendor.example", ip, ssrfDialBlockDetail("metadata.vendor.example", ip))
	if err.blockInfo().Reason != blockreason.SSRFMetadata {
		t.Fatalf("reason = %q, want metadata", err.blockInfo().Reason)
	}
	if !strings.Contains(err.Error(), "metadata.vendor.example") || !strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("detail = %q", err.Error())
	}
}

func TestSSRFDialBlockErrorNilReceivers(t *testing.T) {
	t.Parallel()

	var err *ssrfDialBlockError
	if err.Error() != "" {
		t.Fatalf("nil Error = %q", err.Error())
	}
	if got := err.blockInfo(); got.Reason != blockreason.SSRFPrivateIP {
		t.Fatalf("nil blockInfo reason = %q", got.Reason)
	}
	if err.logDetail() != "" {
		t.Fatalf("nil logDetail = %q", err.logDetail())
	}
}

func TestWithSSRFDialScanSnapshotRejectsEmptyAndBadIPs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if got := withSSRFDialScanSnapshot(ctx, "", "443", []string{"203.0.113.10"}); got != ctx {
		t.Fatal("empty host still stored a snapshot")
	}
	if got := withSSRFDialScanSnapshot(ctx, "api.vendor.example", "443", []string{"not-an-ip"}); got != ctx {
		t.Fatal("invalid IP still stored a snapshot")
	}
	var unset context.Context
	if withSSRFDialPort(unset, "443") != nil {
		t.Fatal("nil parent gained a dial port")
	}
	if ssrfDialPortFromContext(unset) != "" {
		t.Fatal("nil context reported a dial port")
	}
}

func TestSSRFDialRebindAndHostMismatch(t *testing.T) {
	t.Parallel()

	ctx := withSSRFDialScanSnapshot(context.Background(), "API.Vendor.Example.", "443", []string{"203.0.113.10%eth0"})
	ctx = withSSRFDialPort(ctx, "443")
	if !isSSRFDNSRebind(ctx, "api.vendor.example", net.ParseIP("127.0.0.1")) {
		t.Fatal("new IP after scan was not labeled a rebind")
	}
	if isSSRFDNSRebind(ctx, "other.vendor.example", net.ParseIP("127.0.0.1")) {
		t.Fatal("different host was labeled a rebind")
	}
	if isSSRFDNSRebind(ctx, "api.vendor.example", nil) {
		t.Fatal("nil IP was labeled a rebind")
	}
	if !ssrfDialSnapshotContains(ctx, "api.vendor.example", net.ParseIP("203.0.113.10")) {
		t.Fatal("scanned IP was not authorized after zone strip")
	}

	err := newSSRFDialBlockError(ctx, "api.vendor.example", net.ParseIP("127.0.0.1"), "rebind")
	if err.blockInfo().Reason != blockreason.SSRFDNSRebind {
		t.Fatalf("rebind reason = %q", err.blockInfo().Reason)
	}
	if !strings.Contains(err.logDetail(), string(blockreason.SSRFDNSRebind)) {
		t.Fatalf("logDetail = %q", err.logDetail())
	}
}

func TestStripIPv6ZoneAndNormalizeIP(t *testing.T) {
	t.Parallel()

	if got := stripIPv6Zone("fe80::1%eth0"); got != "fe80::1" {
		t.Fatalf("zone strip = %q", got)
	}
	if got := stripIPv6Zone("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("no-zone strip = %q", got)
	}
	if normalizeSSRFDialIP(nil) != nil {
		t.Fatal("nil IP normalized to non-nil")
	}
	v4 := normalizeSSRFDialIP(net.ParseIP("203.0.113.10"))
	if v4 == nil || v4.To4() == nil {
		t.Fatalf("IPv4 mapped form not collapsed: %v", v4)
	}
}
