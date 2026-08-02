// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"net/url"
	"testing"
)

// TestSSRFDialSnapshotPortBinding proves the rebind snapshot only vouches for
// the exact host:port it was recorded for. A snapshot taken while scanning
// host:443 must not influence the rebind verdict of a dial to host:6443. This
// is the port-binding groundwork that lets guard grants (a later PR) authorize
// an internal address for an exact port without leaking that authority to a
// different port on the same host.
func TestSSRFDialSnapshotPortBinding(t *testing.T) {
	const host = "rebind.test"
	scanTimeIP := "203.0.113.10"             // seen at scan time
	changedIP := net.ParseIP("198.51.100.7") // NOT seen at scan time

	base := withSSRFDialScanSnapshot(context.Background(), host, "443", []string{scanTimeIP})

	tests := []struct {
		name     string
		dialPort string
		want     bool
	}{
		// Matching port: the snapshot applies, so an IP that was not seen at
		// scan time is flagged as a rebind. This is the existing behavior and
		// proves the guard still fires — a non-vacuous positive.
		{name: "matching port flags rebind", dialPort: "443", want: true},
		// Mismatched port: the :443 snapshot does not describe a :6443 dial, so
		// it must not apply. Neutralizing the port check flips this to true,
		// which is what makes this assertion non-vacuous.
		{name: "mismatched port does not apply", dialPort: "6443", want: false},
		// No dial port recorded: fall back to host-only behavior for callers
		// that never set a port (backward compatible).
		{name: "absent dial port falls back to host match", dialPort: "", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := base
			if tc.dialPort != "" {
				ctx = withSSRFDialPort(ctx, tc.dialPort)
			}
			if got := isSSRFDNSRebind(ctx, host, changedIP); got != tc.want {
				t.Fatalf("isSSRFDNSRebind(dialPort=%q) = %v, want %v", tc.dialPort, got, tc.want)
			}
		})
	}
}

// TestSSRFDialSnapshotSeenIPNotRebind confirms an IP that WAS seen at scan time
// is never a rebind, regardless of port, so the port binding does not turn a
// legitimate re-resolution into a false rebind.
func TestSSRFDialSnapshotSeenIPNotRebind(t *testing.T) {
	const host = "rebind.test"
	ctx := withSSRFDialScanSnapshot(context.Background(), host, "443", []string{"203.0.113.10"})
	ctx = withSSRFDialPort(ctx, "443")
	if isSSRFDNSRebind(ctx, host, net.ParseIP("203.0.113.10")) {
		t.Fatal("an IP seen at scan time must not be flagged as a rebind")
	}
}

func TestEffectiveURLPort(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "https default", raw: "https://api.vendor.example/", want: "443"},
		{name: "http default", raw: "http://api.vendor.example/", want: "80"},
		{name: "wss default", raw: "wss://api.vendor.example/ws", want: "443"},
		{name: "ws default", raw: "ws://api.vendor.example/ws", want: "80"},
		{name: "explicit https port", raw: "https://api.vendor.example:6443/", want: "6443"},
		{name: "explicit http port", raw: "http://api.vendor.example:8080/", want: "8080"},
		{name: "ipv6 explicit port", raw: "https://[2001:db8::1]:6443/", want: "6443"},
		{name: "unknown scheme has no default", raw: "ftp://api.vendor.example/", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tc.raw, err)
			}
			if got := effectiveURLPort(u); got != tc.want {
				t.Fatalf("effectiveURLPort(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
	if got := effectiveURLPort(nil); got != "" {
		t.Fatalf("effectiveURLPort(nil) = %q, want empty", got)
	}
}
