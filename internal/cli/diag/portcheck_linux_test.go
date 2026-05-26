// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package diag

import (
	"net"
	"testing"
)

func TestParseProcNetIP_IPv4(t *testing.T) {
	// /proc/net/tcp encodes IPv4 as 8 uppercase hex digits in REVERSE
	// host byte order: 127.0.0.1 -> 0100007F, 0.0.0.0 -> 00000000.
	tests := []struct {
		hex  string
		want string // dotted-quad
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
		// 203.0.113.1 is RFC 5737 TEST-NET-3 (documentation block).
		// Bytes CB.00.71.01 stored in /proc's little-endian form become 017100CB.
		{"017100CB", "203.0.113.1"},
	}
	for _, tc := range tests {
		t.Run(tc.hex, func(t *testing.T) {
			got := parseProcNetIP(tc.hex, false)
			if got == nil {
				t.Fatalf("got nil IP for %q", tc.hex)
			}
			if got.String() != tc.want {
				t.Errorf("parseProcNetIP(%q) = %s, want %s", tc.hex, got, tc.want)
			}
		})
	}
}

func TestParseProcNetIP_IPv4_BadHex(t *testing.T) {
	// Wrong length must return nil (not panic, not stretched).
	if got := parseProcNetIP("FF", false); got != nil {
		t.Errorf("short hex got %v, want nil", got)
	}
	if got := parseProcNetIP("XYZ12345", false); got != nil {
		t.Errorf("non-hex got %v, want nil", got)
	}
}

func TestParseProcNetIP_IPv6_BadLength(t *testing.T) {
	if got := parseProcNetIP("DEADBEEF", true); got != nil {
		t.Errorf("short IPv6 hex got %v, want nil", got)
	}
}

func TestParseProcNetIP_IPv6_AnyAddr(t *testing.T) {
	// All-zero IPv6 = :: (the unspecified address).
	got := parseProcNetIP("00000000000000000000000000000000", true)
	if got == nil {
		t.Fatal("got nil for all-zero IPv6")
	}
	if !got.IsUnspecified() {
		t.Errorf("got %v, want unspecified (::)", got)
	}
}

func TestEnumerateListenerHolders_Smoke(t *testing.T) {
	// Smoke test: on a real Linux host the function should succeed and
	// return some holders (the test process inherits a bunch of inherited
	// listeners normally, but a fresh runner may have none — both are valid).
	holders, err := enumerateListenerHolders()
	if err != nil {
		t.Fatalf("enumerateListenerHolders: %v", err)
	}
	// Every entry should have a valid Port; PIDs may be 0 when running
	// without privilege to readdir /proc/<other-uid-pid>/fd.
	for port, list := range holders {
		if port == 0 {
			t.Errorf("holder at port 0 is invalid")
		}
		for _, h := range list {
			if h.Port != port {
				t.Errorf("holder Port=%d under map key %d", h.Port, port)
			}
		}
	}
}

func TestListenerAddressesMayCollide(t *testing.T) {
	tests := []struct {
		name     string
		cfgAddr  string
		holderIP net.IP
		want     bool
	}{
		{"unparseable-address-conservative", "not-a-host-port", net.ParseIP("127.0.0.1"), true},
		{"empty-host-conservative", ":8888", net.ParseIP("127.0.0.1"), true},
		{"hostname-cant-resolve-conservative", "localhost:8888", net.ParseIP("127.0.0.1"), true},
		{"nil-holder-conservative", "127.0.0.1:8888", nil, true},
		{"ipv4-loopback-explicit-match", "127.0.0.1:8888", net.ParseIP("127.0.0.1"), true},
		{"ipv4-loopback-explicit-mismatch", "127.0.0.1:8888", net.ParseIP("127.0.0.2"), false},
		{"ipv4-wildcard-collides-with-loopback", "0.0.0.0:8888", net.ParseIP("127.0.0.1"), true},
		{"ipv4-wildcard-does-not-collide-with-ipv6-explicit", "0.0.0.0:8888", net.ParseIP("::1"), false},
		{"ipv6-wildcard-may-collide-with-ipv4-explicit", "[::]:8888", net.ParseIP("127.0.0.1"), true},
		{"ipv6-explicit-no-collide-with-ipv4-wildcard", "[::1]:8888", net.ParseIP("0.0.0.0"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := listenerAddressesMayCollide(tc.cfgAddr, tc.holderIP)
			if got != tc.want {
				t.Errorf("listenerAddressesMayCollide(%q, %v) = %v, want %v", tc.cfgAddr, tc.holderIP, got, tc.want)
			}
		})
	}
}
