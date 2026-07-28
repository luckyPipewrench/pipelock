// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net"
	"testing"
)

// TestParseForwarderIPLiteralMirrorsScannerInetAton pins the config-side IP
// parser to the scanner's inet_aton semantics. The config parser cannot import
// scanner (scanner depends on config), and its doc comment claims it mirrors
// scanner.ParseIPLiteral, so the agreement has to be asserted directly here.
//
// Scanner semantics being mirrored (internal/scanner parseAlternativeIP): two
// components are A.B with A 8 bits and B 24 bits; three components are A.B.C
// with A and B 8 bits and C 16 bits; four components are plain octets and only
// count when at least one uses non-standard notation, because standard
// dotted-decimal is already handled by net.ParseIP.
//
// A mismatch is a validation/runtime parser differential: the allowlist entry
// an operator writes canonicalizes one way at config-validation time and a
// different way at runtime, so a host can validate as one address and be
// matched as another.
func TestParseForwarderIPLiteralMirrorsScannerInetAton(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want string // empty means "must not parse as an IP literal"
	}{
		{name: "two component packs low 24 bits", host: "8.8", want: "8.0.0.8"},
		{name: "two component loopback", host: "127.1", want: "127.0.0.1"},
		{name: "three component packs low 16 bits", host: "127.0.1", want: "127.0.0.1"},
		{name: "single integer decimal", host: "2130706433", want: "127.0.0.1"},
		{name: "single integer hex", host: "0x7f000001", want: "127.0.0.1"},
		{name: "four component hex octet", host: "0x7f.0.0.1", want: "127.0.0.1"},
		{name: "plain dotted quad handled by ParseIP", host: "127.0.0.1", want: "127.0.0.1"},
		{name: "hostname is not an IP", host: "api.vendor.example", want: ""},
		{name: "five components rejected", host: "1.2.3.4.5", want: ""},
		{name: "binary single integer rejected", host: "0b11111111111111111111111111111111", want: ""},
		{name: "explicit octal single integer rejected", host: "0o17777777777", want: ""},
		{name: "binary short component rejected", host: "0b1000.8", want: ""},
		{name: "explicit octal short component rejected", host: "0o10.8", want: ""},
		{name: "signed short component rejected", host: "+8.8", want: ""},
		{name: "underscore short component rejected", host: "8.1_0", want: ""},
		{name: "empty short component rejected", host: "8..", want: ""},

		// Width bounds. Each form packs its final component into a fixed number
		// of bits, so the boundary between the largest legal value and the first
		// overflowing one is where a mirror is most likely to drift: an
		// off-by-one here means an operator's allowlist entry validates as one
		// address and matches as another at runtime.
		{name: "two component max 24-bit tail", host: "8.16777215", want: "8.255.255.255"},
		{name: "two component 24-bit overflow rejected", host: "8.16777216", want: ""},
		{name: "three component max 16-bit tail", host: "8.8.65535", want: "8.8.255.255"},
		{name: "three component 16-bit overflow rejected", host: "8.8.65536", want: ""},
		{name: "leading component max 8 bits", host: "255.1", want: "255.0.0.1"},
		{name: "leading component 8-bit overflow rejected", host: "256.1", want: ""},
		{name: "three component middle 8-bit overflow rejected", host: "8.256.1", want: ""},
		{name: "single integer max 32 bits", host: "4294967295", want: "255.255.255.255"},
		{name: "single integer 32-bit overflow rejected", host: "4294967296", want: ""},
		{name: "four component octet overflow rejected", host: "0xff.0.0.256", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseForwarderIPLiteral(tt.host)
			if tt.want == "" {
				if got != nil {
					t.Fatalf("parseForwarderIPLiteral(%q) = %v, want no IP literal", tt.host, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseForwarderIPLiteral(%q) = nil, want %s (scanner accepts this form)", tt.host, tt.want)
			}
			if !got.Equal(net.ParseIP(tt.want)) {
				t.Fatalf("parseForwarderIPLiteral(%q) = %v, want %s", tt.host, got, tt.want)
			}
		})
	}
}
