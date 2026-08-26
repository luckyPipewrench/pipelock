// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The shield oversize block page used to say only "exceeds browser shield size
// limit", naming neither the cap nor a knob. Operators hitting it on legal
// texts and long specs could not tell which of two 5 MiB ceilings fired or
// what would let the page through. The message now carries the host, the
// size, the cap, and every remedy, mirroring responseSizeBlockReason.
func TestShieldOversizeBlockReason_NamesCapAndEveryRemedy(t *testing.T) {
	t.Parallel()

	got := shieldOversizeBlockReason("law.example", 7_340_032, 5*1024*1024)
	for _, want := range []string{
		"law.example",
		"7340032 bytes",
		"browser_shield.max_shield_bytes 5242880",
		"raise browser_shield.max_shield_bytes",
		"browser_shield.oversize_action to scan_head",
		"browser_shield.exempt_domains",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("reason %q missing %q", got, want)
		}
	}
}

func TestShieldOversizeBlockReason_UnknownHost(t *testing.T) {
	t.Parallel()

	got := shieldOversizeBlockReason("", 10, 5)
	if !strings.HasPrefix(got, "response from unknown-host is 10 bytes") {
		t.Fatalf("unexpected reason: %q", got)
	}
}

func TestShieldMaxBytesForResponse(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.BrowserShield.MaxShieldBytes = 100
	cfg.ResponseScanning.SizeExemptDomains = []string{"docs.vendor.example"}
	cfg.ResponseScanning.SizeExemptScanMaxBytes = 1000

	tests := []struct {
		name      string
		host      string
		transport string
		want      int
	}{
		{name: "forward size exempt", host: "docs.vendor.example", transport: TransportForward, want: 1000},
		{name: "connect size exempt", host: "docs.vendor.example", transport: TransportConnect, want: 1000},
		{name: "reverse size exempt", host: "docs.vendor.example", transport: TransportReverse, want: 1000},
		{name: "fetch has no bounded exemption", host: "docs.vendor.example", transport: TransportFetch, want: 100},
		{name: "unmatched host", host: "other.vendor.example", transport: TransportForward, want: 100},
		{name: "unknown transport", host: "docs.vendor.example", transport: "unknown", want: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := shieldMaxBytesForResponse(cfg, tt.host, tt.transport); got != tt.want {
				t.Fatalf("shieldMaxBytesForResponse() = %d, want %d", got, tt.want)
			}
		})
	}

	t.Run("unlimited shield remains unlimited", func(t *testing.T) {
		unlimited := *cfg
		unlimited.BrowserShield.MaxShieldBytes = 0
		if got := shieldMaxBytesForResponse(&unlimited, "docs.vendor.example", TransportForward); got != 0 {
			t.Fatalf("shieldMaxBytesForResponse() = %d, want unlimited 0", got)
		}
	})

	t.Run("bounded ceiling never lowers shield ceiling", func(t *testing.T) {
		lower := *cfg
		lower.ResponseScanning.SizeExemptScanMaxBytes = 50
		if got := shieldMaxBytesForResponse(&lower, "docs.vendor.example", TransportForward); got != 100 {
			t.Fatalf("shieldMaxBytesForResponse() = %d, want 100", got)
		}
	})
}
