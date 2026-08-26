// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"
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
