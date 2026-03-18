// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

// allSignals enumerates every SignalType so tests catch missing entries in
// SignalPoints when new signals are added.
var allSignals = []session.SignalType{
	session.SignalBlock,
	session.SignalNearMiss,
	session.SignalDomainAnomaly,
	session.SignalEntropyBudget,
	session.SignalFragmentDLP,
	session.SignalStrip,
}

func TestSignalPoints_AllSignalsPresent(t *testing.T) {
	for _, sig := range allSignals {
		points, ok := session.SignalPoints[sig]
		if !ok {
			t.Errorf("SignalPoints missing entry for SignalType(%d)", int(sig))
			continue
		}
		if points <= 0 {
			t.Errorf("SignalPoints[SignalType(%d)] = %v, want > 0", int(sig), points)
		}
	}
}

func TestSignalPoints_Values(t *testing.T) {
	tests := []struct {
		sig   session.SignalType
		want  float64
		label string
	}{
		{session.SignalBlock, 3.0, "SignalBlock"},
		{session.SignalNearMiss, 1.0, "SignalNearMiss"},
		{session.SignalDomainAnomaly, 2.0, "SignalDomainAnomaly"},
		{session.SignalEntropyBudget, 2.0, "SignalEntropyBudget"},
		{session.SignalFragmentDLP, 3.0, "SignalFragmentDLP"},
		{session.SignalStrip, 2.0, "SignalStrip"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			got, ok := session.SignalPoints[tt.sig]
			if !ok {
				t.Fatalf("SignalPoints missing %s", tt.label)
			}
			if got != tt.want {
				t.Errorf("SignalPoints[%s] = %v, want %v", tt.label, got, tt.want)
			}
		})
	}
}

func TestEscalationLabel(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{-1, "normal"}, // below zero clamps to normal
		{0, "normal"},
		{1, "elevated"},
		{2, "high"},
		{3, "critical"},
		{4, "critical"}, // beyond slice → last entry
		{99, "critical"},
	}

	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.want+"_level_"+strings.TrimLeft(strings.ReplaceAll(strings.ReplaceAll(tt.want, "normal", ""), "elevated", ""), " "), " ", ""), func(t *testing.T) {
			got := session.EscalationLabel(tt.level)
			if got != tt.want {
				t.Errorf("EscalationLabel(%d) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestNextInvocationKey_UniqueAndPrefixed(t *testing.T) {
	const prefix = "mcp-stdio"
	const n = 100

	seen := make(map[string]struct{}, n)
	for i := range n {
		key := session.NextInvocationKey(prefix)
		if !strings.HasPrefix(key, prefix+"-") {
			t.Errorf("key[%d] = %q, want prefix %q-", i, key, prefix)
		}
		if _, dup := seen[key]; dup {
			t.Errorf("duplicate key at iteration %d: %q", i, key)
		}
		seen[key] = struct{}{}
	}
}

func TestNextInvocationKey_DifferentPrefixes(t *testing.T) {
	k1 := session.NextInvocationKey("http")
	k2 := session.NextInvocationKey("stdio")

	if k1 == k2 {
		t.Errorf("keys from different prefixes should not be equal: %q == %q", k1, k2)
	}

	if !strings.HasPrefix(k1, "http-") {
		t.Errorf("k1 = %q, want prefix %q", k1, "http-")
	}
	if !strings.HasPrefix(k2, "stdio-") {
		t.Errorf("k2 = %q, want prefix %q", k2, "stdio-")
	}
}

func TestNextInvocationKey_Monotonic(t *testing.T) {
	// Counter is global and shared across tests, so we just verify each call
	// returns a key with a numeric suffix.
	key := session.NextInvocationKey("test")
	parts := strings.SplitN(key, "-", 2)
	if len(parts) != 2 {
		t.Fatalf("key %q has unexpected format (want prefix-N)", key)
	}
	if parts[1] == "" {
		t.Errorf("numeric suffix is empty in key %q", key)
	}
	for _, ch := range parts[1] {
		if ch < '0' || ch > '9' {
			t.Errorf("suffix of key %q contains non-digit character %q", key, string(ch))
			break
		}
	}
}
