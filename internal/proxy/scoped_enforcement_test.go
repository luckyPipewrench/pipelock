// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// scopedEnforcementRank decides which destination scope an operator is shown
// first when several are in trouble. Ranking the wrong one hides the scope that
// is actually holding a session down, so every branch is pinned here rather
// than only the tier ladder.
func TestScopedEnforcementRank(t *testing.T) {
	for _, tt := range []struct {
		name string
		snap *AdaptiveScopeSnapshot
		want int
	}{
		{name: "nil scope ranks zero", snap: nil, want: 0},
		{name: "no tier and no escalation", snap: &AdaptiveScopeSnapshot{}, want: 0},
		{name: "soft tier", snap: &AdaptiveScopeSnapshot{AirlockTier: config.AirlockTierSoft}, want: 20},
		{name: "hard tier", snap: &AdaptiveScopeSnapshot{AirlockTier: config.AirlockTierHard}, want: 30},
		{name: "drain outranks every other tier", snap: &AdaptiveScopeSnapshot{AirlockTier: config.AirlockTierDrain}, want: 40},
		{
			// block_all with no tier still has to outrank soft: a scope denying
			// everything is worse than one merely in the soft airlock.
			name: "block_all alone floors at 25",
			snap: &AdaptiveScopeSnapshot{BlockAll: true},
			want: 25,
		},
		{
			// The floor must not DEMOTE a higher tier.
			name: "block_all does not lower a drain tier",
			snap: &AdaptiveScopeSnapshot{AirlockTier: config.AirlockTierDrain, BlockAll: true},
			want: 40,
		},
		{
			name: "block_all does not lower a hard tier",
			snap: &AdaptiveScopeSnapshot{AirlockTier: config.AirlockTierHard, BlockAll: true},
			want: 30,
		},
		{
			name: "escalation level wins when it exceeds the tier rank",
			snap: &AdaptiveScopeSnapshot{AirlockTier: config.AirlockTierSoft, EscalationLevelInt: 77},
			want: 77,
		},
		{
			name: "escalation level below the tier rank does not demote it",
			snap: &AdaptiveScopeSnapshot{AirlockTier: config.AirlockTierDrain, EscalationLevelInt: 5},
			want: 40,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := scopedEnforcementRank(tt.snap); got != tt.want {
				t.Fatalf("scopedEnforcementRank = %d, want %d", got, tt.want)
			}
		})
	}
}

// The reason string is what an operator reads to decide what to do next, so an
// unquarantined scope must never read as quarantined and vice versa.
func TestScopedQuarantineReason(t *testing.T) {
	for _, tt := range []struct {
		name     string
		snap     *AdaptiveScopeSnapshot
		contains []string
		exact    string
	}{
		{name: "nil scope is not quarantined", snap: nil, exact: tierNotQuarantinedReason},
		{
			name:  "empty tier is treated as none",
			snap:  &AdaptiveScopeSnapshot{Scope: "api.example"},
			exact: tierNotQuarantinedReason,
		},
		{
			name:  "explicit none tier without escalation",
			snap:  &AdaptiveScopeSnapshot{Scope: "api.example", AirlockTier: config.AirlockTierNone},
			exact: tierNotQuarantinedReason,
		},
		{
			name:     "quarantined tier names the scope and tier",
			snap:     &AdaptiveScopeSnapshot{Scope: "api.example", AirlockTier: config.AirlockTierHard},
			contains: []string{"api.example", "quarantined", config.AirlockTierHard},
		},
		{
			// None tier but denying everything: the operator still has to be
			// told, or a session that blocks all traffic reports as fine.
			name:     "block_all at none tier still reports the adaptive level",
			snap:     &AdaptiveScopeSnapshot{Scope: "api.example", AirlockTier: config.AirlockTierNone, BlockAll: true, EscalationLevel: "deny"},
			contains: []string{"api.example", "adaptive level", "deny"},
		},
		{
			name:     "escalation level alone reports the adaptive level",
			snap:     &AdaptiveScopeSnapshot{Scope: "api.example", EscalationLevelInt: 2, EscalationLevel: "elevated"},
			contains: []string{"api.example", "adaptive level", "elevated"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := scopedQuarantineReason(tt.snap)
			if tt.exact != "" && got != tt.exact {
				t.Fatalf("scopedQuarantineReason = %q, want %q", got, tt.exact)
			}
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("scopedQuarantineReason = %q, missing %q", got, want)
				}
			}
		})
	}
}
