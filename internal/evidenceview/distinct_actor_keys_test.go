// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// TestDistinctActorKeys covers the fallback chain the single-agent refusal
// depends on. The guard asks "are two different agents present here", and an
// empty Actor does not mean "no agent": it means the label was not recorded, so
// the receipt still has to count under some key. Dropping any step of the
// chain would let a receipt go uncounted and let a mixed-actor session render,
// disclosing the other agent's target URLs, which can carry capability tokens.
func TestDistinctActorKeys(t *testing.T) {
	t.Parallel()

	lifecycle := receipt.Receipt{ActionRecord: receipt.ActionRecord{
		Actor:          "pipelock",
		SessionControl: &receipt.SessionControl{},
	}}

	cases := []struct {
		name      string
		sessionID string
		receipts  []receipt.Receipt
		want      []string
	}{
		{
			name: "actor wins when present",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{Actor: " Agent-Alpha ", SessionID: "s-1"}},
			},
			want: []string{"agent-alpha"},
		},
		{
			name: "empty actor falls back to the receipt session id",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{Actor: "agent-alpha"}},
				{ActionRecord: receipt.ActionRecord{Actor: "", SessionID: "s-bravo"}},
			},
			want: []string{"agent-alpha", "s-bravo"},
		},
		{
			name:      "empty actor and session id fall back to the rendered session",
			sessionID: "proxy",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{}},
			},
			want: []string{"proxy"},
		},
		{
			name:     "nothing to key on is skipped rather than counted as an agent",
			receipts: []receipt.Receipt{{ActionRecord: receipt.ActionRecord{}}},
			want:     []string{},
		},
		{
			name:      "lifecycle records are excluded",
			sessionID: "proxy",
			receipts: []receipt.Receipt{
				lifecycle,
				{ActionRecord: receipt.ActionRecord{Actor: "agent-alpha"}},
			},
			want: []string{"agent-alpha"},
		},
		{
			name:      "case variants are one agent, not two",
			sessionID: "proxy",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{Actor: "Agent-Alpha"}},
				{ActionRecord: receipt.ActionRecord{Actor: "agent-alpha"}},
			},
			want: []string{"agent-alpha"},
		},
		{
			name:      "internal whitespace variants are one agent, not two",
			sessionID: "proxy",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{Actor: "agent alpha"}},
				{ActionRecord: receipt.ActionRecord{Actor: "agent\t alpha"}},
			},
			want: []string{"agent alpha"},
		},
		{
			name:      "genuinely different agents still count separately",
			sessionID: "proxy",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{Actor: "agent-alpha"}},
				{ActionRecord: receipt.ActionRecord{Actor: "agent-bravo"}},
			},
			want: []string{"agent-alpha", "agent-bravo"},
		},
		{
			name:      "duplicates collapse",
			sessionID: "proxy",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{Actor: "agent-alpha"}},
				{ActionRecord: receipt.ActionRecord{Actor: "agent-alpha"}},
			},
			want: []string{"agent-alpha"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DistinctActorKeys(tc.sessionID, tc.receipts)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("DistinctActorKeys = %v, want %v", got, tc.want)
			}
		})
	}
}
