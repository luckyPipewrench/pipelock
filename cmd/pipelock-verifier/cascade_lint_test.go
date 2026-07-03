// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestLintDeferredCascadeReceipts(t *testing.T) {
	bounds := deferred.ResolutionPolicy{
		Timeout:              2 * time.Second,
		MaxPending:           64,
		MaxPendingPerSession: 8,
		MaxPendingBytes:      1024 * 1024,
		MaxCascadeDepth:      8,
	}
	admit := func(deferID string) receipt.Receipt {
		return receipt.Receipt{ActionRecord: receipt.ActionRecord{
			DeferID:          deferID,
			DecisionPhase:    receipt.DecisionPhaseDefer,
			ResolutionPolicy: deferred.ReceiptPolicyString(bounds, config.DeferResolutionPolicy{}),
		}}
	}
	resolve := func(deferID, parentID string, depth int) receipt.Receipt {
		return receipt.Receipt{ActionRecord: receipt.ActionRecord{
			DeferID:       deferID,
			DecisionPhase: receipt.DecisionPhaseResolution,
			ResolutionPolicy: deferred.ReceiptPolicyStringFor(deferred.ReceiptPolicyOptions{
				Bounds: bounds,
				Cascade: &deferred.ReceiptCascade{
					ParentDeferID: parentID,
					CascadeDepth:  depth,
					Linkage:       deferred.LinkageSessionPendingAncestor,
				},
			}),
		}}
	}

	tests := []struct {
		name     string
		receipts []receipt.Receipt
		want     string
	}{
		{
			name:     "well formed cascade",
			receipts: []receipt.Receipt{admit("parent"), admit("child"), resolve("parent", "", 1), resolve("child", "parent", 2)},
		},
		{
			name:     "skip absent cascade",
			receipts: []receipt.Receipt{{ActionRecord: receipt.ActionRecord{DeferID: "legacy", DecisionPhase: receipt.DecisionPhaseResolution}}},
		},
		{
			name:     "missing parent admission",
			receipts: []receipt.Receipt{admit("child"), resolve("child", "parent", 2)},
			want:     "missing earlier parent admission",
		},
		{
			name:     "depth mismatch",
			receipts: []receipt.Receipt{admit("parent"), admit("child"), resolve("parent", "", 1), resolve("child", "parent", 3)},
			want:     "does not equal parent",
		},
		{
			name:     "child before parent depth mismatch",
			receipts: []receipt.Receipt{admit("parent"), admit("child"), resolve("child", "parent", 3), resolve("parent", "", 1)},
			want:     "does not equal parent",
		},
		{
			name:     "missing parent resolution",
			receipts: []receipt.Receipt{admit("parent"), admit("child"), resolve("child", "parent", 2)},
			want:     "without a cascade resolution",
		},
		{
			name:     "invalid zero depth",
			receipts: []receipt.Receipt{admit("child"), resolve("child", "", 0)},
			want:     "invalid cascade depth",
		},
		{
			name:     "invalid root depth",
			receipts: []receipt.Receipt{admit("child"), resolve("child", "", 2)},
			want:     "root depth",
		},
		{
			name: "unsupported linkage",
			receipts: []receipt.Receipt{admit("child"), {ActionRecord: receipt.ActionRecord{
				DeferID:       "child",
				DecisionPhase: receipt.DecisionPhaseResolution,
				ResolutionPolicy: deferred.ReceiptPolicyStringFor(deferred.ReceiptPolicyOptions{
					Bounds: bounds,
					Cascade: &deferred.ReceiptCascade{
						CascadeDepth: 1,
						Linkage:      "unknown_linkage",
					},
				}),
			}}},
			want: "unsupported cascade linkage",
		},
		{
			name:     "duplicate cascade resolution",
			receipts: []receipt.Receipt{admit("child"), resolve("child", "", 1), resolve("child", "", 1)},
			want:     "duplicate cascade resolution",
		},
		{
			name: "depth exceeds bound",
			receipts: []receipt.Receipt{
				admit("parent"),
				{ActionRecord: receipt.ActionRecord{
					DeferID:       "child",
					DecisionPhase: receipt.DecisionPhaseDefer,
					ResolutionPolicy: deferred.ReceiptPolicyString(deferred.ResolutionPolicy{
						MaxCascadeDepth: 1,
					}, config.DeferResolutionPolicy{}),
				}},
				resolve("parent", "", 1),
				resolve("child", "parent", 2),
			},
			want: "exceeds admission max_cascade_depth",
		},
		{
			name: "missing own admission",
			receipts: []receipt.Receipt{
				resolve("child", "", 1),
			},
			want: "no earlier admission receipt",
		},
		{
			name: "malformed admission policy fails closed",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{
					DeferID:          "child",
					DecisionPhase:    receipt.DecisionPhaseDefer,
					ResolutionPolicy: "{not json",
				}},
				resolve("child", "", 1),
			},
			want: "malformed resolution policy",
		},
		{
			name: "malformed resolution policy fails closed",
			receipts: []receipt.Receipt{
				admit("child"),
				{ActionRecord: receipt.ActionRecord{
					DeferID:          "child",
					DecisionPhase:    receipt.DecisionPhaseResolution,
					ResolutionPolicy: "{not json",
				}},
			},
			want: "malformed resolution policy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lintDeferredCascadeReceipts(tt.receipts)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("lintDeferredCascadeReceipts() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("lintDeferredCascadeReceipts() error = %v, want %q", err, tt.want)
			}
		})
	}
}
