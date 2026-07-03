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
			name: "depth exceeds bound",
			receipts: []receipt.Receipt{
				{ActionRecord: receipt.ActionRecord{
					DeferID:       "child",
					DecisionPhase: receipt.DecisionPhaseDefer,
					ResolutionPolicy: deferred.ReceiptPolicyString(deferred.ResolutionPolicy{
						MaxCascadeDepth: 1,
					}, config.DeferResolutionPolicy{}),
				}},
				resolve("child", "", 2),
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
