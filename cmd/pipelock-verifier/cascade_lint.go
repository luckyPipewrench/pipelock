// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/deferred"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
)

type cascadeAdmission struct {
	index  int
	policy deferred.ReceiptPolicy
}

func lintDeferredCascadeReceipts(receipts []actionreceipt.Receipt) error {
	admissions := make(map[string]cascadeAdmission)
	resolutionDepths := make(map[string]int)
	for i, rcpt := range receipts {
		ar := rcpt.ActionRecord
		if ar.DeferID == "" {
			continue
		}
		if ar.DecisionPhase == actionreceipt.DecisionPhaseDefer {
			admissions[ar.DeferID] = cascadeAdmission{index: i, policy: parseReceiptPolicy(ar.ResolutionPolicy)}
			continue
		}
		if ar.DecisionPhase != actionreceipt.DecisionPhaseResolution {
			continue
		}
		policy, ok := parseReceiptPolicyCascade(ar.ResolutionPolicy)
		if !ok {
			continue
		}
		cascade := policy.Cascade
		admission, found := admissions[ar.DeferID]
		if !found {
			return fmt.Errorf("defer cascade lint: resolution %q has cascade metadata but no earlier admission receipt", ar.DeferID)
		}
		if cascade.ParentDeferID != "" {
			parentAdmission, parentFound := admissions[cascade.ParentDeferID]
			if !parentFound || parentAdmission.index >= i {
				return fmt.Errorf("defer cascade lint: resolution %q references missing earlier parent admission %q", ar.DeferID, cascade.ParentDeferID)
			}
			if parentDepth, parentResolved := resolutionDepths[cascade.ParentDeferID]; parentResolved && cascade.CascadeDepth != parentDepth+1 {
				return fmt.Errorf("defer cascade lint: resolution %q depth %d does not equal parent %q depth %d + 1", ar.DeferID, cascade.CascadeDepth, cascade.ParentDeferID, parentDepth)
			}
		}
		if admission.policy.Bounds.MaxCascadeDepth > 0 && cascade.CascadeDepth > admission.policy.Bounds.MaxCascadeDepth {
			return fmt.Errorf("defer cascade lint: resolution %q depth %d exceeds admission max_cascade_depth %d", ar.DeferID, cascade.CascadeDepth, admission.policy.Bounds.MaxCascadeDepth)
		}
		resolutionDepths[ar.DeferID] = cascade.CascadeDepth
	}
	return nil
}

func parseReceiptPolicyCascade(raw string) (deferred.ReceiptPolicy, bool) {
	policy := parseReceiptPolicy(raw)
	return policy, policy.Cascade != nil
}

func parseReceiptPolicy(raw string) deferred.ReceiptPolicy {
	var policy deferred.ReceiptPolicy
	if raw == "" {
		return policy
	}
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return deferred.ReceiptPolicy{}
	}
	return policy
}
