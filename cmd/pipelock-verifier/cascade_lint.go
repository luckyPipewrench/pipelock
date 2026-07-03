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

type cascadeResolution struct {
	index  int
	depth  int
	parent string
}

func lintDeferredCascadeReceipts(receipts []actionreceipt.Receipt) error {
	admissions := make(map[string]cascadeAdmission)
	resolutions := make(map[string]cascadeResolution)
	for i, rcpt := range receipts {
		ar := rcpt.ActionRecord
		if ar.DeferID == "" {
			continue
		}
		if ar.DecisionPhase == actionreceipt.DecisionPhaseDefer {
			policy, err := parseReceiptPolicy(ar.ResolutionPolicy)
			if err != nil {
				return fmt.Errorf("defer cascade lint: admission %q has malformed resolution policy: %w", ar.DeferID, err)
			}
			admissions[ar.DeferID] = cascadeAdmission{index: i, policy: policy}
			continue
		}
		if ar.DecisionPhase != actionreceipt.DecisionPhaseResolution {
			continue
		}
		policy, ok, err := parseReceiptPolicyCascade(ar.ResolutionPolicy)
		if err != nil {
			return fmt.Errorf("defer cascade lint: resolution %q has malformed resolution policy: %w", ar.DeferID, err)
		}
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
		}
		if cascade.CascadeDepth <= 0 {
			return fmt.Errorf("defer cascade lint: resolution %q has invalid cascade depth %d", ar.DeferID, cascade.CascadeDepth)
		}
		if cascade.ParentDeferID == "" && cascade.CascadeDepth != 1 {
			return fmt.Errorf("defer cascade lint: resolution %q root depth %d does not equal 1", ar.DeferID, cascade.CascadeDepth)
		}
		if cascade.Linkage != "" && cascade.Linkage != deferred.LinkageSessionPendingAncestor {
			return fmt.Errorf("defer cascade lint: resolution %q has unsupported cascade linkage %q", ar.DeferID, cascade.Linkage)
		}
		if admission.policy.Bounds.MaxCascadeDepth > 0 && cascade.CascadeDepth > admission.policy.Bounds.MaxCascadeDepth {
			return fmt.Errorf("defer cascade lint: resolution %q depth %d exceeds admission max_cascade_depth %d", ar.DeferID, cascade.CascadeDepth, admission.policy.Bounds.MaxCascadeDepth)
		}
		if prior, exists := resolutions[ar.DeferID]; exists {
			return fmt.Errorf("defer cascade lint: resolution %q has duplicate cascade resolution at receipts %d and %d", ar.DeferID, prior.index, i)
		}
		resolutions[ar.DeferID] = cascadeResolution{
			index:  i,
			depth:  cascade.CascadeDepth,
			parent: cascade.ParentDeferID,
		}
	}
	for deferID, resolution := range resolutions {
		if resolution.parent == "" {
			continue
		}
		parent, found := resolutions[resolution.parent]
		if !found {
			return fmt.Errorf("defer cascade lint: resolution %q references parent %q without a cascade resolution", deferID, resolution.parent)
		}
		if resolution.depth != parent.depth+1 {
			return fmt.Errorf("defer cascade lint: resolution %q depth %d does not equal parent %q depth %d + 1", deferID, resolution.depth, resolution.parent, parent.depth)
		}
	}
	return nil
}

func parseReceiptPolicyCascade(raw string) (deferred.ReceiptPolicy, bool, error) {
	policy, err := parseReceiptPolicy(raw)
	if err != nil {
		return deferred.ReceiptPolicy{}, false, err
	}
	return policy, policy.Cascade != nil, nil
}

// parseReceiptPolicy fails closed: a malformed policy string is a lint error,
// never an empty policy, so bad receipts cannot bypass the cascade checks.
func parseReceiptPolicy(raw string) (deferred.ReceiptPolicy, error) {
	var policy deferred.ReceiptPolicy
	if raw == "" {
		return policy, nil
	}
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return deferred.ReceiptPolicy{}, err
	}
	return policy, nil
}
