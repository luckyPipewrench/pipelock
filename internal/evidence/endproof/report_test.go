// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package endproof

import (
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestEndpointPolicy(t *testing.T) {
	for _, scope := range []string{"receipt_chain", "whole_recorder", "receipt_group", "chain_set"} {
		r := New(true, scope)
		var exit *cliutil.ExitError
		if !errors.As(r.Require(false), &exit) || exit.Code != 3 || r.Status != Prefix {
			t.Fatalf("prefix: %+v", r)
		}
		if err := r.Require(true); err != nil || r.Status != Prefix || r.EndProof.Proven {
			t.Fatalf("accepted prefix: %+v %v", r, err)
		}
		r = New(true, scope, "authenticated_boundary")
		if r.Status != Valid || !r.EndProof.Proven || r.Require(false) != nil {
			t.Fatalf("closed: %+v", r)
		}
		r = New(false, scope, "authenticated_boundary")
		if r.Integrity != "invalid" || r.EndProof.Proven || len(r.EndProof.Evidence) != 0 {
			t.Fatalf("invalid proof: %+v", r)
		}
	}
}

func TestIndependentPins(t *testing.T) {
	seq := uint64(3)
	if proof, err := Pin("tip", seq, "tip", &seq); err != nil || len(proof) != 2 {
		t.Fatalf("matched pins: %v %v", proof, err)
	}
	if _, err := Pin("tip", seq, "other", &seq); err == nil {
		t.Fatal("mismatching head accepted")
	}
	seq++
	if _, err := Pin("tip", 3, "tip", &seq); err == nil {
		t.Fatal("mismatching sequence accepted")
	}
	if proof, err := Pin("tip", 3, "", nil); err != nil || len(proof) != 0 {
		t.Fatalf("inferred proof: %v %v", proof, err)
	}
}

func TestCloseMustBeTerminal(t *testing.T) {
	if ActionEvidence(nil) != nil {
		t.Fatal("empty chain has no endpoint")
	}
	closeReceipt := receipt.Receipt{ActionRecord: receipt.ActionRecord{SessionControl: &receipt.SessionControl{Kind: receipt.SessionControlClose, Close: &receipt.SessionClose{}}}}
	if len(ActionEvidence([]receipt.Receipt{closeReceipt})) != 1 {
		t.Fatal("terminal close missing")
	}
	if ActionEvidence([]receipt.Receipt{closeReceipt, {}}) != nil {
		t.Fatal("earlier close proved a later prefix")
	}
}
