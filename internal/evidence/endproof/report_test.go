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
	open := func(run, session string) receipt.Receipt {
		return receipt.Receipt{ActionRecord: receipt.ActionRecord{SessionControl: &receipt.SessionControl{Kind: receipt.SessionControlOpen, Open: &receipt.SessionOpen{RunNonce: run, RecorderSession: session}}}}
	}
	closeOf := func(run string) receipt.Receipt {
		return receipt.Receipt{ActionRecord: receipt.ActionRecord{SessionControl: &receipt.SessionControl{Kind: receipt.SessionControlClose, Close: &receipt.SessionClose{RunNonce: run}}}}
	}
	runSession := "proxy.run.0123456789abcdef0123456789abcdef"
	if len(ActionEvidence([]receipt.Receipt{open("a", runSession), closeOf("a")})) != 1 {
		t.Fatal("terminal close of a per-run session missing")
	}
	if ActionEvidence([]receipt.Receipt{open("a", runSession), closeOf("a"), {}}) != nil {
		t.Fatal("earlier close proved a later prefix")
	}
	// A legacy shared session was resumed by the next restart, so a chain cut
	// after any close of it is indistinguishable from one that ended there.
	if ActionEvidence([]receipt.Receipt{open("a", "proxy"), closeOf("a")}) != nil {
		t.Fatal("close of a resumable shared session proved the chain end")
	}
	// The closed run decides, not an earlier run-scoped open in the chain.
	if ActionEvidence([]receipt.Receipt{open("a", runSession), closeOf("a"), open("b", "proxy"), closeOf("b")}) != nil {
		t.Fatal("an earlier run's session proved a later shared run's close")
	}
	if ActionEvidence([]receipt.Receipt{open("a", runSession), closeOf("b")}) != nil {
		t.Fatal("close without its own session_open proved the chain end")
	}
}

func TestRunScopedEmitterGrammar(t *testing.T) {
	for _, tc := range []struct {
		session string
		want    bool
	}{
		{"proxy.run.0123456789abcdef0123456789abcdef", true},
		{"π.run.0123456789abcdef0123456789abcdef", true},
		{"proxy", false},
		{"proxy.run.", false},
		{"proxy.run.abc", false},
		{"proxy.run.0123456789ABCDEF0123456789ABCDEF", false},
		{"proxy.run.0123456789abcdef0123456789abcdefx", false},
		{"proxy.run.x.run.0123456789abcdef0123456789abcdef", false},
		{"proxy.RUN.0123456789abcdef0123456789abcdef", false},
		{".run.0123456789abcdef0123456789abcdef", false},
		{"a/b.run.0123456789abcdef0123456789abcdef", false},
	} {
		t.Run(tc.session, func(t *testing.T) {
			if got := RunScoped(tc.session); got != tc.want {
				t.Fatalf("RunScoped=%v want %v", got, tc.want)
			}
		})
	}
}
