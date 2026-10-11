// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package endproof defines CLI reports, without changing receipt verification
// or signed formats. Integrity of a prefix does not establish its endpoint.
package endproof

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	Prefix     = "VALID PREFIX, END UNPROVEN"
	Valid      = "CHAIN VALID"
	Invalid    = "CHAIN BROKEN"
	ExitPrefix = 3
)

// Proof identifies the authenticated boundary or operator expectation checked.
type Proof struct {
	Proven   bool     `json:"proven"`
	Evidence []string `json:"evidence"`
}

// Report keeps integrity, endpoint, scope, and the human verdict independent.
// Signer trust belongs to the caller's existing report fields.
type Report struct {
	Integrity string `json:"integrity"`
	EndProof  Proof  `json:"end_proof"`
	Scope     string `json:"scope"`
	Status    string `json:"status"`
}

// New reports already-verified evidence. Its evidence list must only contain
// boundaries whose bindings and signatures the caller authenticated.
func New(valid bool, scope string, evidence ...string) Report {
	r := Report{Integrity: "invalid", Scope: scope, Status: Invalid, EndProof: Proof{Evidence: []string{}}}
	if valid {
		r.Integrity = "valid"
		r.EndProof.Evidence = append(r.EndProof.Evidence, evidence...)
		r.EndProof.Proven = len(evidence) > 0
		r.Status = Prefix
		if r.EndProof.Proven {
			r.Status = Valid
		}
	}
	return r
}

// ActionEvidence is called only after full chain verification. A close must
// be the final receipt: an earlier close cannot bound a later reopened run.
//
// A close ends its run, and it ends the chain only when no later run can
// continue that chain. Pipelock never resumes a per-run recorder session
// ("<base>.run.<hex>"), so a close there is final. A legacy shared session
// ("proxy") was resumed by every restart, which appended a new session_open
// after the close, so deleting the later runs leaves a chain that ends at a
// genuine close. The session is read from the closed run's signed
// session_open.
func ActionEvidence(chain []receipt.Receipt) []string {
	if len(chain) == 0 {
		return nil
	}
	c := chain[len(chain)-1].ActionRecord.SessionControl
	if c == nil || c.Kind != receipt.SessionControlClose || c.Close == nil {
		return nil
	}
	for i := len(chain) - 1; i >= 0; i-- {
		o := chain[i].ActionRecord.SessionControl
		if o == nil || o.Kind != receipt.SessionControlOpen || o.Open == nil || o.Open.RunNonce != c.Close.RunNonce {
			continue
		}
		if RunScoped(o.Open.RecorderSession) {
			return []string{"session_close"}
		}
		return nil
	}
	return nil
}

// RunScoped reports whether a recorder session is a per-run session that no
// later process resumes, so a boundary sealed inside it can end the chain.
func RunScoped(session string) bool {
	_, ok := receipt.RunSessionBase(session)
	return ok
}

// Pin checks an independently supplied expected endpoint. It never creates
// proof from a value inferred from the chain being verified.
func Pin(head string, seq uint64, expectedHead string, expectedSeq *uint64) ([]string, error) {
	var evidence []string
	if expectedHead != "" {
		if head != expectedHead {
			return nil, fmt.Errorf("chain tip does not match expected head %s (tail truncated or different scope)", expectedHead)
		}
		evidence = append(evidence, "operator_head")
	}
	if expectedSeq != nil {
		if seq != *expectedSeq {
			return nil, fmt.Errorf("final_seq %d does not match expected seq %d", seq, *expectedSeq)
		}
		evidence = append(evidence, "operator_seq")
	}
	return evidence, nil
}

// Require maps only a valid prefix to exit 3; invalid evidence and signer
// trust failures must be handled first by the caller.
func (r Report) Require(allowPrefix bool) error {
	if r.Integrity == "valid" && !r.EndProof.Proven && !allowPrefix {
		return cliutil.ExitCodeError(ExitPrefix, errors.New(Prefix))
	}
	return nil
}
