//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	testActor        = "agent-alpha"
	testPolicyHash   = "policy-hash-test"
	testPrincipal    = "operator"
	testSessionID    = "session-alpha"
	testTarget       = "https://api.vendor.example/evidence"
	testTransport    = "fetch"
	trustedKeySource = "operator-imported"
)

func generateDashboardKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func allowFleetScope(*http.Request, DecisionScope, bool) error {
	return nil
}

func buildDashboardChain(t *testing.T, priv ed25519.PrivateKey, count int) []receipt.Receipt {
	t.Helper()
	chain := make([]receipt.Receipt, 0, count)
	prevHash := receipt.GenesisHash
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	for i := range count {
		r := signDashboardReceipt(t, priv, uint64(i), prevHash, base.Add(time.Duration(i)*time.Second))
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
		chain = append(chain, r)
		prevHash = hash
	}
	return chain
}

func signDashboardReceipt(
	t *testing.T,
	priv ed25519.PrivateKey,
	seq uint64,
	prevHash string,
	ts time.Time,
) receipt.Receipt {
	t.Helper()
	ar := validDashboardAction(seq, prevHash, ts)
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func validDashboardAction(seq uint64, prevHash string, ts time.Time) receipt.ActionRecord {
	return receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       ts,
		Principal:       testPrincipal,
		Actor:           testActor,
		Target:          testTarget,
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
		PolicyHash:      testPolicyHash,
		Verdict:         "allow",
		SessionID:       testSessionID,
		Transport:       testTransport,
		Method:          http.MethodGet,
		Layer:           "allowlist",
		Pattern:         "api.vendor.example",
		ChainPrevHash:   prevHash,
		ChainSeq:        seq,
	}
}
