// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// validateRestartOpen guards the seam where one run's chain hands off to the
// next: a restart session_open must reference the real prior tail and must not
// impersonate a bound genesis. Only the prior_chain_head mismatch had a
// regression; the remaining fail-closed branches are covered here.
//
// Each case must FAIL verification. A restart open that verified while
// misdescribing its own position would let an operator read a continuous chain
// across a gap that was never proven continuous.
func TestVerifyChain_RestartSessionOpenRejections(t *testing.T) {
	t.Parallel()

	// restartChain builds a valid bound-genesis open plus one action receipt,
	// then appends a restart open at seq 2 whose payload the caller corrupts.
	restartChain := func(t *testing.T, priv ed25519.PrivateKey, corrupt func(open *SessionOpen, priorHash string, priorSeq uint64), prevHash func(priorHash string) string) []Receipt {
		t.Helper()
		base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
		boundOpen := signBoundOpen(t, priv, base)
		tail := signRunReceipt(t, priv, 1, mustHash(t, boundOpen), sessionOpenTestRunA, base.Add(time.Second))
		priorHash := mustHash(t, tail)
		priorSeq := tail.ActionRecord.ChainSeq

		open := testSessionOpen(sessionOpenTestRunB, "open-b", 2)
		open.PriorChainHead = priorHash
		open.PriorChainSeq = priorSeq
		corrupt(&open, priorHash, priorSeq)

		restart := signSessionReceipt(t, priv, 2, prevHash(priorHash), base.Add(2*time.Second), sessionOpenTestRunB, &SessionControl{
			Kind: SessionControlOpen,
			Open: &open,
		}, nil)
		return []Receipt{boundOpen, tail, restart}
	}

	unchangedPrev := func(priorHash string) string { return priorHash }

	tests := map[string]struct {
		build   func(t *testing.T, priv ed25519.PrivateKey) []Receipt
		wantErr string
	}{
		// A restart open that claims the g1 genesis prefix is asserting it
		// begins a chain rather than continuing one, which would detach it
		// from the prior tail it is supposed to be anchored to.
		"restart_open_claims_g1_chain_prev_hash": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				return restartChain(t, priv,
					func(open *SessionOpen, _ string, _ uint64) {},
					func(string) string { return genesisSessionOpenPrefix + strings.Repeat("0", 64) },
				)
			},
			wantErr: "must not use g1 chain_prev_hash",
		},
		// Carrying a genesis_hash is the bound-genesis form's marker. A
		// restart open carrying one is claiming two mutually exclusive
		// positions at once.
		"restart_open_carries_genesis_hash": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				return restartChain(t, priv, func(open *SessionOpen, _ string, _ uint64) {
					open.GenesisHash = ComputeSessionOpenGenesis(*open)
				}, unchangedPrev)
			},
			wantErr: "must not carry genesis_hash",
		},
		// chain_open_seq is the payload's own claim about where this open
		// sits. If it disagrees with the receipt's chain_seq, the signed
		// payload and the signed envelope describe different positions.
		"restart_open_chain_open_seq_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				return restartChain(t, priv, func(open *SessionOpen, _ string, _ uint64) {
					open.ChainOpenSeq = 99
				}, unchangedPrev)
			},
			wantErr: "chain_open_seq does not match receipt chain_seq",
		},
		// The prior tail's hash and its seq are two independent claims about
		// the same handoff point. A correct hash with a wrong seq still
		// misdescribes the gap, so both are checked.
		"restart_open_prior_chain_seq_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				return restartChain(t, priv, func(open *SessionOpen, _ string, priorSeq uint64) {
					open.PriorChainSeq = priorSeq + 7
				}, unchangedPrev)
			},
			wantErr: "prior_chain_seq does not match prior tail seq",
		},
	}

	// Availability control. Every case above is deliberately corrupt, so a
	// change that rejected EVERY restart open, valid handoffs included, would
	// pass all of them. This builds the same shape with nothing corrupted and
	// requires it to verify, so over-strictness at the chain boundary fails
	// here rather than shipping as a refusal an operator has to debug.
	t.Run("control_valid_restart_open_verifies", func(t *testing.T) {
		t.Parallel()
		pub, priv := generateTestKey(t)
		chain := restartChain(t, priv, func(*SessionOpen, string, uint64) {}, unchangedPrev)
		res := VerifyChain(chain, hex.EncodeToString(pub))
		if !res.Valid {
			t.Fatalf("a valid restart session_open chain failed to verify: %s", res.Error)
		}
	})

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pub, priv := generateTestKey(t)
			res := VerifyChain(tc.build(t, priv), hex.EncodeToString(pub))
			if res.Valid {
				t.Fatal("malformed restart session_open chain verified")
			}
			if !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", res.Error, tc.wantErr)
			}
		})
	}
}

// VerifyChainIntegrity's empty-key form is trust-on-first-use: the genesis
// segment's key becomes the sole trusted key. It is the entry point offline
// verification uses when the operator has no pinned key, so the difference
// between it and the pinned form is worth pinning.
func TestVerifyChainIntegrity_TrustOnFirstUse(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	boundOpen := signBoundOpen(t, priv, base)
	tail := signRunReceipt(t, priv, 1, mustHash(t, boundOpen), sessionOpenTestRunA, base.Add(time.Second))
	chain := []Receipt{boundOpen, tail}

	tofu := VerifyChainIntegrity(chain, "")
	if !tofu.Valid {
		t.Fatalf("trust-on-first-use integrity verify failed: %s", tofu.Error)
	}

	pinned := VerifyChainIntegrity(chain, hex.EncodeToString(pub))
	if !pinned.Valid {
		t.Fatalf("pinned-key integrity verify failed: %s", pinned.Error)
	}
	if tofu.RootHash != pinned.RootHash {
		t.Fatalf("root hash differs between trust-on-first-use (%q) and pinned (%q)", tofu.RootHash, pinned.RootHash)
	}

	// A key the operator did not pin must be rejected even though the chain is
	// internally consistent. This is the direction that matters: an attacker
	// with write access can produce a self-consistent chain under their own
	// key, and only the trusted set rejects it.
	otherPub, _ := generateTestKey(t)
	if res := VerifyChainIntegrity(chain, hex.EncodeToString(otherPub)); res.Valid {
		t.Fatal("integrity verify accepted a chain signed by an untrusted key")
	}
}
