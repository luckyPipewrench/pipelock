// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

// chainTip returns the ReceiptHash of the final receipt in a chain, which is
// the value trusted external context would pin as the expected head.
func chainTip(t *testing.T, chain []receipt.EvidenceReceipt) string {
	t.Helper()
	h, err := receipt.ReceiptHash(chain[len(chain)-1])
	if err != nil {
		t.Fatalf("hash chain tip: %v", err)
	}
	return h
}

// TestVerifyChain_TruncationIsInvisibleWithoutAnExpectedHead pins the LIMIT
// rather than blessing it. Every check other than ExpectHeadHash is satisfied
// by any valid PREFIX of a chain: linkage only proves the receipts present form
// a sequence starting at genesis. So dropping the tail leaves a chain that still
// verifies, and omission is the failure mode that matters most for evidence,
// because the dropped entries are exactly the ones worth dropping.
//
// The honest invariant, and what this asserts, is NOT "truncation is fine". It
// is that an unpinned verdict must never claim completeness: Valid may be true,
// but HeadVerified must be false, so no consumer can read "valid" as "nothing is
// missing". If someone later makes an unpinned verification report completeness,
// this fails.
func TestVerifyChain_TruncationIsInvisibleWithoutAnExpectedHead(t *testing.T) {
	t.Parallel()
	priv, pub := testKey(t, 7)
	chain := buildChain(t, priv, 5)

	res := receipt.VerifyChain(chain[:2], receipt.ChainVerifyOptions{PinnedKey: pub})
	if !res.Valid {
		t.Fatalf("a valid prefix should still verify structurally: %s", res.Error)
	}
	if res.HeadVerified {
		t.Fatal("unpinned verification claimed head verification; a truncated chain would read as complete")
	}
	if res.ReceiptCount != 2 {
		t.Fatalf("receipt count = %d, want 2", res.ReceiptCount)
	}
}

// TestVerifyChain_ExpectHeadHashDetectsTruncation is the closing half: with
// trusted head context the same truncation is caught. This is the case the
// evidence-provenance anchoring work must keep passing, which is why it is under
// test now rather than assumed covered when that lands.
func TestVerifyChain_ExpectHeadHashDetectsTruncation(t *testing.T) {
	t.Parallel()
	priv, pub := testKey(t, 8)
	chain := buildChain(t, priv, 5)
	tip := chainTip(t, chain)

	full := receipt.VerifyChain(chain, receipt.ChainVerifyOptions{PinnedKey: pub, ExpectHeadHash: tip})
	if !full.Valid {
		t.Fatalf("complete chain rejected against its own head: %s", full.Error)
	}
	if !full.HeadVerified {
		t.Fatal("HeadVerified false after a matching ExpectHeadHash")
	}

	// Drop the tail. Every per-receipt check still passes; only the head
	// binding can see the omission.
	for _, cut := range []int{1, 2, 4} {
		res := receipt.VerifyChain(chain[:cut], receipt.ChainVerifyOptions{PinnedKey: pub, ExpectHeadHash: tip})
		if res.Valid {
			t.Fatalf("truncation to %d receipts verified against the full-chain head", cut)
		}
		if res.HeadVerified {
			t.Fatalf("HeadVerified true on a rejected chain (cut=%d)", cut)
		}
	}
}

// TestVerifyChain_ExpectHeadHashRejectsAForeignHead guards the other direction:
// the binding must not be satisfiable by a chain from a different session or
// signer that happens to be internally consistent.
func TestVerifyChain_ExpectHeadHashRejectsAForeignHead(t *testing.T) {
	t.Parallel()
	privA, pubA := testKey(t, 9)
	privB, _ := testKey(t, 10)
	mine := buildChain(t, privA, 3)
	other := buildChain(t, privB, 3)

	otherTip := chainTip(t, other)
	if chainTip(t, mine) == otherTip {
		t.Fatal("two independently keyed chains produced the same tip")
	}
	res := receipt.VerifyChain(mine, receipt.ChainVerifyOptions{PinnedKey: pubA, ExpectHeadHash: otherTip})
	if res.Valid {
		t.Fatal("chain verified against a head hash it does not have")
	}
}

// TestVerifyChain_BrokenLinkReportsTheLinkNotTheHead pins the ordering choice.
// The head check runs last so an internally broken chain reports the broken link
// at its sequence, which is the cause, rather than the head mismatch it also
// produces, which is only the downstream symptom and would send an operator
// hunting for a truncation that did not happen.
func TestVerifyChain_BrokenLinkReportsTheLinkNotTheHead(t *testing.T) {
	t.Parallel()
	priv, pub := testKey(t, 11)
	chain := buildChain(t, priv, 4)
	tip := chainTip(t, chain)
	chain[2].ChainPrevHash = receipt.GenesisHash // break the middle link

	res := receipt.VerifyChain(chain, receipt.ChainVerifyOptions{PinnedKey: pub, ExpectHeadHash: tip})
	if res.Valid {
		t.Fatal("chain with a broken link verified")
	}
	if res.BrokenAtSeq != 2 {
		t.Fatalf("broken_at_seq = %d, want 2 (the broken link, not the head)", res.BrokenAtSeq)
	}
	if !strings.Contains(res.Error, "chain_prev_hash mismatch") {
		t.Fatalf("error = %q, want the broken-link cause rather than signature or head mismatch", res.Error)
	}
}

func TestVerifyChain_ExpectedHeadBoundaryOrdering(t *testing.T) {
	t.Parallel()
	priv, pub := testKey(t, 12)
	chain := buildChain(t, priv, 3)
	tip := chainTip(t, chain)

	t.Run("empty chain", func(t *testing.T) {
		res := receipt.VerifyChain(nil, receipt.ChainVerifyOptions{PinnedKey: pub, ExpectHeadHash: tip})
		if res.Valid || res.HeadVerified || res.Error != "empty chain" {
			t.Fatalf("empty result = %#v, want invalid unverified empty-chain error", res)
		}
	})

	t.Run("single receipt", func(t *testing.T) {
		singleTip := chainTip(t, chain[:1])
		res := receipt.VerifyChain(chain[:1], receipt.ChainVerifyOptions{PinnedKey: pub, ExpectHeadHash: singleTip})
		if !res.Valid || !res.HeadVerified || res.ReceiptCount != 1 || res.FinalSeq != 0 {
			t.Fatalf("single result = %#v, want valid head-verified one-receipt chain", res)
		}
	})

	t.Run("final signature failure precedes head", func(t *testing.T) {
		broken := append([]receipt.EvidenceReceipt(nil), chain...)
		broken[len(broken)-1].Signature.Signature = "ed25519:" + strings.Repeat("0", 128)
		res := receipt.VerifyChain(broken, receipt.ChainVerifyOptions{PinnedKey: pub, ExpectHeadHash: tip})
		if res.Valid || res.HeadVerified {
			t.Fatalf("bad final signature result = %#v, want invalid and head unverified", res)
		}
		if res.BrokenAtSeq != 2 || !strings.Contains(res.Error, "signature") {
			t.Fatalf("bad final signature result = %#v, want signature failure at seq 2 before head comparison", res)
		}
	})
}
