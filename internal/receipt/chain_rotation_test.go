// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// signSegmentReceipt signs a receipt for a segment, optionally carrying a
// KeyTransition marker (for the segment-genesis receipt of a rotated segment).
func signSegmentReceipt(t *testing.T, priv ed25519.PrivateKey, seq uint64, prevHash string, ts time.Time, marker *KeyTransition) Receipt {
	t.Helper()
	ar := ActionRecord{
		Version:       ActionRecordVersion,
		ActionID:      NewActionID(),
		ActionType:    ActionRead,
		Timestamp:     ts,
		Target:        chainTestTarget,
		Verdict:       testVerdict,
		Transport:     chainTestTransport,
		ChainPrevHash: prevHash,
		ChainSeq:      seq,
		KeyTransition: marker,
	}
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func mustHash(t *testing.T, r Receipt) string {
	t.Helper()
	h, err := ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	return h
}

// buildSegment appends n receipts to an existing chain under priv, starting at
// segment seq 0 with the given prevHash, and returns the appended receipts plus
// the new tail hash. The first receipt carries marker (nil for the genesis
// segment). Each segment's seq baseline is 0 - that is the rotation model: a new
// segment restarts seq at its own genesis.
func buildSegment(t *testing.T, priv ed25519.PrivateKey, n int, prevHash string, base time.Time, marker *KeyTransition) ([]Receipt, string) {
	t.Helper()
	out := make([]Receipt, 0, n)
	for i := range n {
		var m *KeyTransition
		if i == 0 {
			m = marker
		}
		r := signSegmentReceipt(t, priv, uint64(i), prevHash, base.Add(time.Duration(i)*time.Second), m)
		prevHash = mustHash(t, r)
		out = append(out, r)
	}
	return out, prevHash
}

// buildRotatedChain builds a 2-segment chain: aN receipts under keyA (genesis),
// then bN receipts under keyB introduced by a valid KeyTransition.
func buildRotatedChain(t *testing.T, privA, privB ed25519.PrivateKey, aN, bN int) []Receipt {
	t.Helper()
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	segA, tailA := buildSegment(t, privA, aN, GenesisHash, base, nil)
	priorTail := segA[len(segA)-1]
	marker := &KeyTransition{
		PriorSignerKey: hex.EncodeToString(privA.Public().(ed25519.PublicKey)),
		PriorChainSeq:  priorTail.ActionRecord.ChainSeq,
		PriorChainHash: tailA,
	}
	segB, _ := buildSegment(t, privB, bN, tailA, base.Add(time.Hour), marker)
	return append(segA, segB...)
}

func TestVerifyChain_RotatedChainVerifiesEndToEndWithBothKeysTrusted(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)

	chain := buildRotatedChain(t, privA, privB, 3, 2)
	keyA := hex.EncodeToString(pubA)
	keyB := hex.EncodeToString(pubB)

	// Both keys trusted (operator confirmed the rotation): verifies end-to-end.
	res := VerifyChainTrusted(chain, []string{keyA, keyB})
	if !res.Valid {
		t.Fatalf("rotated chain with both keys trusted must verify end-to-end, got: %s", res.Error)
	}
	if res.ReceiptCount != 5 {
		t.Errorf("ReceiptCount = %d, want 5", res.ReceiptCount)
	}
	if len(res.Segments) != 2 {
		t.Fatalf("Segments = %d, want 2", len(res.Segments))
	}
	wantKeys := []string{keyA, keyB}
	if len(res.SignerKeys) != 2 || res.SignerKeys[0] != wantKeys[0] || res.SignerKeys[1] != wantKeys[1] {
		t.Errorf("SignerKeys = %v, want %v", res.SignerKeys, wantKeys)
	}
	if res.Segments[0].Boundary {
		t.Error("genesis segment must not be marked as a boundary")
	}
	if !res.Segments[1].Boundary {
		t.Error("rotated segment must be marked as a boundary")
	}
	if res.Segments[1].FirstSeq != 0 {
		t.Errorf("rotated segment FirstSeq = %d, want 0", res.Segments[1].FirstSeq)
	}
}

func TestVerifyChain_RotationToUnconfirmedKeyIsFlagged(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)

	chain := buildRotatedChain(t, privA, privB, 3, 2)
	keyB := hex.EncodeToString(pubB)

	// Trust-on-first-use (no key): genesis key A is adopted; the rotation to B
	// is NOT silently trusted - it is flagged so the operator confirms it.
	res := VerifyChain(chain, "")
	if res.Valid {
		t.Fatal("rotation to an unconfirmed key must NOT be silently trusted")
	}
	if res.UntrustedSignerKey != keyB {
		t.Errorf("UntrustedSignerKey = %q, want %q", res.UntrustedSignerKey, keyB)
	}
	if res.BrokenAtSeq != 0 {
		t.Errorf("BrokenAtSeq = %d, want 0 (the rotated segment genesis)", res.BrokenAtSeq)
	}

	// Pinned ONLY to genesis key A: the rotation to B is likewise flagged,
	// because the marker does not delegate trust.
	res = VerifyChain(chain, hex.EncodeToString(pubA))
	if res.Valid {
		t.Fatal("rotation to a key outside the trusted set must be flagged even when pinned to genesis")
	}
	if res.UntrustedSignerKey != keyB {
		t.Errorf("pinned UntrustedSignerKey = %q, want %q", res.UntrustedSignerKey, keyB)
	}
}

func TestVerifyChain_ExplicitEmptyTrustedKeyFailsClosed(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)
	key := hex.EncodeToString(pub)
	chain := buildChain(t, priv, 2)

	res := VerifyChainTrusted(chain, []string{" "})
	if res.Valid {
		t.Fatal("explicit blank trusted key must not fall back to trust-on-first-use")
	}
	if res.Error == "" {
		t.Fatal("blank trusted key rejection should explain the trust-anchor error")
	}

	root, err := ComputeTranscriptRootTrusted("proxy", chain, []string{" "})
	if err == nil {
		t.Fatalf("transcript root with blank trusted key must fail, got root %+v", root)
	}

	if root, err := ComputeTranscriptRootTrusted("proxy", chain, []string{" " + key + " "}); err != nil {
		t.Fatalf("transcript root should trim valid trusted keys: %v", err)
	} else if root.ReceiptCount != uint64(len(chain)) {
		t.Fatalf("ReceiptCount = %d, want %d", root.ReceiptCount, len(chain))
	}
}

func TestVerifyChain_RotatedSegmentWithoutPriorSegmentRejected(t *testing.T) {
	t.Parallel()
	_, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)

	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	segA, tailA := buildSegment(t, privA, 2, GenesisHash, base, nil)
	priorTail := segA[len(segA)-1]
	marker := &KeyTransition{
		PriorSignerKey: hex.EncodeToString(privA.Public().(ed25519.PublicKey)),
		PriorChainSeq:  priorTail.ActionRecord.ChainSeq,
		PriorChainHash: tailA,
	}
	segB, _ := buildSegment(t, privB, 3, tailA, base.Add(time.Hour), marker)

	// A rotated segment cannot verify as a COMPLETE chain by itself. The marker
	// is signed by the new key and embeds only a claimed prior hash; the actual
	// prior tail must be present so deletion/truncation is detected.
	res := VerifyChain(segB, "")
	if res.Valid {
		t.Fatal("rotated segment without its prior segment must be rejected")
	}
	if res.Error == "" {
		t.Fatal("rejected isolated rotated segment should explain the missing prior segment")
	}
	// Pinned to B (the isolated segment's own key) still rejects: key trust
	// cannot substitute for the missing prior tail.
	if res := VerifyChain(segB, hex.EncodeToString(pubB)); res.Valid {
		t.Fatal("isolated rotated segment pinned to its own key must still be rejected")
	}
	if _, err := ComputeTranscriptRootTrusted("proxy", segB, []string{hex.EncodeToString(pubB)}); err == nil {
		t.Fatal("transcript root must reject a rotated suffix missing its prior segment")
	}
}

func TestVerifyChain_OrdinarySeqZeroWithoutMarkerStillFails(t *testing.T) {
	t.Parallel()
	_, priv := generateTestKey(t)
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	// A seq-0 receipt with a non-genesis prev_hash and NO marker must fail.
	bad := signSegmentReceipt(t, priv, 0, "not-genesis-hash", base, nil)
	res := VerifyChain([]Receipt{bad}, "")
	if res.Valid {
		t.Fatal("seq-0 receipt with non-genesis prev_hash and no marker must FAIL")
	}

	// A mid-chain ordinary seq-0 (fork attempt, no marker) must fail.
	good := buildChain(t, priv, 2)
	forced := signSegmentReceipt(t, priv, 0, mustHash(t, good[1]), base.Add(2*time.Second), nil)
	res = VerifyChain(append(good, forced), "")
	if res.Valid {
		t.Fatal("mid-chain seq-0 without a key_transition boundary must FAIL")
	}
}

func TestVerifyChain_ForgedSegmentAttackerKeyRejected(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privAttacker := generateTestKey(t)

	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	segA, tailA := buildSegment(t, privA, 3, GenesisHash, base, nil)
	priorTail := segA[len(segA)-1]
	keyA := hex.EncodeToString(pubA)
	attackerHex := hex.EncodeToString(privAttacker.Public().(ed25519.PublicKey))

	// Attacker forges a new segment under THEIR key with a marker that
	// correctly references the real prior tail (they can READ the file). The
	// marker is structurally consistent, BUT it is signed by the attacker key,
	// not key A - the marker does NOT prove key A authorized the rotation.
	// Because the attacker key is not in the trusted set, the segment is
	// REJECTED and the offending key is named.
	marker := &KeyTransition{
		PriorSignerKey: keyA,
		PriorChainSeq:  priorTail.ActionRecord.ChainSeq,
		PriorChainHash: tailA,
	}
	segAttacker, _ := buildSegment(t, privAttacker, 2, tailA, base.Add(time.Hour), marker)
	chain := append(segA, segAttacker...)

	// Trust-on-first-use: only key A is trusted; attacker segment rejected.
	res := VerifyChain(chain, "")
	if res.Valid {
		t.Fatal("forged attacker-key segment with a consistent marker must be REJECTED")
	}
	if res.UntrustedSignerKey != attackerHex {
		t.Errorf("UntrustedSignerKey = %q, want attacker key %q", res.UntrustedSignerKey, attackerHex)
	}

	// Even pinned to key A: rejected (attacker key not trusted).
	if res := VerifyChain(chain, keyA); res.Valid {
		t.Fatal("forged attacker-key segment must be REJECTED when pinned to key A")
	}

	// And a marker that does NOT reference the real prior tail is rejected at
	// the structural-boundary check, before the trust check.
	badMarker := &KeyTransition{
		PriorSignerKey: keyA,
		PriorChainSeq:  priorTail.ActionRecord.ChainSeq,
		PriorChainHash: "attacker-fabricated-prior-hash",
	}
	segBad, _ := buildSegment(t, privAttacker, 2, "attacker-fabricated-prior-hash", base.Add(2*time.Hour), badMarker)
	badChain := append(append([]Receipt{}, segA...), segBad...)
	if res := VerifyChain(badChain, ""); res.Valid {
		t.Fatal("forged segment whose marker does not reference the real prior tail must be REJECTED")
	}
}

func TestVerifyChain_PinnedKeyRejectsForgedGenesisSegment(t *testing.T) {
	t.Parallel()
	pubA, _ := generateTestKey(t)
	_, privAttacker := generateTestKey(t)

	// Attacker builds a chain entirely under their own key. Pinned to the
	// operator's real key A, the FIRST receipt's signature must fail (it is
	// signed by the attacker, not key A).
	chain := buildChain(t, privAttacker, 3)
	res := VerifyChain(chain, hex.EncodeToString(pubA))
	if res.Valid {
		t.Fatal("chain signed entirely by attacker must FAIL when pinned to operator key")
	}
}

func TestVerifyChain_TamperedPriorTailBreaksBoundary(t *testing.T) {
	t.Parallel()
	_, privA := generateTestKey(t)
	_, privB := generateTestKey(t)

	chain := buildRotatedChain(t, privA, privB, 3, 2)
	// Tamper the prior segment's tail (last receipt of segment A, index 2):
	// flip its verdict and re-sign under A so its OWN signature is valid but
	// its hash changes -> the boundary marker's PriorChainHash no longer
	// matches the actual prior tail hash.
	tail := chain[2]
	tail.ActionRecord.Verdict = "allow"
	resigned, err := Sign(tail.ActionRecord, privA)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	chain[2] = resigned

	res := VerifyChain(chain, "")
	if res.Valid {
		t.Fatal("tampering the prior tail must break the boundary validation")
	}
}

func TestVerifyChain_BoundaryFieldMismatchesRejected(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	keyA := hex.EncodeToString(pubA)
	keyB := hex.EncodeToString(pubB)
	trusted := []string{keyA, keyB}

	segA, tailA := buildSegment(t, privA, 3, GenesisHash, base, nil)
	priorTail := segA[len(segA)-1]

	// Wrong prior_signer_key in the marker (does not name the prior segment).
	t.Run("wrong_prior_signer_key", func(t *testing.T) {
		t.Parallel()
		marker := &KeyTransition{
			PriorSignerKey: keyB, // should be keyA
			PriorChainSeq:  priorTail.ActionRecord.ChainSeq,
			PriorChainHash: tailA,
		}
		segB, _ := buildSegment(t, privB, 2, tailA, base.Add(time.Hour), marker)
		if res := VerifyChainTrusted(append(append([]Receipt{}, segA...), segB...), trusted); res.Valid {
			t.Fatal("marker with wrong prior_signer_key must be rejected")
		}
	})

	// Wrong prior_chain_seq in the marker.
	t.Run("wrong_prior_chain_seq", func(t *testing.T) {
		t.Parallel()
		marker := &KeyTransition{
			PriorSignerKey: keyA,
			PriorChainSeq:  priorTail.ActionRecord.ChainSeq + 99,
			PriorChainHash: tailA,
		}
		segB, _ := buildSegment(t, privB, 2, tailA, base.Add(time.Hour), marker)
		if res := VerifyChainTrusted(append(append([]Receipt{}, segA...), segB...), trusted); res.Valid {
			t.Fatal("marker with wrong prior_chain_seq must be rejected")
		}
	})

	// chain_prev_hash on the boundary receipt disagrees with the marker hash.
	t.Run("prev_hash_disagrees_with_marker", func(t *testing.T) {
		t.Parallel()
		marker := &KeyTransition{
			PriorSignerKey: keyA,
			PriorChainSeq:  priorTail.ActionRecord.ChainSeq,
			PriorChainHash: tailA,
		}
		// Sign the boundary receipt with a prev_hash that does NOT match tailA.
		bad := signSegmentReceipt(t, privB, 0, "different-prev-hash", base.Add(time.Hour), marker)
		if res := VerifyChainTrusted(append(append([]Receipt{}, segA...), bad), trusted); res.Valid {
			t.Fatal("boundary receipt whose prev_hash disagrees with the marker must be rejected")
		}
	})
}

func TestVerifyChain_IsolatedSegmentStructuralRejections(t *testing.T) {
	t.Parallel()
	_, priv := generateTestKey(t)
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	// First receipt carrying a marker is rejected before it can be treated as
	// a complete chain, including when seq != 0.
	t.Run("marker_seq_not_zero", func(t *testing.T) {
		t.Parallel()
		marker := &KeyTransition{PriorSignerKey: "k", PriorChainSeq: 1, PriorChainHash: "anchor"}
		r := signSegmentReceipt(t, priv, 5, "anchor", base, marker)
		if res := VerifyChain([]Receipt{r}, ""); res.Valid {
			t.Fatal("isolated marker receipt with seq != 0 must be rejected")
		}
	})

	// First receipt carrying a marker is rejected before it can be treated as
	// a complete chain, including when prev_hash != marker.PriorChainHash.
	t.Run("prev_hash_not_marker_anchor", func(t *testing.T) {
		t.Parallel()
		marker := &KeyTransition{PriorSignerKey: "k", PriorChainSeq: 1, PriorChainHash: "anchor"}
		r := signSegmentReceipt(t, priv, 0, "different-anchor", base, marker)
		if res := VerifyChain([]Receipt{r}, ""); res.Valid {
			t.Fatal("isolated marker receipt whose prev_hash != marker anchor must be rejected")
		}
	})
}

func TestVerifyChain_MarkerOnNonGenesisReceiptRejected(t *testing.T) {
	t.Parallel()
	_, priv := generateTestKey(t)
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	seg, tail := buildSegment(t, priv, 2, GenesisHash, base, nil)
	// Append a receipt at seq 2 that wrongly carries a KeyTransition marker.
	marker := &KeyTransition{
		PriorSignerKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
		PriorChainSeq:  1,
		PriorChainHash: tail,
	}
	bad := signSegmentReceipt(t, priv, 2, tail, base.Add(2*time.Second), marker)
	res := VerifyChain(append(seg, bad), "")
	if res.Valid {
		t.Fatal("a key_transition marker on a non-genesis (seq != 0) receipt must be REJECTED")
	}
}
