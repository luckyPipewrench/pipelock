// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	portedTestActor        = "agent-alpha"
	portedTestPolicyHash   = "policy-hash-test"
	portedTestPrincipal    = "operator"
	portedTestSessionID    = "session-alpha"
	portedTestTarget       = "https://api.vendor.example/evidence"
	portedTestTransport    = "fetch"
	portedTrustedKeySource = "operator-imported"
)

func TestComputeScorecard_NoTOFU(t *testing.T) {
	t.Parallel()

	pub, priv := generatePortedKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildPortedChain(t, priv, 1)

	score := ComputeScorecard(chain, nil, portedTestSessionID).Scorecard
	assertPortedNotVerify(t, score.Authentic.State, "empty trusted key set")
	if score.Authentic.State != StateWarn {
		t.Fatalf("Authentic.State = %q, want %q", score.Authentic.State, StateWarn)
	}
	if !strings.Contains(score.Authentic.Detail, "UNTRUSTED") {
		t.Fatalf("Authentic.Detail = %q, want UNTRUSTED", score.Authentic.Detail)
	}

	_, forgedPriv := generatePortedKey(t)
	forged := buildPortedChain(t, forgedPriv, 1)
	forgedScore := ComputeScorecard(forged, map[string]TrustedKey{}, portedTestSessionID).Scorecard
	assertPortedNotVerify(t, forgedScore.Authentic.State, "different forged key with empty trusted key set")

	trustedScore := ComputeScorecard(chain, map[string]TrustedKey{
		keyHex: {Source: portedTrustedKeySource},
	}, portedTestSessionID).Scorecard
	if trustedScore.Authentic.State != StateVerify {
		t.Fatalf("Authentic.State = %q, want %q; detail=%s", trustedScore.Authentic.State, StateVerify, trustedScore.Authentic.Detail)
	}
}

func TestComputeScorecard_UntamperedBrokenChain(t *testing.T) {
	t.Parallel()

	pub, priv := generatePortedKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildPortedChain(t, priv, 4)
	chain[1].ActionRecord.Target = "https://api.vendor.example/tampered"

	evidence := SessionEvidenceOf(portedTestSessionID, chain, map[string]TrustedKey{
		keyHex: {Source: portedTrustedKeySource},
	}, false, DashboardReceiptReadLimit, DashboardTimelineLimit)
	if evidence.Scorecard.Untampered.State != StateFail {
		t.Fatalf("Untampered.State = %q, want %q", evidence.Scorecard.Untampered.State, StateFail)
	}
	if evidence.Chain.BrokenAtSeq != 1 {
		t.Fatalf("BrokenAtSeq = %d, want 1", evidence.Chain.BrokenAtSeq)
	}

	for _, item := range evidence.Timeline {
		if item.Seq >= evidence.Chain.BrokenAtSeq && !item.Unverifiable {
			t.Fatalf("seq %d should be marked unverifiable at or after break", item.Seq)
		}
	}
}

func TestComputeScorecard_BrokenReceiptIsNotCountedVerifiable(t *testing.T) {
	t.Parallel()

	pub, priv := generatePortedKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildPortedChain(t, priv, 4)
	chain[1].ActionRecord.Target = "https://api.vendor.example/tampered"

	score := ComputeScorecard(chain, map[string]TrustedKey{
		keyHex: {Source: portedTrustedKeySource},
	}, portedTestSessionID).Scorecard
	if !strings.Contains(score.Completeness.Detail, "1 of 4 receipts verifiable; 3 lost") {
		t.Fatalf("Completeness.Detail = %q, want broken receipt counted lost", score.Completeness.Detail)
	}
	if !strings.Contains(score.Untampered.Detail, "this receipt and later receipts are unverifiable") {
		t.Fatalf("Untampered.Detail = %q, want at-and-after wording", score.Untampered.Detail)
	}
}

func TestComputeScorecard_TimelineWindowUsesGlobalReceiptPosition(t *testing.T) {
	t.Parallel()

	pub, priv := generatePortedKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildPortedChain(t, priv, 4)
	chain[1].ActionRecord.Target = "https://api.vendor.example/tampered"

	evidence := SessionEvidenceOf(portedTestSessionID, chain, map[string]TrustedKey{
		keyHex: {Source: portedTrustedKeySource},
	}, false, DashboardReceiptReadLimit, 1)
	if evidence.TimelineWindow != "latest" {
		t.Fatalf("TimelineWindow = %q, want latest", evidence.TimelineWindow)
	}
	if len(evidence.Timeline) != 1 {
		t.Fatalf("len(Timeline) = %d, want 1", len(evidence.Timeline))
	}
	if !evidence.Timeline[0].Unverifiable {
		t.Fatal("latest displayed receipt should be marked unverifiable after an earlier break")
	}
}

func TestComputeScorecard_RotatedBreakUsesReceiptPositionNotSeq(t *testing.T) {
	t.Parallel()

	pubA, privA := generatePortedKey(t)
	keyA := hex.EncodeToString(pubA)
	pubB, privB := generatePortedKey(t)
	keyB := hex.EncodeToString(pubB)
	chain := buildRotatedPortedChain(t, privA, privB)
	chain[3].ActionRecord.Target = "https://api.vendor.example/tampered-after-rotation"

	evidence := SessionEvidenceOf(portedTestSessionID, chain, map[string]TrustedKey{
		keyA: {Source: portedTrustedKeySource},
		keyB: {Source: portedTrustedKeySource},
	}, false, DashboardReceiptReadLimit, DashboardTimelineLimit)
	if evidence.Chain.Valid {
		t.Fatal("rotated tampered chain should fail verification")
	}
	if evidence.Chain.BrokenAtSeq != 1 {
		t.Fatalf("BrokenAtSeq = %d, want reused rotated seq 1", evidence.Chain.BrokenAtSeq)
	}
	if evidence.Chain.BrokenAtIndex != 3 {
		t.Fatalf("BrokenAtIndex = %d, want 3", evidence.Chain.BrokenAtIndex)
	}
	if !strings.Contains(evidence.Scorecard.Completeness.Detail, "3 of 4 receipts verifiable; 1 lost") {
		t.Fatalf("Completeness.Detail = %q, want only receipts at/after broken index lost", evidence.Scorecard.Completeness.Detail)
	}
	for i, item := range evidence.Timeline {
		if got, want := item.Unverifiable, i >= evidence.Chain.BrokenAtIndex; got != want {
			t.Fatalf("timeline index %d seq %d Unverifiable = %t, want %t", i, item.Seq, got, want)
		}
	}
}

func TestComputeScorecard_RotatedChainDoesNotTrustPresentKeysForAuthentic(t *testing.T) {
	t.Parallel()

	pubA, privA := generatePortedKey(t)
	keyA := hex.EncodeToString(pubA)
	pubB, privB := generatePortedKey(t)
	keyB := hex.EncodeToString(pubB)
	chain := buildRotatedPortedChain(t, privA, privB)

	untrusted := ComputeScorecard(chain, nil, portedTestSessionID)
	if !untrusted.Chain.Valid {
		t.Fatalf("structural rotated chain Valid = false, want true: %s", untrusted.Chain.Error)
	}
	if untrusted.Scorecard.Untampered.State != StateVerify {
		t.Fatalf("Untampered.State = %q, want %q", untrusted.Scorecard.Untampered.State, StateVerify)
	}
	assertPortedNotVerify(t, untrusted.Scorecard.Authentic.State, "rotated chain with only present keys")

	partialTrust := ComputeScorecard(chain, map[string]TrustedKey{
		keyA: {Source: portedTrustedKeySource},
	}, portedTestSessionID)
	if partialTrust.Scorecard.Authentic.State == StateVerify {
		t.Fatal("Authentic returned verify when the rotated segment key was not trusted")
	}
	if partialTrust.Chain.UntrustedSignerKey != keyB {
		t.Fatalf("UntrustedSignerKey = %q, want %q", partialTrust.Chain.UntrustedSignerKey, keyB)
	}
	if partialTrust.Chain.BrokenAtIndex != 2 {
		t.Fatalf("BrokenAtIndex = %d, want 2", partialTrust.Chain.BrokenAtIndex)
	}
	if !strings.Contains(partialTrust.Scorecard.Completeness.Detail, "2 of 4 receipts verifiable; 2 lost") {
		t.Fatalf("Completeness.Detail = %q, want trusted-key break to count receipts at/after broken index lost", partialTrust.Scorecard.Completeness.Detail)
	}

	evidence := SessionEvidenceOf(portedTestSessionID, chain, map[string]TrustedKey{
		keyA: {Source: portedTrustedKeySource},
	}, false, DashboardReceiptReadLimit, DashboardTimelineLimit)
	if evidence.Chain.UntrustedSignerKey != keyB {
		t.Fatalf("evidence UntrustedSignerKey = %q, want %q", evidence.Chain.UntrustedSignerKey, keyB)
	}
	for i, item := range evidence.Timeline {
		if got, want := item.Unverifiable, i >= evidence.Chain.BrokenAtIndex; got != want {
			t.Fatalf("timeline index %d seq %d Unverifiable = %t, want %t", i, item.Seq, got, want)
		}
	}
}

func TestComputeScorecard_ReadLimitedDowngradesGreenProofLines(t *testing.T) {
	t.Parallel()

	pub, priv := generatePortedKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildPortedChain(t, priv, 2)

	evidence := SessionEvidenceOf(portedTestSessionID, chain, map[string]TrustedKey{
		keyHex: {Source: portedTrustedKeySource},
	}, true, 1, DashboardTimelineLimit)
	if !evidence.ReadLimited {
		t.Fatal("evidence should be marked read-limited")
	}
	if evidence.Scorecard.Authentic.State != StateLimited {
		t.Fatalf("Authentic.State = %q, want %q", evidence.Scorecard.Authentic.State, StateLimited)
	}
	if evidence.Scorecard.Untampered.State != StateLimited {
		t.Fatalf("Untampered.State = %q, want %q", evidence.Scorecard.Untampered.State, StateLimited)
	}
	if strings.Contains(evidence.Scorecard.Authentic.Chip, chipSignaturesVerify) {
		t.Fatalf("Authentic.Chip = %q, must not claim full signature verification", evidence.Scorecard.Authentic.Chip)
	}
}

func TestComputeScorecard_CompletenessAndAnchoredNeverGreen(t *testing.T) {
	t.Parallel()

	pub, priv := generatePortedKey(t)
	keyHex := hex.EncodeToString(pub)
	scenarios := map[string][]receipt.Receipt{
		"trusted":   buildPortedChain(t, priv, 2),
		"untrusted": buildPortedChain(t, priv, 1),
		"absent":    nil,
	}
	for name, receipts := range scenarios {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			trusted := map[string]TrustedKey{}
			if name == "trusted" {
				trusted[keyHex] = TrustedKey{Source: portedTrustedKeySource}
			}
			score := ComputeScorecard(receipts, trusted, portedTestSessionID).Scorecard
			if score.Completeness.State != StateLimited {
				t.Fatalf("Completeness.State = %q, want %q", score.Completeness.State, StateLimited)
			}
			if score.Anchored.State == StateVerify {
				t.Fatalf("Anchored.State = %q, MVP must never return green", score.Anchored.State)
			}
			if name != "absent" && score.Anchored.Chip != chipNotAnchored {
				t.Fatalf("Anchored.Chip = %q, want %q", score.Anchored.Chip, chipNotAnchored)
			}
		})
	}
}

func TestComputeScorecard_BoundSessionOpenGenesis(t *testing.T) {
	t.Parallel()

	pub, priv := generatePortedKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildBoundPortedChain(t, priv, keyHex)

	evidence := SessionEvidenceOf(portedTestSessionID, chain, map[string]TrustedKey{
		keyHex: {Source: portedTrustedKeySource},
	}, false, DashboardReceiptReadLimit, DashboardTimelineLimit)
	if !evidence.Chain.Valid {
		t.Fatalf("bound g1 session_open chain should verify in dashboard scorecard: %s", evidence.Chain.Error)
	}
	if evidence.Scorecard.Authentic.State != StateVerify {
		t.Fatalf("Authentic.State = %q, want %q", evidence.Scorecard.Authentic.State, StateVerify)
	}
	if evidence.Scorecard.Untampered.State != StateVerify {
		t.Fatalf("Untampered.State = %q, want %q", evidence.Scorecard.Untampered.State, StateVerify)
	}
	if evidence.Timeline[0].Seq != 0 || evidence.Timeline[0].Unverifiable {
		t.Fatalf("first bound-g1 timeline item = %+v, want verifiable seq 0", evidence.Timeline[0])
	}
}

// --- Ported test helpers (renamed to avoid collision with Wave 1 helpers) ---

func generatePortedKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func buildPortedChain(t *testing.T, priv ed25519.PrivateKey, count int) []receipt.Receipt {
	t.Helper()
	chain := make([]receipt.Receipt, 0, count)
	prevHash := receipt.GenesisHash
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	for i := range count {
		r := signPortedReceipt(t, priv, uint64(i), prevHash, base.Add(time.Duration(i)*time.Second))
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
		chain = append(chain, r)
		prevHash = hash
	}
	return chain
}

func buildBoundPortedChain(t *testing.T, priv ed25519.PrivateKey, signerKey string) []receipt.Receipt {
	t.Helper()
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	open := receipt.SessionOpen{
		RunNonce:        "dashboard-run",
		OpenNonce:       "dashboard-open",
		RecorderSession: "proxy",
		PolicyHash:      portedTestPolicyHash,
		SignerKeyEpoch:  signerKey,
		ChainOpenSeq:    0,
	}
	genesis := receipt.ComputeSessionOpenGenesis(open)
	open.GenesisHash = genesis

	ar := validPortedAction(0, genesis, base)
	ar.RunNonce = open.RunNonce
	ar.Transport = "receipt_session"
	ar.Target = "pipelock://session/open"
	ar.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlOpen,
		Open: &open,
	}
	first, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign bound session_open: %v", err)
	}
	firstHash, err := receipt.ReceiptHash(first)
	if err != nil {
		t.Fatalf("ReceiptHash bound session_open: %v", err)
	}
	second := signPortedReceipt(t, priv, 1, firstHash, base.Add(time.Second))
	second.ActionRecord.RunNonce = open.RunNonce
	second, err = receipt.Sign(second.ActionRecord, priv)
	if err != nil {
		t.Fatalf("Sign bound follow-up: %v", err)
	}
	return []receipt.Receipt{first, second}
}

func buildRotatedPortedChain(t *testing.T, privA, privB ed25519.PrivateKey) []receipt.Receipt {
	t.Helper()
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	chain := buildPortedChain(t, privA, 2)
	priorTail := chain[len(chain)-1]
	priorHash, err := receipt.ReceiptHash(priorTail)
	if err != nil {
		t.Fatalf("ReceiptHash prior tail: %v", err)
	}

	ar := validPortedAction(0, priorHash, base.Add(2*time.Second))
	ar.KeyTransition = &receipt.KeyTransition{
		PriorSignerKey: priorTail.SignerKey,
		PriorChainSeq:  priorTail.ActionRecord.ChainSeq,
		PriorChainHash: priorHash,
	}
	rotatedGenesis, err := receipt.Sign(ar, privB)
	if err != nil {
		t.Fatalf("Sign rotated genesis: %v", err)
	}
	rotatedHash, err := receipt.ReceiptHash(rotatedGenesis)
	if err != nil {
		t.Fatalf("ReceiptHash rotated genesis: %v", err)
	}
	chain = append(chain, rotatedGenesis)
	chain = append(chain, signPortedReceipt(t, privB, 1, rotatedHash, base.Add(3*time.Second)))
	return chain
}

func signPortedReceipt(t *testing.T, priv ed25519.PrivateKey, seq uint64, prevHash string, ts time.Time) receipt.Receipt {
	t.Helper()
	ar := validPortedAction(seq, prevHash, ts)
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func validPortedAction(seq uint64, prevHash string, ts time.Time) receipt.ActionRecord {
	return receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       ts,
		Principal:       portedTestPrincipal,
		Actor:           portedTestActor,
		Target:          portedTestTarget,
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
		PolicyHash:      portedTestPolicyHash,
		Verdict:         "allow",
		SessionID:       portedTestSessionID,
		Transport:       portedTestTransport,
		Method:          http.MethodGet,
		Layer:           "allowlist",
		Pattern:         "api.vendor.example",
		ChainPrevHash:   prevHash,
		ChainSeq:        seq,
	}
}

func assertPortedNotVerify(t *testing.T, got, name string) {
	t.Helper()
	if got == StateVerify {
		t.Fatalf("%s returned %q for an unknown signer", name, StateVerify)
	}
}
