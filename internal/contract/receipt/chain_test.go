// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

const (
	testSignerID    = "receipt-signing-test"
	testContractTag = "sha256:test-contract"
	testManifestTag = "sha256:test-manifest"
)

func shadowDeltaPayload(t *testing.T) json.RawMessage {
	t.Helper()
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     testContractTag,
		RuleID:           "rule-1",
		OriginalVerdict:  "allow",
		CandidateVerdict: "block",
		Aggregation: receipt.ShadowDeltaAggregation{
			WindowStart:      "2026-04-30T00:00:00Z",
			WindowEnd:        "2026-04-30T01:00:00Z",
			LosslessCount:    1,
			DeltaSampleCount: 1,
			ExemplarIDs:      []string{"sha256:exemplar"},
		},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal shadow_delta payload: %v", err)
	}
	return raw
}

// unsignedReceipt builds a structurally valid shadow_delta receipt at the
// given chain position, without a signature.
func unsignedReceipt(t *testing.T, signerID string, seq uint64, prevHash string) receipt.EvidenceReceipt {
	t.Helper()
	return receipt.EvidenceReceipt{
		RecordType:         receipt.RecordTypeEvidenceV2,
		ReceiptVersion:     2,
		PayloadKind:        receipt.PayloadShadowDelta,
		EventID:            "01900000-0000-7000-8000-00000000000" + string(rune('0'+seq%10)),
		Timestamp:          time.Now().UTC(),
		Actor:              "shadow",
		ChainSeq:           seq,
		ChainPrevHash:      prevHash,
		ContractHash:       testContractTag,
		ActiveManifestHash: testManifestTag,
		Payload:            shadowDeltaPayload(t),
		Signature: receipt.SignatureProof{
			SignerKeyID: signerID,
			KeyPurpose:  "receipt-signing",
			Algorithm:   "ed25519",
		},
	}
}

// signReceipt fills in the detached Ed25519 signature over the receipt's
// canonical preimage.
func signReceipt(t *testing.T, r receipt.EvidenceReceipt, priv ed25519.PrivateKey) receipt.EvidenceReceipt {
	t.Helper()
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	r.Signature.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, preimage))
	return r
}

// buildChain returns n signed, correctly-linked shadow_delta receipts signed
// by priv under the test signer id.
func buildChain(t *testing.T, priv ed25519.PrivateKey, n int) []receipt.EvidenceReceipt {
	t.Helper()
	var chain []receipt.EvidenceReceipt
	prev := receipt.GenesisHash
	for i := 0; i < n; i++ {
		r := signReceipt(t, unsignedReceipt(t, testSignerID, uint64(i), prev), priv)
		h, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("hash receipt %d: %v", i, err)
		}
		chain = append(chain, r)
		prev = h
	}
	return chain
}

func testKey(t *testing.T, seedByte byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func TestVerifyChain_ValidPinnedKey(t *testing.T) {
	priv, pub := testKey(t, 1)
	chain := buildChain(t, priv, 3)

	res := receipt.VerifyChain(chain, receipt.ChainVerifyOptions{PinnedKey: pub})
	if !res.Valid {
		t.Fatalf("expected valid chain, got error %q at seq %d", res.Error, res.BrokenAtSeq)
	}
	if !res.SignaturesVerified {
		t.Error("expected SignaturesVerified=true when key pinned")
	}
	if res.ReceiptCount != 3 || res.FinalSeq != 2 {
		t.Errorf("count=%d finalSeq=%d, want 3/2", res.ReceiptCount, res.FinalSeq)
	}
	if res.SignerKeyID != testSignerID {
		t.Errorf("signer=%q, want %q", res.SignerKeyID, testSignerID)
	}
}

func TestVerifyChain_ValidNoKeyIsSelfConsistencyOnly(t *testing.T) {
	priv, _ := testKey(t, 1)
	chain := buildChain(t, priv, 2)

	res := receipt.VerifyChain(chain, receipt.ChainVerifyOptions{})
	if !res.Valid {
		t.Fatalf("expected self-consistent chain valid, got %q", res.Error)
	}
	if res.SignaturesVerified {
		t.Error("SignaturesVerified must be false without a pinned key (self-consistency is not provenance)")
	}
}

// The load-bearing trust-model test: a chain an attacker signs with their own
// key is internally self-consistent and passes WITHOUT a pinned key, but MUST
// be rejected once the legitimate operator key is pinned.
func TestVerifyChain_AttackerSelfConsistentChainRejectedUnderPinnedKey(t *testing.T) {
	attackerPriv, _ := testKey(t, 9)
	_, legitPub := testKey(t, 1)
	forged := buildChain(t, attackerPriv, 2)

	selfConsistent := receipt.VerifyChain(forged, receipt.ChainVerifyOptions{})
	if !selfConsistent.Valid || selfConsistent.SignaturesVerified {
		t.Fatalf("attacker chain should pass self-consistency without provenance, got valid=%v sigVerified=%v",
			selfConsistent.Valid, selfConsistent.SignaturesVerified)
	}

	pinned := receipt.VerifyChain(forged, receipt.ChainVerifyOptions{PinnedKey: legitPub})
	if pinned.Valid {
		t.Fatal("attacker chain must be REJECTED under the pinned legitimate key")
	}
	if pinned.BrokenAtSeq != 0 {
		t.Errorf("expected break at seq 0, got %d", pinned.BrokenAtSeq)
	}
}

func TestVerifyChain_Rejections(t *testing.T) {
	priv, pub := testKey(t, 1)
	_, wrongPub := testKey(t, 2)

	tests := []struct {
		name      string
		mutate    func(chain []receipt.EvidenceReceipt) []receipt.EvidenceReceipt
		opts      receipt.ChainVerifyOptions
		brokenSeq uint64
	}{
		{
			name:   "empty chain",
			mutate: func([]receipt.EvidenceReceipt) []receipt.EvidenceReceipt { return nil },
			opts:   receipt.ChainVerifyOptions{PinnedKey: pub},
		},
		{
			name:      "wrong pinned key",
			mutate:    func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt { return c },
			opts:      receipt.ChainVerifyOptions{PinnedKey: wrongPub},
			brokenSeq: 0,
		},
		{
			name: "tampered payload breaks signature under pinned key",
			mutate: func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt {
				c[1].ContractHash = "sha256:tampered"
				return c
			},
			opts:      receipt.ChainVerifyOptions{PinnedKey: pub},
			brokenSeq: 1,
		},
		{
			name: "bad chain_prev_hash breaks linkage",
			mutate: func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt {
				c[1].ChainPrevHash = "deadbeef"
				return c
			},
			opts:      receipt.ChainVerifyOptions{}, // no key: isolate linkage check
			brokenSeq: 1,
		},
		{
			name: "chain_seq gap",
			mutate: func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt {
				c[1].ChainSeq = 5
				return c
			},
			opts:      receipt.ChainVerifyOptions{},
			brokenSeq: 1,
		},
		{
			name: "signer splice",
			mutate: func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt {
				c[1].Signature.SignerKeyID = "other-signer"
				return c
			},
			opts:      receipt.ChainVerifyOptions{},
			brokenSeq: 1,
		},
		{
			name:      "expect contract hash mismatch",
			mutate:    func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt { return c },
			opts:      receipt.ChainVerifyOptions{PinnedKey: pub, ExpectContractHash: "sha256:other"},
			brokenSeq: 0,
		},
		{
			name:      "expect manifest hash mismatch",
			mutate:    func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt { return c },
			opts:      receipt.ChainVerifyOptions{PinnedKey: pub, ExpectManifestHash: "sha256:other"},
			brokenSeq: 0,
		},
		{
			name:      "expect payload kind mismatch",
			mutate:    func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt { return c },
			opts:      receipt.ChainVerifyOptions{PinnedKey: pub, ExpectPayloadKind: receipt.PayloadProxyDecision},
			brokenSeq: 0,
		},
		{
			name:      "expect signer key id mismatch",
			mutate:    func(c []receipt.EvidenceReceipt) []receipt.EvidenceReceipt { return c },
			opts:      receipt.ChainVerifyOptions{PinnedKey: pub, ExpectSignerKeyID: "someone-else"},
			brokenSeq: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := tc.mutate(buildChain(t, priv, 2))
			res := receipt.VerifyChain(chain, tc.opts)
			if res.Valid {
				t.Fatal("expected chain to be rejected, got valid")
			}
			if res.Error == "" {
				t.Error("expected non-empty error on rejection")
			}
			if len(chain) > 0 && res.BrokenAtSeq != tc.brokenSeq {
				t.Errorf("brokenAtSeq=%d, want %d", res.BrokenAtSeq, tc.brokenSeq)
			}
		})
	}
}

func TestExtractEvidenceReceipts(t *testing.T) {
	priv, pub := testKey(t, 1)
	chain := buildChain(t, priv, 2)

	var lines [][]byte
	// A non-evidence recorder entry that must be skipped.
	lines = append(lines, []byte(`{"type":"checkpoint","detail":{"entry_count":2}}`))
	for _, r := range chain {
		detail, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal receipt: %v", err)
		}
		entry, err := json.Marshal(map[string]json.RawMessage{
			"type":   json.RawMessage(`"evidence_receipt"`),
			"detail": detail,
		})
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		lines = append(lines, entry)
	}
	lines = append(lines, []byte("")) // blank line tolerated

	var buf []byte
	for _, l := range lines {
		buf = append(buf, l...)
		buf = append(buf, '\n')
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := receipt.ExtractEvidenceReceipts(path)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("extracted %d receipts, want 2 (checkpoint must be skipped)", len(got))
	}
	res := receipt.VerifyChain(got, receipt.ChainVerifyOptions{PinnedKey: pub})
	if !res.Valid {
		t.Fatalf("extracted chain failed verification: %q", res.Error)
	}
}

func TestExtractEvidenceReceiptsFromSessionDir(t *testing.T) {
	priv, pub := testKey(t, 1)
	chain := buildChain(t, priv, 2)
	dir := t.TempDir()
	for i, r := range chain {
		detail, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal receipt: %v", err)
		}
		entry, err := json.Marshal(map[string]json.RawMessage{
			"type":   json.RawMessage(`"evidence_receipt"`),
			"detail": detail,
		})
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		path := filepath.Join(dir, "evidence-proxy-"+string(rune('0'+i))+".jsonl")
		if err := os.WriteFile(path, append(entry, '\n'), 0o600); err != nil {
			t.Fatalf("write evidence file: %v", err)
		}
	}
	// Wrong-session files must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "evidence-other-0.jsonl"), []byte(`{"type":"evidence_receipt","detail":null}`+"\n"), 0o600); err != nil {
		t.Fatalf("write other-session file: %v", err)
	}

	got, err := receipt.ExtractEvidenceReceiptsFromSessionDir(dir, "proxy")
	if err != nil {
		t.Fatalf("extract from session dir: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("extracted %d receipts, want 2", len(got))
	}
	res := receipt.VerifyChain(got, receipt.ChainVerifyOptions{PinnedKey: pub})
	if !res.Valid {
		t.Fatalf("extracted dir chain failed verification: %q", res.Error)
	}

	empty, err := receipt.ExtractEvidenceReceiptsFromSessionDir(dir, "missing")
	if err != nil {
		t.Fatalf("extract missing session: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("missing session extracted %d receipts, want 0", len(empty))
	}
}

func TestExtractEvidenceReceiptsFromSessionDir_Errors(t *testing.T) {
	dir := t.TempDir()
	if _, err := receipt.ExtractEvidenceReceiptsFromSessionDir(filepath.Join(dir, "missing"), "proxy"); err == nil {
		t.Fatal("expected missing directory error")
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-bad.jsonl"), []byte("not json\n"), 0o600); err != nil {
		t.Fatalf("write bad evidence file: %v", err)
	}
	if _, err := receipt.ExtractEvidenceReceiptsFromSessionDir(dir, "proxy"); err == nil {
		t.Fatal("expected bad session file error")
	}
}

func TestExtractEvidenceReceipts_Errors(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{"bad recorder json", "{not json}\n"},
		{"empty detail", `{"type":"evidence_receipt","detail":null}` + "\n"},
		{"bad receipt json", `{"type":"evidence_receipt","detail":{"record_type":123}}` + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "f.jsonl")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := receipt.ExtractEvidenceReceipts(path); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}

	if _, err := receipt.ExtractEvidenceReceipts(filepath.Join(dir, "missing.jsonl")); err == nil {
		t.Error("expected error for missing file")
	}
}
