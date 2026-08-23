// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
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
		Canonicalization:   receipt.DefaultCanonicalizationProfile(),
		Crit:               receipt.CritForPayloadKind(receipt.PayloadShadowDelta),
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

func TestPinnedStreamingVerifierFailsClosedAndLatches(t *testing.T) {
	priv, pub := testKey(t, 9)
	marshal := func(t *testing.T, r receipt.EvidenceReceipt) []byte {
		t.Helper()
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Run("constructor rejects invalid keys", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			key  ed25519.PublicKey
		}{
			{name: "empty"},
			{name: "short", key: ed25519.PublicKey{1}},
			{name: "long", key: make(ed25519.PublicKey, ed25519.PublicKeySize+1)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := receipt.NewPinnedStreamingVerifier(tc.key); err == nil {
					t.Fatal("invalid pinned key accepted")
				}
			})
		}
	})
	t.Run("valid chain reaches a signed head", func(t *testing.T) {
		v, err := receipt.NewPinnedStreamingVerifier(pub)
		if err != nil {
			t.Fatal(err)
		}
		chain := buildChain(t, priv, 2)
		for _, r := range chain {
			if err := v.AddRaw(marshal(t, r)); err != nil {
				t.Fatal(err)
			}
		}
		result := v.Finish()
		if !result.Valid || !result.SignaturesVerified || result.ReceiptCount != 2 {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("invalid input latches independently", func(t *testing.T) {
		badSignature := unsignedReceipt(t, testSignerID, 0, receipt.GenesisHash)
		badSignature = signReceipt(t, badSignature, priv)
		badSignature.Actor = "tampered"
		valid := buildChain(t, priv, 1)[0]
		for _, tc := range []struct {
			name string
			raw  []byte
			want string
		}{
			{name: "empty", raw: []byte{}, want: "decode"},
			{name: "malformed", raw: []byte("[]"), want: "decode"},
			{name: "signature", raw: marshal(t, badSignature), want: "signature"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				v, err := receipt.NewPinnedStreamingVerifier(pub)
				if err != nil {
					t.Fatal(err)
				}
				firstErr := v.AddRaw(tc.raw)
				if firstErr == nil || !strings.Contains(firstErr.Error(), tc.want) {
					t.Fatalf("first AddRaw error = %v, want %q", firstErr, tc.want)
				}
				if err := v.AddRaw(marshal(t, valid)); err == nil || err.Error() != firstErr.Error() {
					t.Fatalf("latched AddRaw error = %v, want original %v", err, firstErr)
				}
				if got := v.Finish(); got.Valid || got.Error != firstErr.Error() {
					t.Fatalf("latched Finish = %+v, want error %q", got, firstErr)
				}
			})
		}
	})
	t.Run("empty verifier is not proof", func(t *testing.T) {
		v, err := receipt.NewPinnedStreamingVerifier(pub)
		if err != nil {
			t.Fatal(err)
		}
		if got := v.Finish(); got.Valid || got.Error != "empty chain" {
			t.Fatalf("empty Finish=%+v", got)
		}
	})
	t.Run("signature signer and chain disagreement deny", func(t *testing.T) {
		v, _ := receipt.NewPinnedStreamingVerifier(pub)
		badSig := unsignedReceipt(t, testSignerID, 0, receipt.GenesisHash)
		badSig = signReceipt(t, badSig, priv)
		badSig.Actor = "tampered"
		if err := v.AddRaw(marshal(t, badSig)); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("signature error=%v", err)
		}
		v, _ = receipt.NewPinnedStreamingVerifier(pub)
		first := buildChain(t, priv, 1)[0]
		if err := v.AddRaw(marshal(t, first)); err != nil {
			t.Fatal(err)
		}
		prev, err := receipt.ReceiptHash(first)
		if err != nil {
			t.Fatal(err)
		}
		other := signReceipt(t, unsignedReceipt(t, "other-signer", 1, prev), priv)
		if err := v.AddRaw(marshal(t, other)); err == nil || !strings.Contains(err.Error(), "signer_key_id") {
			t.Fatalf("signer error=%v", err)
		}
		v, _ = receipt.NewPinnedStreamingVerifier(pub)
		wrongSeq := signReceipt(t, unsignedReceipt(t, testSignerID, 1, receipt.GenesisHash), priv)
		if err := v.AddRaw(marshal(t, wrongSeq)); err == nil || !strings.Contains(err.Error(), "sequence") {
			t.Fatalf("sequence error=%v", err)
		}
	})
}

func TestExtractEvidenceReceiptsFromEntriesUsesWireDetailAndRejectsUnknown(t *testing.T) {
	priv, _ := testKey(t, 10)
	valid := signReceipt(t, unsignedReceipt(t, testSignerID, 0, receipt.GenesisHash), priv)
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	entries := []recorder.Entry{
		{Type: "decision"},
		{Type: receipt.EvidenceEntryType, RawDetail: raw, Detail: map[string]string{"wrong": "shape"}},
		{Type: receipt.EvidenceEntryType, Detail: valid},
	}
	got, err := receipt.ExtractEvidenceReceiptsFromEntries(entries)
	if err != nil || len(got) != 2 {
		t.Fatalf("extract entries=%d err=%v", len(got), err)
	}
	if _, err := receipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{{Type: "unknown"}}); err == nil || !strings.Contains(err.Error(), "unexpected recorder entry type") {
		t.Fatalf("unknown entry error=%v", err)
	}
	if _, err := receipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{{Type: receipt.EvidenceEntryType, Detail: math.Inf(1)}}); err == nil || !strings.Contains(err.Error(), "marshal evidence detail") {
		t.Fatalf("unmarshalable detail error=%v", err)
	}
	if _, err := receipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{{Type: receipt.EvidenceEntryType}}); err == nil || !strings.Contains(err.Error(), "empty detail") {
		t.Fatalf("empty detail error=%v", err)
	}
	if _, err := receipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{{Type: receipt.EvidenceEntryType, RawDetail: []byte("[]")}}); err == nil || !strings.Contains(err.Error(), "decode evidence receipt") {
		t.Fatalf("decode detail error=%v", err)
	}
}

func TestEvidenceDetailFailuresPreserveExtractorContext(t *testing.T) {
	for _, tc := range []struct {
		name       string
		detail     string
		wantDetail string
	}{
		{name: "empty", detail: "null", wantDetail: "evidence entry has empty detail"},
		{name: "malformed", detail: "[]", wantDetail: "decode evidence receipt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := recorder.Entry{Type: receipt.EvidenceEntryType, RawDetail: []byte(tc.detail)}
			if _, err := receipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{entry}); err == nil || !strings.Contains(err.Error(), "parsed recorder entry 1: "+tc.wantDetail) {
				t.Fatalf("parsed extraction error = %v", err)
			}

			path := filepath.Join(t.TempDir(), "evidence.jsonl")
			line := `{"type":"evidence_receipt","detail":` + tc.detail + "}\n"
			if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
				t.Fatalf("write evidence file: %v", err)
			}
			if _, err := receipt.ExtractEvidenceReceipts(path); err == nil || !strings.Contains(err.Error(), path+" line 1: "+tc.wantDetail) {
				t.Fatalf("raw extraction error = %v", err)
			}
		})
	}
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

func TestExtractEvidenceReceipts_RejectsUnexpectedRecorderType(t *testing.T) {
	priv, _ := testKey(t, 1)
	chain := buildChain(t, priv, 1)
	detail, err := json.Marshal(chain[0])
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	good, err := json.Marshal(map[string]json.RawMessage{
		"type":   json.RawMessage(`"evidence_receipt"`),
		"detail": detail,
	})
	if err != nil {
		t.Fatalf("marshal evidence entry: %v", err)
	}
	unknown := []byte(`{"type":"surprise","detail":{"ignored":true}}`)

	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	if err := os.WriteFile(path, append(append(good, '\n'), append(unknown, '\n')...), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := receipt.ExtractEvidenceReceipts(path); err == nil || !strings.Contains(err.Error(), "unexpected recorder entry type") {
		t.Fatalf("ExtractEvidenceReceipts error = %v, want unexpected recorder entry type", err)
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

func TestExtractEvidenceReceiptsFromSessionDirRejectsTiedShardStarts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	data := []byte(`{"type":"evidence_receipt","detail":null}` + "\n")
	for _, name := range []string{"evidence-proxy-0.jsonl", "evidence-proxy-00.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if _, err := receipt.ExtractEvidenceReceiptsFromSessionDir(dir, "proxy"); err == nil {
		t.Fatal("expected tied shard starts to fail closed")
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
