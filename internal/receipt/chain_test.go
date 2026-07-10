// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	chainTestTarget    = "https://example.com/chain"
	chainTestTransport = "fetch"
	chainTestSession   = "session-001"
)

// Ensure crypto/rand is imported for key generation.
var _ = rand.Reader

// signChainReceipt creates a signed receipt with the given chain fields.
func signChainReceipt(t *testing.T, priv ed25519.PrivateKey, seq uint64, prevHash string, ts time.Time) Receipt {
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
	}
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

// buildChain creates a valid chain of n signed receipts.
func buildChain(t *testing.T, priv ed25519.PrivateKey, n int) []Receipt {
	t.Helper()
	chain := make([]Receipt, 0, n)
	prevHash := GenesisHash
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	for i := range n {
		r := signChainReceipt(t, priv, uint64(i), prevHash, base.Add(time.Duration(i)*time.Second))
		h, err := ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
		chain = append(chain, r)
		prevHash = h
	}
	return chain
}

func TestReceiptHash_Deterministic(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signChainReceipt(t, priv, 0, GenesisHash, time.Now().UTC())

	h1, err := ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	h2, err := ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}

	if h1 != h2 {
		t.Errorf("ReceiptHash not deterministic: %q != %q", h1, h2)
	}

	// Must be valid hex, 64 chars (SHA-256).
	if len(h1) != 64 {
		t.Errorf("ReceiptHash length = %d, want 64", len(h1))
	}
	if _, err := hex.DecodeString(h1); err != nil {
		t.Errorf("ReceiptHash not valid hex: %v", err)
	}
}

func TestVerifyChain_EmptyChain(t *testing.T) {
	t.Parallel()

	result := VerifyChain(nil, "")
	if !result.Valid {
		t.Errorf("empty chain should be valid, got error: %s", result.Error)
	}
}

func TestVerifyChain_SingleReceipt(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildChain(t, priv, 1)

	result := VerifyChain(chain, keyHex)
	if !result.Valid {
		t.Fatalf("single receipt chain invalid: %s", result.Error)
	}
	if result.ReceiptCount != 1 {
		t.Errorf("receipt_count = %d, want 1", result.ReceiptCount)
	}
	if result.FinalSeq != 0 {
		t.Errorf("final_seq = %d, want 0", result.FinalSeq)
	}
	if result.RootHash == "" {
		t.Error("root_hash should not be empty")
	}

	// First receipt must have genesis prev_hash.
	if chain[0].ActionRecord.ChainPrevHash != GenesisHash {
		t.Errorf("first receipt chain_prev_hash = %q, want %q",
			chain[0].ActionRecord.ChainPrevHash, GenesisHash)
	}
}

func TestVerifyChain_TenReceipts(t *testing.T) {
	t.Parallel()

	const chainLen = 10
	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildChain(t, priv, chainLen)

	result := VerifyChain(chain, keyHex)
	if !result.Valid {
		t.Fatalf("10-receipt chain invalid: %s", result.Error)
	}
	if result.ReceiptCount != chainLen {
		t.Errorf("receipt_count = %d, want %d", result.ReceiptCount, chainLen)
	}
	if result.FinalSeq != chainLen-1 {
		t.Errorf("final_seq = %d, want %d", result.FinalSeq, chainLen-1)
	}
}

func TestVerifyChain_TamperedMidChain(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildChain(t, priv, 5)

	// Tamper with the 3rd receipt's target - breaks its signature.
	chain[2].ActionRecord.Target = "https://evil.com/tampered"

	result := VerifyChain(chain, keyHex)
	if result.Valid {
		t.Fatal("tampered chain should be invalid")
	}
	if result.BrokenAtSeq != 2 {
		t.Errorf("broken_at_seq = %d, want 2", result.BrokenAtSeq)
	}
}

func TestVerifyChain_SeqGap(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildChain(t, priv, 3)

	// Replace the third receipt with one having seq=5 instead of seq=2.
	prevHash, err := ReceiptHash(chain[1])
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	chain[2] = signChainReceipt(t, priv, 5, prevHash, chain[2].ActionRecord.Timestamp)

	result := VerifyChain(chain, keyHex)
	if result.Valid {
		t.Fatal("chain with seq gap should be invalid")
	}
	if result.BrokenAtSeq != 5 {
		t.Errorf("broken_at_seq = %d, want 5", result.BrokenAtSeq)
	}
}

func TestVerifyChain_WrongPrevHash(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildChain(t, priv, 3)

	// Replace the 2nd receipt with one that has a wrong prev_hash.
	chain[1] = signChainReceipt(t, priv, 1, "wrong-hash", chain[1].ActionRecord.Timestamp)

	result := VerifyChain(chain, keyHex)
	if result.Valid {
		t.Fatal("chain with wrong prev_hash should be invalid")
	}
	if result.BrokenAtSeq != 1 {
		t.Errorf("broken_at_seq = %d, want 1", result.BrokenAtSeq)
	}
}

func TestVerifyChain_InvalidSignature(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildChain(t, priv, 3)

	// Sign the 2nd receipt with a different key.
	_, otherPriv := generateTestKey(t)
	h0, err := ReceiptHash(chain[0])
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	chain[1] = signChainReceipt(t, otherPriv, 1, h0, chain[1].ActionRecord.Timestamp)

	result := VerifyChain(chain, keyHex)
	if result.Valid {
		t.Fatal("chain with invalid signature should be invalid")
	}
	if result.BrokenAtSeq != 1 {
		t.Errorf("broken_at_seq = %d, want 1", result.BrokenAtSeq)
	}
}

func TestVerifyChainIntegrityOnlyNoOpen(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	ar := ActionRecord{
		Version:       ActionRecordVersion,
		ActionID:      NewActionID(),
		ActionType:    ActionUnclassified,
		Timestamp:     time.Date(2026, 7, 6, 14, 0, 0, 0, time.UTC),
		Target:        "pipelock://session/heartbeat",
		Verdict:       testVerdict,
		Transport:     "session_control",
		ChainPrevHash: GenesisHash,
		ChainSeq:      0,
		RunNonce:      "run-no-open-integrity",
		SessionControl: &SessionControl{
			Kind: SessionControlHeartbeat,
			Heartbeat: &SessionHeartbeat{
				RunNonce:         "run-no-open-integrity",
				OpenNonce:        "open-no-open-integrity",
				Beat:             1,
				HeartbeatTime:    time.Date(2026, 7, 6, 14, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
				DurabilityBlocks: 1,
			},
		},
	}
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	chain := []Receipt{r}

	result := VerifyChain(chain, keyHex)
	if result.Valid {
		t.Fatal("chain with run_nonce and no session_open should be invalid")
	}
	if result.FailureKind != ChainFailureLifecycleOpen || !result.IntegrityVerified {
		t.Fatalf("result kind/integrity = %q/%t, want %q/true: %#v",
			result.FailureKind, result.IntegrityVerified, ChainFailureLifecycleOpen, result)
	}
	if integrity := VerifyChainIntegrity(chain, keyHex); !integrity.Valid {
		t.Fatalf("integrity-only verification failed: %s", integrity.Error)
	}

	chain[0].ActionRecord.Target = "https://api.vendor.example/forged-no-open"
	result = VerifyChain(chain, keyHex)
	if result.Valid || result.FailureKind != ChainFailureIntegrity || result.IntegrityVerified {
		t.Fatalf("forged no-open result = valid %t kind %q integrity %t, want integrity failure: %#v",
			result.Valid, result.FailureKind, result.IntegrityVerified, result)
	}
}

func TestVerifyChainFailureKindsDoNotOverDowngrade(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 7, 6, 15, 0, 0, 0, time.UTC)

	t.Run("forged_first_receipt", func(t *testing.T) {
		t.Parallel()
		pub, priv := generateTestKey(t)
		chain := []Receipt{signBoundOpen(t, priv, base)}
		chain[0].ActionRecord.Target = "https://api.vendor.example/forged-first"

		requireChainFailure(t, VerifyChain(chain, hex.EncodeToString(pub)), ChainFailureIntegrity)
	})

	t.Run("forged_mid_chain_receipt", func(t *testing.T) {
		t.Parallel()
		pub, priv := generateTestKey(t)
		open := signBoundOpen(t, priv, base)
		action := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))
		action.ActionRecord.Target = "https://api.vendor.example/forged-mid"

		requireChainFailure(t, VerifyChain([]Receipt{open, action}, hex.EncodeToString(pub)), ChainFailureIntegrity)
	})

	t.Run("forged_heartbeat_in_open_chain", func(t *testing.T) {
		t.Parallel()
		pub, priv := generateTestKey(t)
		open := signBoundOpen(t, priv, base)
		heartbeat := signHeartbeatReceipt(t, priv, 1, mustHash(t, open), "open-a", base.Add(time.Second))
		heartbeat.ActionRecord.Target = "https://api.vendor.example/forged-heartbeat"

		requireChainFailure(t, VerifyChain([]Receipt{open, heartbeat}, hex.EncodeToString(pub)), ChainFailureIntegrity)
	})

	t.Run("forged_close_in_open_chain", func(t *testing.T) {
		t.Parallel()
		pub, priv := generateTestKey(t)
		open := signBoundOpen(t, priv, base)
		closeReceipt := signCloseReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, "open-a", base.Add(time.Second))
		closeReceipt.ActionRecord.Target = "https://api.vendor.example/forged-close"

		requireChainFailure(t, VerifyChain([]Receipt{open, closeReceipt}, hex.EncodeToString(pub)), ChainFailureIntegrity)
	})

	t.Run("untrusted_signer_key", func(t *testing.T) {
		t.Parallel()
		pubA, privA := generateTestKey(t)
		pubB, privB := generateTestKey(t)
		open := signBoundOpen(t, privA, base)
		priorHash := mustHash(t, open)
		marker := &KeyTransition{
			PriorSignerKey: hex.EncodeToString(pubA),
			PriorChainSeq:  open.ActionRecord.ChainSeq,
			PriorChainHash: priorHash,
		}
		rotated := signRestartOpen(t, privB, 0, priorHash, open.ActionRecord.ChainSeq, sessionOpenTestRunB, base.Add(time.Second), marker)

		requireChainFailure(t, VerifyChainTrusted([]Receipt{open, rotated}, []string{hex.EncodeToString(pubA)}), ChainFailureTrust)
		requireChainFailure(t, VerifyChainIntegrityTrusted([]Receipt{open, rotated}, []string{hex.EncodeToString(pubA)}), ChainFailureTrust)
		if res := VerifyChainTrusted([]Receipt{open, rotated}, []string{hex.EncodeToString(pubA), hex.EncodeToString(pubB)}); !res.Valid {
			t.Fatalf("trusted rotation should verify: %s", res.Error)
		}
	})

	t.Run("duplicate_open_lifecycle_failure", func(t *testing.T) {
		t.Parallel()
		pub, priv := generateTestKey(t)
		open := signBoundOpen(t, priv, base)
		priorHash := mustHash(t, open)
		duplicate := signRestartOpen(t, priv, 1, priorHash, open.ActionRecord.ChainSeq, sessionOpenTestRunA, base.Add(time.Second), nil)

		requireChainFailure(t, VerifyChain([]Receipt{open, duplicate}, hex.EncodeToString(pub)), ChainFailureLifecycle)
		if integrity := VerifyChainIntegrity([]Receipt{open, duplicate}, hex.EncodeToString(pub)); !integrity.Valid {
			t.Fatalf("integrity-only duplicate-open chain should verify structurally: %s", integrity.Error)
		}
	})

	t.Run("wrong_open_nonce_lifecycle_failure", func(t *testing.T) {
		t.Parallel()
		pub, priv := generateTestKey(t)
		open := signBoundOpen(t, priv, base)
		heartbeat := signHeartbeatReceipt(t, priv, 1, mustHash(t, open), "wrong-open", base.Add(time.Second))

		requireChainFailure(t, VerifyChain([]Receipt{open, heartbeat}, hex.EncodeToString(pub)), ChainFailureLifecycle)
		if integrity := VerifyChainIntegrity([]Receipt{open, heartbeat}, hex.EncodeToString(pub)); !integrity.Valid {
			t.Fatalf("integrity-only wrong-open-nonce chain should verify structurally: %s", integrity.Error)
		}
	})
}

func signHeartbeatReceipt(t *testing.T, priv ed25519.PrivateKey, seq uint64, prevHash, openNonce string, ts time.Time) Receipt {
	t.Helper()
	return signSessionReceipt(t, priv, seq, prevHash, ts, sessionOpenTestRunA, &SessionControl{
		Kind: SessionControlHeartbeat,
		Heartbeat: &SessionHeartbeat{
			RunNonce:         sessionOpenTestRunA,
			OpenNonce:        openNonce,
			Beat:             1,
			ChainHead:        prevHash,
			ChainSeqHead:     seq - 1,
			HeartbeatTime:    ts.Format(time.RFC3339Nano),
			DurabilityBlocks: 1,
		},
	}, nil)
}

func signCloseReceipt(t *testing.T, priv ed25519.PrivateKey, seq uint64, prevHash, runNonce, openNonce string, ts time.Time) Receipt {
	t.Helper()
	return signSessionReceipt(t, priv, seq, prevHash, ts, runNonce, &SessionControl{
		Kind: SessionControlClose,
		Close: &SessionClose{
			RunNonce:         runNonce,
			OpenNonce:        openNonce,
			FinalSeq:         seq,
			RootHash:         prevHash,
			ReceiptCount:     seq + 1,
			CloseReason:      "normal",
			DurabilityBlocks: 1,
		},
	}, nil)
}

func requireChainFailure(t *testing.T, res ChainResult, want ChainFailureKind) {
	t.Helper()
	if res.Valid || res.FailureKind != want || res.IntegrityVerified {
		t.Fatalf("result = valid %t kind %q integrity %t, want invalid %q integrity false: %#v",
			res.Valid, res.FailureKind, res.IntegrityVerified, want, res)
	}
}

func TestVerifyChain_NoKeyPinning(t *testing.T) {
	t.Parallel()

	// Verify with empty expectedKeyHex uses embedded key.
	_, priv := generateTestKey(t)
	chain := buildChain(t, priv, 3)

	result := VerifyChain(chain, "")
	if !result.Valid {
		t.Fatalf("chain with embedded key verification failed: %s", result.Error)
	}
}

func TestVerifyChain_TimestampOrdering(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	chain := buildChain(t, priv, 3)

	result := VerifyChain(chain, "")
	if !result.Valid {
		t.Fatalf("chain should be valid: %s", result.Error)
	}

	if result.StartTime.After(result.EndTime) {
		t.Errorf("start_time %v should be <= end_time %v", result.StartTime, result.EndTime)
	}
}

func TestComputeTranscriptRoot_HappyPath(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildChain(t, priv, 5)

	root, err := ComputeTranscriptRoot(chainTestSession, chain, keyHex)
	if err != nil {
		t.Fatalf("ComputeTranscriptRoot: %v", err)
	}

	if root.SessionID != chainTestSession {
		t.Errorf("session_id = %q, want %q", root.SessionID, chainTestSession)
	}
	if root.ReceiptCount != 5 {
		t.Errorf("receipt_count = %d, want 5", root.ReceiptCount)
	}
	if root.FinalSeq != 4 {
		t.Errorf("final_seq = %d, want 4", root.FinalSeq)
	}
	if root.RootHash == "" {
		t.Error("root_hash should not be empty")
	}
	if root.StartTime.IsZero() {
		t.Error("start_time should not be zero")
	}
	if root.EndTime.IsZero() {
		t.Error("end_time should not be zero")
	}
}

func TestComputeTranscriptRoot_EmptyChain(t *testing.T) {
	t.Parallel()

	_, err := ComputeTranscriptRoot(chainTestSession, nil, "deadbeef")
	if err == nil {
		t.Fatal("ComputeTranscriptRoot with empty chain should return error")
	}
}

func TestComputeTranscriptRoot_InvalidChain(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildChain(t, priv, 3)

	// Tamper to make the chain invalid.
	chain[1].ActionRecord.Target = "https://evil.com/tampered"

	_, err := ComputeTranscriptRoot(chainTestSession, chain, keyHex)
	if err == nil {
		t.Fatal("ComputeTranscriptRoot with invalid chain should return error")
	}
}

func TestComputeTranscriptRoot_RequiresKey(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	chain := buildChain(t, priv, 3)

	_, err := ComputeTranscriptRoot(chainTestSession, chain, "")
	if err == nil {
		t.Fatal("ComputeTranscriptRoot with empty key should return error")
	}
}

func TestExtractReceipts_HappyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "testhash",
		Principal:  "test-principal",
	})
	emitSessionOpenForTest(t, e)

	for i := 0; i < 3; i++ {
		if err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    chainTestTarget,
			Verdict:   "block",
			Transport: chainTestTransport,
		}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	_ = rec.Close()

	// Find the JSONL file
	entries, _ := os.ReadDir(dir)
	var jsonlPath string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".jsonl") {
			jsonlPath = filepath.Join(dir, entry.Name())
			break
		}
	}
	if jsonlPath == "" {
		t.Fatal("no JSONL file found")
	}

	receipts, err := ExtractReceipts(jsonlPath)
	if err != nil {
		t.Fatalf("ExtractReceipts: %v", err)
	}
	if len(receipts) != 4 {
		t.Fatalf("expected 4 receipts, got %d", len(receipts))
	}

	// Verify the extracted chain
	keyHex := hex.EncodeToString(pub)
	result := VerifyChain(receipts, keyHex)
	if !result.Valid {
		t.Fatalf("extracted chain invalid: %s", result.Error)
	}
}

func TestExtractReceipts_RawJSONL(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	now := time.Now().UTC()
	var receipts []Receipt
	prev := GenesisHash
	for seq := uint64(0); seq < 3; seq++ {
		r := signChainReceipt(t, priv, seq, prev, now.Add(time.Duration(seq)*time.Second))
		receipts = append(receipts, r)
		hash, err := ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash %d: %v", seq, err)
		}
		prev = hash
	}

	var raw strings.Builder
	raw.WriteByte('\n')
	for _, r := range receipts {
		data, err := Marshal(r)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		raw.Write(data)
		raw.WriteString("\n\n")
	}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := os.WriteFile(path, []byte(raw.String()), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := ExtractReceipts(path)
	if err != nil {
		t.Fatalf("ExtractReceipts: %v", err)
	}
	if len(got) != len(receipts) {
		t.Fatalf("receipt count = %d, want %d", len(got), len(receipts))
	}
	result := VerifyChain(got, got[0].SignerKey)
	if !result.Valid {
		t.Fatalf("raw chain invalid: %s", result.Error)
	}
}

func TestExtractReceiptsBytes_RawJSONL(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	receipts := buildChain(t, priv, 2)

	var raw strings.Builder
	raw.WriteByte('\n')
	for _, r := range receipts {
		data, err := Marshal(r)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		raw.Write(data)
		raw.WriteString("\n\n")
	}

	got, err := ExtractReceiptsBytes([]byte(raw.String()))
	if err != nil {
		t.Fatalf("ExtractReceiptsBytes: %v", err)
	}
	if len(got) != len(receipts) {
		t.Fatalf("receipt count = %d, want %d", len(got), len(receipts))
	}
	result := VerifyChain(got, got[0].SignerKey)
	if !result.Valid {
		t.Fatalf("raw byte chain invalid: %s", result.Error)
	}
}

func TestExtractReceiptsBytes_RecorderEntries(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signChainReceipt(t, priv, 0, GenesisHash, time.Now().UTC())
	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  0,
		Timestamp: r.ActionRecord.Timestamp,
		SessionID: chainTestSession,
		Type:      recorderEntryType,
		Transport: chainTestTransport,
		Summary:   "signed receipt",
		Detail:    r,
		PrevHash:  recorder.GenesisHash,
	}
	entry.Hash = recorder.ComputeHash(entry)
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal entry: %v", err)
	}
	data = append(data, '\n')

	got, err := ExtractReceiptsBytes(data)
	if err != nil {
		t.Fatalf("ExtractReceiptsBytes: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("receipt count = %d, want 1", len(got))
	}
	if got[0].ActionRecord.Target != chainTestTarget {
		t.Fatalf("receipt target = %q, want %q", got[0].ActionRecord.Target, chainTestTarget)
	}
}

func TestExtractReceipts_RawJSONLRejectsMalformedTail(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signChainReceipt(t, priv, 0, GenesisHash, time.Now().UTC())
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := os.WriteFile(path, append(data, []byte("\nnot-json\n")...), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = ExtractReceipts(path)
	if err == nil || !strings.Contains(err.Error(), "parse raw receipt line 2") {
		t.Fatalf("ExtractReceipts error = %v, want raw line parse error", err)
	}
}

func TestExtractReceiptsBytes_RejectsMalformedTail(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signChainReceipt(t, priv, 0, GenesisHash, time.Now().UTC())
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	_, err = ExtractReceiptsBytes(append(data, []byte("\nnot-json\n")...))
	if err == nil || !strings.Contains(err.Error(), "parse raw receipt line 2") {
		t.Fatalf("ExtractReceiptsBytes error = %v, want raw line parse error", err)
	}
}

func TestExtractReceiptsBytes_RejectsUnreadableEvidence(t *testing.T) {
	t.Parallel()

	_, err := ExtractReceiptsBytes([]byte("not-json\n"))
	if err == nil || !strings.Contains(err.Error(), "reading entries") {
		t.Fatalf("ExtractReceiptsBytes error = %v, want recorder read error", err)
	}
}

func TestExtractReceipts_RawJSONLRejectsMissingFieldsTail(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signChainReceipt(t, priv, 0, GenesisHash, time.Now().UTC())
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	body := append(data, []byte("\n{\"version\":1}\n")...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = ExtractReceipts(path)
	if err == nil || !strings.Contains(err.Error(), "missing receipt fields") {
		t.Fatalf("ExtractReceipts error = %v, want missing fields error", err)
	}
}

func TestExtractReceipts_RawJSONLIgnoresNonReceiptFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "not-receipts.jsonl")
	if err := os.WriteFile(path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := extractRawReceiptsJSONLFile(path)
	if err != nil {
		t.Fatalf("extractRawReceiptsJSONLFile: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("receipt count = %d, want 0", len(got))
	}
}

func TestExtractReceipts_RecorderFileWithoutReceipts(t *testing.T) {
	t.Parallel()

	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  0,
		Timestamp: time.Now().UTC(),
		SessionID: "session-no-receipts",
		Type:      "decision",
		Transport: "fetch",
		Summary:   "operational entry only",
		PrevHash:  recorder.GenesisHash,
	}
	entry.Hash = recorder.ComputeHash(entry)

	path := filepath.Join(t.TempDir(), "evidence-session-no-receipts-0.jsonl")
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := json.NewEncoder(f).Encode(entry); err != nil {
		_ = f.Close()
		t.Fatalf("Encode: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := ExtractReceipts(path)
	if err != nil {
		t.Fatalf("ExtractReceipts: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("receipt count = %d, want 0", len(got))
	}
}

func TestExtractReceipts_BadPath(t *testing.T) {
	t.Parallel()

	_, err := ExtractReceipts("/nonexistent/path.jsonl")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestConfigHashString(t *testing.T) {
	t.Parallel()

	if got := configHashString("hello"); got != "hello" {
		t.Errorf("configHashString(string) = %q, want \"hello\"", got)
	}
	if got := configHashString(nil); got != "" {
		t.Errorf("configHashString(nil) = %q, want empty", got)
	}
	if got := configHashString(42); got != "" {
		t.Errorf("configHashString(int) = %q, want empty", got)
	}
}

func TestEmitTranscriptRoot_NilEmitter(t *testing.T) {
	t.Parallel()

	var e *Emitter
	err := e.EmitTranscriptRoot(chainTestSession)
	if err != nil {
		t.Errorf("EmitTranscriptRoot on nil emitter should be no-op, got: %v", err)
	}
}

func TestEmitTranscriptRoot_NoReceipts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})

	// No receipts emitted -- EmitTranscriptRoot should be a no-op.
	err := e.EmitTranscriptRoot(chainTestSession)
	if err != nil {
		t.Errorf("EmitTranscriptRoot with no receipts should be no-op, got: %v", err)
	}
}

// TestResume_AfterTranscriptRoot_DoesNotBrick is the FIX-TRAP B regression. Once
// EmitTranscriptRoot has a production caller (graceful shutdown), a transcript
// root lands as the newest evidence entry on clean exit. A resume that treated
// the root as a permanent on-disk seal would set rootEmitted and make every Emit
// after the first clean shutdown return ErrChainSealed - silently killing
// receipts. This proves a restart after a sealed shutdown resumes emitting into
// one continuous, verifiable chain.
func TestResume_AfterTranscriptRoot_DoesNotBrick(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)

	emit := func(e *Emitter) error {
		return e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    chainTestTarget,
			Verdict:   config.ActionAllow,
			Transport: chainTestTransport,
			Method:    http.MethodGet,
		})
	}

	// Run 1: emit 2 receipts, seal with a transcript root, shut down.
	rec1 := newTestRecorder(t, dir, priv)
	e1 := NewEmitter(EmitterConfig{Recorder: rec1, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	emitSessionOpenForTest(t, e1)
	for range 2 {
		if err := emit(e1); err != nil {
			t.Fatalf("run1 Emit: %v", err)
		}
	}
	if err := e1.EmitTranscriptRoot(chainTestSession); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}
	if err := rec1.Close(); err != nil {
		t.Fatalf("close rec1: %v", err)
	}

	// Run 2: restart against the SAME evidence dir (sealed tail on disk).
	rec2 := newTestRecorder(t, dir, priv)
	e2 := NewEmitter(EmitterConfig{Recorder: rec2, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	if e2 == nil {
		t.Fatal("emitter nil after resume")
	}
	if err := e2.InitError(); err != nil {
		t.Fatalf("resume after sealed shutdown errored (should resume cleanly): %v", err)
	}
	emitSessionOpenForTest(t, e2)
	// The post-seal restart MUST emit (not be bricked by ErrChainSealed).
	for range 2 {
		if err := emit(e2); err != nil {
			t.Fatalf("post-seal restart Emit bricked: %v", err)
		}
	}
	if err := rec2.Close(); err != nil {
		t.Fatalf("close rec2: %v", err)
	}

	// All 6 action receipts (session_open + 2 decisions per run) form one
	// continuous, verifiable chain.
	entries := readAllEntriesFromDir(t, dir)
	var receipts []Receipt
	for i := range entries {
		if entries[i].Type != recorderEntryType {
			continue
		}
		r, err := receiptFromEntry(entries[i])
		if err != nil {
			t.Fatalf("parse receipt: %v", err)
		}
		receipts = append(receipts, *r)
	}
	if len(receipts) != 6 {
		t.Fatalf("expected 6 action receipts across both runs, got %d", len(receipts))
	}
	res := VerifyChain(receipts, "")
	if !res.Valid {
		t.Fatalf("post-seal chain failed to verify: %s", res.Error)
	}
	if res.ReceiptCount != 6 {
		t.Errorf("ReceiptCount = %d, want 6 (seq must continue across the seal, not reset)", res.ReceiptCount)
	}
}

func TestEmitTranscriptRoot_HappyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})

	// Emit 3 receipts.
	for range 3 {
		err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    chainTestTarget,
			Verdict:   config.ActionAllow,
			Transport: chainTestTransport,
			Method:    http.MethodGet,
		})
		if err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}

	// Emit transcript root.
	err := e.EmitTranscriptRoot(chainTestSession)
	if err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read all entries and find the transcript_root.
	entries := readAllEntriesFromDir(t, dir)
	var rootEntry *recorder.Entry
	for i := range entries {
		if entries[i].Type == transcriptRootEntryType {
			rootEntry = &entries[i]
			break
		}
	}
	if rootEntry == nil {
		t.Fatal("transcript_root entry not found in recorder output")
	}

	// Parse the root detail.
	detailJSON, err := json.Marshal(rootEntry.Detail)
	if err != nil {
		t.Fatalf("json.Marshal(detail): %v", err)
	}
	var root TranscriptRoot
	if err := json.Unmarshal(detailJSON, &root); err != nil {
		t.Fatalf("json.Unmarshal(root): %v", err)
	}

	if root.SessionID != chainTestSession {
		t.Errorf("session_id = %q, want %q", root.SessionID, chainTestSession)
	}
	if root.ReceiptCount != 3 {
		t.Errorf("receipt_count = %d, want 3", root.ReceiptCount)
	}
	if root.FinalSeq != 2 {
		t.Errorf("final_seq = %d, want 2", root.FinalSeq)
	}
	if root.RootHash == "" {
		t.Error("root_hash should not be empty")
	}
}

func TestEmitter_ChainState(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	emitSessionOpenForTest(t, e)

	const chainLen = 5
	for range chainLen {
		err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    chainTestTarget,
			Verdict:   config.ActionAllow,
			Transport: chainTestTransport,
			Method:    http.MethodGet,
		})
		if err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read all receipts and verify chain integrity.
	receipts := readAllReceiptsFromDir(t, dir, pub)
	if len(receipts) != chainLen+1 {
		t.Fatalf("expected %d receipts, got %d", chainLen+1, len(receipts))
	}

	// First receipt should have a bound session-open genesis prev_hash.
	if !strings.HasPrefix(receipts[0].ActionRecord.ChainPrevHash, genesisSessionOpenPrefix) {
		t.Errorf("first receipt chain_prev_hash = %q, want %q prefix",
			receipts[0].ActionRecord.ChainPrevHash, genesisSessionOpenPrefix)
	}

	// Each receipt's seq should increment by 1.
	for i, r := range receipts {
		if r.ActionRecord.ChainSeq != uint64(i) {
			t.Errorf("receipt[%d] chain_seq = %d, want %d",
				i, r.ActionRecord.ChainSeq, i)
		}
	}

	// Each receipt's prev_hash should match the hash of the previous receipt.
	for i := 1; i < len(receipts); i++ {
		prevHash, err := ReceiptHash(receipts[i-1])
		if err != nil {
			t.Fatalf("ReceiptHash[%d]: %v", i-1, err)
		}
		if receipts[i].ActionRecord.ChainPrevHash != prevHash {
			t.Errorf("receipt[%d] chain_prev_hash mismatch: got %q, want %q",
				i, receipts[i].ActionRecord.ChainPrevHash, prevHash)
		}
	}

	// Full chain verification should pass.
	keyHex := hex.EncodeToString(pub)
	result := VerifyChain(receipts, keyHex)
	if !result.Valid {
		t.Fatalf("VerifyChain failed: %s", result.Error)
	}
	if result.ReceiptCount != chainLen+1 {
		t.Errorf("VerifyChain receipt_count = %d, want %d", result.ReceiptCount, chainLen+1)
	}
}

func TestEmit_ChainSealed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  "test",
	})

	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    chainTestTarget,
		Verdict:   "block",
		Transport: chainTestTransport,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := e.EmitTranscriptRoot(chainTestSession); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}

	// Emit after root should fail with ErrChainSealed.
	err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    chainTestTarget,
		Verdict:   "allow",
		Transport: chainTestTransport,
	})
	if err == nil {
		t.Fatal("expected ErrChainSealed after EmitTranscriptRoot")
	}
	if !errors.Is(err, ErrChainSealed) {
		t.Errorf("expected ErrChainSealed, got: %v", err)
	}
}

func TestEmitTranscriptRoot_TimeBounds(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  "test",
	})

	before := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    chainTestTarget,
			Verdict:   "block",
			Transport: chainTestTransport,
		}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	after := time.Now().UTC()

	if err := e.EmitTranscriptRoot(chainTestSession); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}

	entries := readAllEntriesFromDir(t, dir)
	for _, entry := range entries {
		if entry.Type != transcriptRootEntryType {
			continue
		}
		detailJSON, _ := json.Marshal(entry.Detail)
		var root TranscriptRoot
		if err := json.Unmarshal(detailJSON, &root); err != nil {
			t.Fatalf("unmarshal root: %v", err)
		}
		if root.StartTime.Before(before) || root.StartTime.After(after) {
			t.Errorf("start_time %v outside [%v, %v]", root.StartTime, before, after)
		}
		if root.EndTime.Before(root.StartTime) {
			t.Errorf("end_time %v before start_time %v", root.EndTime, root.StartTime)
		}
		return
	}
	t.Fatal("transcript_root entry not found")
}

func TestEmitter_ResumesChainAfterRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)

	newEmitter := func() (*recorder.Recorder, *Emitter) {
		rec := newTestRecorder(t, dir, priv)
		e := NewEmitter(EmitterConfig{
			Recorder:   rec,
			PrivKey:    priv,
			ConfigHash: testConfigHash,
			Principal:  "test",
		})
		if e == nil {
			t.Fatal("NewEmitter() returned nil")
		}
		emitSessionOpenForTest(t, e)
		return rec, e
	}

	rec1, emitter1 := newEmitter()
	for i := 0; i < 2; i++ {
		if err := emitter1.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    chainTestTarget,
			Verdict:   "allow",
			Transport: chainTestTransport,
			Method:    http.MethodGet,
		}); err != nil {
			t.Fatalf("emitter1.Emit(%d): %v", i, err)
		}
	}
	if err := rec1.Close(); err != nil {
		t.Fatalf("rec1.Close(): %v", err)
	}

	rec2, emitter2 := newEmitter()
	if err := emitter2.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    chainTestTarget,
		Verdict:   "allow",
		Transport: chainTestTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("emitter2.Emit(): %v", err)
	}
	if err := rec2.Close(); err != nil {
		t.Fatalf("rec2.Close(): %v", err)
	}

	result, err := recorder.QuerySession(dir, "proxy", &recorder.QueryFilter{Type: recorderEntryType})
	if err != nil {
		t.Fatalf("QuerySession(): %v", err)
	}
	if len(result.Entries) != 5 {
		t.Fatalf("receipt entry count = %d, want 5", len(result.Entries))
	}

	receipts := make([]Receipt, 0, len(result.Entries))
	for _, entry := range result.Entries {
		detailJSON, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatalf("json.Marshal(detail): %v", err)
		}
		rcpt, err := Unmarshal(detailJSON)
		if err != nil {
			t.Fatalf("Unmarshal(): %v", err)
		}
		receipts = append(receipts, rcpt)
	}

	chainResult := VerifyChain(receipts, hex.EncodeToString(pub))
	if !chainResult.Valid {
		t.Fatalf("VerifyChain(): %s", chainResult.Error)
	}
	for i, rcpt := range receipts {
		if rcpt.ActionRecord.ChainSeq != uint64(i) {
			t.Fatalf("receipt[%d].ChainSeq = %d, want %d", i, rcpt.ActionRecord.ChainSeq, i)
		}
	}
}

func TestExtractReceiptsWithSessionID_HappyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
	})
	emitSessionOpenForTest(t, e)

	for i := 0; i < 3; i++ {
		if err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    chainTestTarget,
			Verdict:   config.ActionBlock,
			Transport: chainTestTransport,
			Method:    http.MethodGet,
		}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	_ = rec.Close()

	// Find JSONL file.
	entries, _ := os.ReadDir(dir)
	var jsonlPath string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".jsonl") {
			jsonlPath = filepath.Join(dir, entry.Name())
			break
		}
	}
	if jsonlPath == "" {
		t.Fatal("no JSONL file found")
	}

	receipts, sessionID, err := ExtractReceiptsWithSessionID(jsonlPath)
	if err != nil {
		t.Fatalf("ExtractReceiptsWithSessionID: %v", err)
	}
	if len(receipts) != 4 {
		t.Fatalf("expected 4 receipts, got %d", len(receipts))
	}
	if sessionID == "" {
		t.Fatal("expected non-empty session ID")
	}

	keyHex := hex.EncodeToString(pub)
	result := VerifyChain(receipts, keyHex)
	if !result.Valid {
		t.Fatalf("extracted chain invalid: %s", result.Error)
	}
}

func TestExtractReceiptsWithSessionID_EmptyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(emptyPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	receipts, sessionID, err := ExtractReceiptsWithSessionID(emptyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receipts) != 0 {
		t.Fatalf("expected 0 receipts, got %d", len(receipts))
	}
	if sessionID != "" {
		t.Fatalf("expected empty session ID, got %q", sessionID)
	}
}

func TestExtractReceiptsWithSessionID_BadPath(t *testing.T) {
	t.Parallel()

	_, _, err := ExtractReceiptsWithSessionID("/nonexistent/path.jsonl")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestExtractReceiptsFromSessionDir_HappyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
	})

	for i := 0; i < 2; i++ {
		if err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    chainTestTarget,
			Verdict:   config.ActionAllow,
			Transport: chainTestTransport,
			Method:    http.MethodGet,
		}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	_ = rec.Close()

	// The recorder uses "proxy" as the session ID.
	receipts, err := ExtractReceiptsFromSessionDir(dir, "proxy")
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(receipts))
	}
}

func TestExtractReceiptsFromSessionDir_NoMatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	_ = rec.Close()

	// Query with a session ID that doesn't match any files.
	receipts, err := ExtractReceiptsFromSessionDir(dir, "nonexistent-session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receipts) != 0 {
		t.Fatalf("expected 0 receipts, got %d", len(receipts))
	}
}

func TestExtractReceiptsFromSessionDir_BadDir(t *testing.T) {
	t.Parallel()

	_, err := ExtractReceiptsFromSessionDir("/nonexistent/dir", "any-session")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

// readAllEntriesFromDir reads all recorder entries from JSONL files in dir.
func readAllEntriesFromDir(t *testing.T, dir string) []recorder.Entry {
	t.Helper()

	dirEntries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}

	var entries []recorder.Entry
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(dir, de.Name())
		fileEntries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatalf("ReadEntries(%q): %v", path, err)
		}
		entries = append(entries, fileEntries...)
	}
	return entries
}
