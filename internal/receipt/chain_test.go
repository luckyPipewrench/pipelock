// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

	// Tamper with the 3rd receipt's target — breaks its signature.
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

	_, priv := generateTestKey(t)
	chain := buildChain(t, priv, 5)

	root, err := ComputeTranscriptRoot(chainTestSession, chain, "")
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

	_, err := ComputeTranscriptRoot(chainTestSession, nil, "")
	if err == nil {
		t.Fatal("ComputeTranscriptRoot with empty chain should return error")
	}
}

func TestComputeTranscriptRoot_InvalidChain(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	chain := buildChain(t, priv, 3)

	// Tamper to make the chain invalid.
	chain[1].ActionRecord.Target = "https://evil.com/tampered"

	_, err := ComputeTranscriptRoot(chainTestSession, chain, "")
	if err == nil {
		t.Fatal("ComputeTranscriptRoot with invalid chain should return error")
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
	if len(receipts) != chainLen {
		t.Fatalf("expected %d receipts, got %d", chainLen, len(receipts))
	}

	// First receipt should have genesis prev_hash.
	if receipts[0].ActionRecord.ChainPrevHash != GenesisHash {
		t.Errorf("first receipt chain_prev_hash = %q, want %q",
			receipts[0].ActionRecord.ChainPrevHash, GenesisHash)
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
	if result.ReceiptCount != chainLen {
		t.Errorf("VerifyChain receipt_count = %d, want %d", result.ReceiptCount, chainLen)
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
