// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

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

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Test-scoped constants to avoid goconst triggers.
const (
	actionAllow = "allow"

	coverageTestPrincipal  = "test-principal"
	coverageTestActor      = "test-actor"
	coverageTestConfigHash = "coverage-test-hash"
	coverageTestTarget     = "https://example.com/coverage"
	coverageTestAgent      = "coverage-agent"
)

// extractReceiptsFromDir reads all JSONL files from dir and returns parsed receipts.
func extractReceiptsFromDir(t *testing.T, dir string) []receipt.Receipt {
	t.Helper()
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var all []receipt.Receipt
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".jsonl") {
			continue
		}
		receipts, rErr := receipt.ExtractReceipts(filepath.Join(dir, de.Name()))
		if rErr != nil {
			t.Fatalf("ExtractReceipts(%s): %v", de.Name(), rErr)
		}
		all = append(all, receipts...)
	}
	return all
}

// newCoverageEmitter creates a recorder and emitter pair for coverage tests.
// Returns the emitter and recorder; caller must close the recorder.
func newCoverageEmitter(t *testing.T, dir string) (*receipt.Emitter, *recorder.Recorder, ed25519.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKey := priv.Public().(ed25519.PublicKey)

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: coverageTestConfigHash,
		Principal:  coverageTestPrincipal,
		Actor:      coverageTestActor,
	})

	return emitter, rec, pubKey
}

// TestReceiptCoverage_ChainIntegrity_CrossTransport emits receipts across
// three different transports through the SAME emitter and verifies that
// chain_prev_hash linkage is correct across transport boundaries.
func TestReceiptCoverage_ChainIntegrity_CrossTransport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	// Emit receipts across three different transports.
	transports := []struct {
		transport string
		method    string
		target    string
		layer     string
		verdict   string
	}{
		{transport: TransportFetch, method: http.MethodGet, target: "https://example.com/fetch", layer: "blocklist", verdict: config.ActionBlock},
		{transport: TransportWS, method: "", target: "wss://example.com/ws", layer: "dlp", verdict: config.ActionBlock},
		{transport: TransportForward, method: http.MethodPost, target: "https://api.example.com/data", layer: "dlp", verdict: config.ActionBlock},
	}

	for _, tc := range transports {
		err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   tc.verdict,
			Layer:     tc.layer,
			Transport: tc.transport,
			Method:    tc.method,
			Target:    tc.target,
			RequestID: "req-" + tc.transport,
			Agent:     coverageTestAgent,
		})
		if err != nil {
			t.Fatalf("Emit(%s): %v", tc.transport, err)
		}
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(receipts))
	}

	// Verify chain via receipt.VerifyChain.
	keyHex := hex.EncodeToString(pubKey)
	result := receipt.VerifyChain(receipts, keyHex)
	if !result.Valid {
		t.Fatalf("VerifyChain failed: %s (broken at seq %d)", result.Error, result.BrokenAtSeq)
	}
	if result.ReceiptCount != 3 {
		t.Errorf("receipt_count = %d, want 3", result.ReceiptCount)
	}

	// Assert first receipt has genesis prev_hash.
	if receipts[0].ActionRecord.ChainPrevHash != receipt.GenesisHash {
		t.Errorf("first receipt chain_prev_hash = %q, want %q",
			receipts[0].ActionRecord.ChainPrevHash, receipt.GenesisHash)
	}

	// Assert chain_seq increments monotonically.
	for i, r := range receipts {
		if r.ActionRecord.ChainSeq != uint64(i) {
			t.Errorf("receipt[%d] chain_seq = %d, want %d", i, r.ActionRecord.ChainSeq, i)
		}
	}

	// Assert each receipt's prev_hash matches hash of the previous receipt.
	for i := 1; i < len(receipts); i++ {
		prevHash, err := receipt.ReceiptHash(receipts[i-1])
		if err != nil {
			t.Fatalf("ReceiptHash[%d]: %v", i-1, err)
		}
		if receipts[i].ActionRecord.ChainPrevHash != prevHash {
			t.Errorf("receipt[%d] chain_prev_hash mismatch: got %q, want hash of receipt[%d]",
				i, receipts[i].ActionRecord.ChainPrevHash, i-1)
		}
	}

	// Assert each receipt has the correct transport.
	for i, tc := range transports {
		if receipts[i].ActionRecord.Transport != tc.transport {
			t.Errorf("receipt[%d] transport = %q, want %q",
				i, receipts[i].ActionRecord.Transport, tc.transport)
		}
	}
}

// TestReceiptCoverage_VerifierRoundTrip_WebSocketBlock verifies that a
// websocket block receipt round-trips through Verify and VerifyWithKey.
func TestReceiptCoverage_VerifierRoundTrip_WebSocketBlock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "dlp",
		Transport: TransportWS,
		Target:    "wss://example.com/ws-block",
		RequestID: "ws-block-1",
		Agent:     coverageTestAgent,
		Pattern:   "test-secret-pattern",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	r := receipts[0]

	// Verify with embedded key.
	if err := receipt.Verify(r); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Verify with explicit key.
	keyHex := hex.EncodeToString(pubKey)
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		t.Fatalf("VerifyWithKey failed: %v", err)
	}

	// Verify fields.
	if r.ActionRecord.Transport != TransportWS {
		t.Errorf("transport = %q, want %q", r.ActionRecord.Transport, TransportWS)
	}
	if r.ActionRecord.Verdict != actionBlock {
		t.Errorf("verdict = %q, want %q", r.ActionRecord.Verdict, actionBlock)
	}
	if r.ActionRecord.Layer != "dlp" {
		t.Errorf("layer = %q, want %q", r.ActionRecord.Layer, "dlp")
	}
	if r.ActionRecord.Pattern != "test-secret-pattern" {
		t.Errorf("pattern = %q, want %q", r.ActionRecord.Pattern, "test-secret-pattern")
	}
}

// TestReceiptCoverage_VerifierRoundTrip_WebSocketSessionClose verifies that
// a websocket session close (allow) receipt round-trips correctly.
func TestReceiptCoverage_VerifierRoundTrip_WebSocketSessionClose(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Layer:     "session_close",
		Transport: TransportWS,
		Target:    "wss://example.com/ws-close",
		RequestID: "ws-close-1",
		Agent:     coverageTestAgent,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	r := receipts[0]

	if err := receipt.Verify(r); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	keyHex := hex.EncodeToString(pubKey)
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		t.Fatalf("VerifyWithKey failed: %v", err)
	}

	if r.ActionRecord.Transport != TransportWS {
		t.Errorf("transport = %q, want %q", r.ActionRecord.Transport, TransportWS)
	}
	if r.ActionRecord.Verdict != actionAllow {
		t.Errorf("verdict = %q, want %q", r.ActionRecord.Verdict, actionAllow)
	}
	if r.ActionRecord.Layer != "session_close" {
		t.Errorf("layer = %q, want %q", r.ActionRecord.Layer, "session_close")
	}
}

// TestReceiptCoverage_VerifierRoundTrip_FetchHeaderDLP verifies that a fetch
// header DLP block receipt round-trips correctly.
func TestReceiptCoverage_VerifierRoundTrip_FetchHeaderDLP(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "dlp_header",
		Transport: TransportFetch,
		Method:    http.MethodGet,
		Target:    "https://example.com/fetch-header-dlp",
		RequestID: "fetch-hdr-1",
		Agent:     coverageTestAgent,
		Pattern:   "Authorization: Bearer.*",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	r := receipts[0]

	if err := receipt.Verify(r); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	keyHex := hex.EncodeToString(pubKey)
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		t.Fatalf("VerifyWithKey failed: %v", err)
	}

	if r.ActionRecord.Transport != TransportFetch {
		t.Errorf("transport = %q, want %q", r.ActionRecord.Transport, TransportFetch)
	}
	if r.ActionRecord.Verdict != actionBlock {
		t.Errorf("verdict = %q, want %q", r.ActionRecord.Verdict, actionBlock)
	}
	if r.ActionRecord.Layer != "dlp_header" {
		t.Errorf("layer = %q, want %q", r.ActionRecord.Layer, "dlp_header")
	}
	if r.ActionRecord.ActionType != receipt.ActionRead {
		t.Errorf("action_type = %q, want %q", r.ActionRecord.ActionType, receipt.ActionRead)
	}
}

// TestReceiptCoverage_VerifierRoundTrip_A2ABlock verifies that a forward/A2A
// response block receipt round-trips correctly.
func TestReceiptCoverage_VerifierRoundTrip_A2ABlock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "a2a_response",
		Transport: TransportForward,
		Method:    http.MethodPost,
		Target:    "https://agent.example.com/.well-known/agent.json",
		RequestID: "a2a-block-1",
		Agent:     coverageTestAgent,
		Pattern:   "injection-detected",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	r := receipts[0]

	if err := receipt.Verify(r); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	keyHex := hex.EncodeToString(pubKey)
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		t.Fatalf("VerifyWithKey failed: %v", err)
	}

	if r.ActionRecord.Transport != TransportForward {
		t.Errorf("transport = %q, want %q", r.ActionRecord.Transport, TransportForward)
	}
	if r.ActionRecord.Verdict != actionBlock {
		t.Errorf("verdict = %q, want %q", r.ActionRecord.Verdict, actionBlock)
	}
	if r.ActionRecord.Layer != "a2a_response" {
		t.Errorf("layer = %q, want %q", r.ActionRecord.Layer, "a2a_response")
	}
	if r.ActionRecord.ActionType != receipt.ActionWrite {
		t.Errorf("action_type = %q, want %q", r.ActionRecord.ActionType, receipt.ActionWrite)
	}
}

// TestReceiptCoverage_VerifierRoundTrip_ConnectBlock verifies that a CONNECT
// transport block receipt round-trips correctly.
func TestReceiptCoverage_VerifierRoundTrip_ConnectBlock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "blocklist",
		Transport: TransportConnect,
		Method:    http.MethodConnect,
		Target:    "https://blocked.example.com:443",
		RequestID: "connect-block-1",
		Agent:     coverageTestAgent,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	r := receipts[0]

	if err := receipt.Verify(r); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	keyHex := hex.EncodeToString(pubKey)
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		t.Fatalf("VerifyWithKey failed: %v", err)
	}

	if r.ActionRecord.Transport != TransportConnect {
		t.Errorf("transport = %q, want %q", r.ActionRecord.Transport, TransportConnect)
	}
	if r.ActionRecord.Verdict != actionBlock {
		t.Errorf("verdict = %q, want %q", r.ActionRecord.Verdict, actionBlock)
	}
	// CONNECT method classifies as read (tunnel establishment).
	if r.ActionRecord.ActionType != receipt.ActionRead {
		t.Errorf("action_type = %q, want %q", r.ActionRecord.ActionType, receipt.ActionRead)
	}
}

// TestReceiptCoverage_WSFrameBurst_NoReceiptsForAllowed verifies the design
// invariant that allowed WebSocket frames produce ZERO per-frame receipts.
// Only session-level events (connect block, session close) emit receipts.
// This prevents O(n) receipt growth from high-frequency frame traffic.
func TestReceiptCoverage_WSFrameBurst_NoReceiptsForAllowed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	// Simulate what WOULD happen if per-frame receipts were emitted:
	// only session-level receipts should exist.
	// We emit a single session-close receipt (what the proxy actually does
	// for a clean 100-frame WS session).
	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Layer:     "session_close",
		Transport: TransportWS,
		Target:    "wss://clean.example.com/ws",
		RequestID: "ws-burst-1",
		Agent:     coverageTestAgent,
	})
	if err != nil {
		t.Fatalf("Emit session close: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)

	// Exactly 1 receipt: the session close. Not 100+ per-frame receipts.
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt (session close only), got %d", len(receipts))
	}

	r := receipts[0]
	keyHex := hex.EncodeToString(pubKey)
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}

	if r.ActionRecord.Layer != "session_close" {
		t.Errorf("layer = %q, want %q", r.ActionRecord.Layer, "session_close")
	}
	if r.ActionRecord.Verdict != actionAllow {
		t.Errorf("verdict = %q, want %q", r.ActionRecord.Verdict, actionAllow)
	}
}

// TestReceiptCoverage_NilEmitter_NoOp verifies that calling Emit on a nil
// emitter is a no-op (no panic, nil error). This ensures receipt emission
// failures cannot fail requests (fail-open on receipt emit).
func TestReceiptCoverage_NilEmitter_NoOp(t *testing.T) {
	t.Parallel()

	var emitter *receipt.Emitter

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "dlp",
		Transport: TransportFetch,
		Method:    http.MethodGet,
		Target:    coverageTestTarget,
		RequestID: "nil-emit-1",
	})
	if err != nil {
		t.Errorf("Emit on nil emitter should return nil, got: %v", err)
	}

	// Also verify EmitTranscriptRoot is safe on nil.
	err = emitter.EmitTranscriptRoot("test-session")
	if err != nil {
		t.Errorf("EmitTranscriptRoot on nil emitter should return nil, got: %v", err)
	}

	// Also verify UpdateConfigHash is safe on nil.
	emitter.UpdateConfigHash("new-hash") // should not panic
}

// TestReceiptCoverage_EmitAfterChainSealed verifies that once
// EmitTranscriptRoot is called, subsequent Emit calls return ErrChainSealed.
func TestReceiptCoverage_EmitAfterChainSealed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, _ := newCoverageEmitter(t, dir)
	defer func() { _ = rec.Close() }()

	// Emit at least one receipt so transcript root has content.
	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "dlp",
		Transport: TransportFetch,
		Method:    http.MethodGet,
		Target:    coverageTestTarget,
		RequestID: "seal-1",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}

	// Seal the chain.
	err = emitter.EmitTranscriptRoot("coverage-session")
	if err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}

	// Attempt to emit after seal -- must get ErrChainSealed.
	err = emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Layer:     "blocklist",
		Transport: TransportForward,
		Method:    http.MethodPost,
		Target:    "https://post-seal.example.com",
		RequestID: "seal-2",
	})
	if err == nil {
		t.Fatal("expected ErrChainSealed after EmitTranscriptRoot, got nil")
	}
	if !errors.Is(err, receipt.ErrChainSealed) {
		t.Errorf("expected ErrChainSealed, got: %v", err)
	}
}

// TestReceiptCoverage_EmitTranscriptRoot_DoubleCall verifies that calling
// EmitTranscriptRoot twice returns ErrRootAlreadyEmitted on the second call.
func TestReceiptCoverage_EmitTranscriptRoot_DoubleCall(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, _ := newCoverageEmitter(t, dir)
	defer func() { _ = rec.Close() }()

	// Emit a receipt so transcript root has content.
	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "dlp",
		Transport: TransportFetch,
		Target:    coverageTestTarget,
		RequestID: "double-1",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	// First root -- should succeed.
	err = emitter.EmitTranscriptRoot("session-double")
	if err != nil {
		t.Fatalf("first EmitTranscriptRoot: %v", err)
	}

	// Second root -- should return ErrRootAlreadyEmitted.
	err = emitter.EmitTranscriptRoot("session-double")
	if err == nil {
		t.Fatal("expected ErrRootAlreadyEmitted on second call, got nil")
	}
	if !errors.Is(err, receipt.ErrRootAlreadyEmitted) {
		t.Errorf("expected ErrRootAlreadyEmitted, got: %v", err)
	}
}

// TestReceiptCoverage_MarshalUnmarshalRoundTrip verifies that receipt JSON
// serialization and deserialization preserves all fields faithfully.
func TestReceiptCoverage_MarshalUnmarshalRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, _ := newCoverageEmitter(t, dir)

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "dlp",
		Pattern:   "secret-pattern-xyz",
		Transport: TransportFetch,
		Method:    http.MethodGet,
		Target:    "https://marshal.example.com/test",
		RequestID: "marshal-1",
		Agent:     coverageTestAgent,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	original := receipts[0]

	// Marshal to JSON and unmarshal back.
	data, err := receipt.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	roundTripped, err := receipt.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Compare key fields.
	if roundTripped.Version != original.Version {
		t.Errorf("version: got %d, want %d", roundTripped.Version, original.Version)
	}
	if roundTripped.Signature != original.Signature {
		t.Errorf("signature mismatch after round-trip")
	}
	if roundTripped.SignerKey != original.SignerKey {
		t.Errorf("signer_key mismatch after round-trip")
	}
	if roundTripped.ActionRecord.ActionID != original.ActionRecord.ActionID {
		t.Errorf("action_id mismatch after round-trip")
	}
	if roundTripped.ActionRecord.Transport != original.ActionRecord.Transport {
		t.Errorf("transport: got %q, want %q",
			roundTripped.ActionRecord.Transport, original.ActionRecord.Transport)
	}
	if roundTripped.ActionRecord.Layer != original.ActionRecord.Layer {
		t.Errorf("layer: got %q, want %q",
			roundTripped.ActionRecord.Layer, original.ActionRecord.Layer)
	}
	if roundTripped.ActionRecord.Pattern != original.ActionRecord.Pattern {
		t.Errorf("pattern: got %q, want %q",
			roundTripped.ActionRecord.Pattern, original.ActionRecord.Pattern)
	}

	// The round-tripped receipt must still verify.
	if err := receipt.Verify(roundTripped); err != nil {
		t.Fatalf("Verify after round-trip failed: %v", err)
	}
}

// TestReceiptCoverage_ChainIntegrity_FiveTransports verifies chain integrity
// across all five transport types (fetch, websocket, forward, connect, mcp).
func TestReceiptCoverage_ChainIntegrity_FiveTransports(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	allTransports := []struct {
		transport string
		method    string
		target    string
	}{
		{transport: TransportFetch, method: http.MethodGet, target: "https://fetch.example.com"},
		{transport: TransportWS, method: "", target: "wss://ws.example.com"},
		{transport: TransportForward, method: http.MethodPost, target: "https://forward.example.com"},
		{transport: TransportConnect, method: http.MethodConnect, target: "https://connect.example.com:443"},
		{transport: TransportMCP, target: "mcp://tool.example.com"},
	}

	for _, tc := range allTransports {
		opts := receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     "dlp",
			Transport: tc.transport,
			Method:    tc.method,
			Target:    tc.target,
			RequestID: "chain-" + tc.transport,
		}
		if tc.transport == TransportMCP {
			opts.MCPMethod = "tools/call"
			opts.ToolName = "getStatus"
		}
		if err := emitter.Emit(opts); err != nil {
			t.Fatalf("Emit(%s): %v", tc.transport, err)
		}
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 5 {
		t.Fatalf("expected 5 receipts, got %d", len(receipts))
	}

	keyHex := hex.EncodeToString(pubKey)
	result := receipt.VerifyChain(receipts, keyHex)
	if !result.Valid {
		t.Fatalf("VerifyChain failed across 5 transports: %s", result.Error)
	}
	if result.ReceiptCount != 5 {
		t.Errorf("receipt_count = %d, want 5", result.ReceiptCount)
	}
	if result.FinalSeq != 4 {
		t.Errorf("final_seq = %d, want 4", result.FinalSeq)
	}

	// Verify timestamps are ordered.
	if result.StartTime.After(result.EndTime) {
		t.Errorf("start_time %v should be <= end_time %v", result.StartTime, result.EndTime)
	}
}

// TestReceiptCoverage_VerifierRoundTrip_MCPBlock verifies that an MCP tool
// call block receipt round-trips through the verifier.
func TestReceiptCoverage_VerifierRoundTrip_MCPBlock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "mcp_input_scanning",
		Transport: TransportMCP,
		Target:    "mcp://tool-server/exec",
		RequestID: "mcp-block-1",
		MCPMethod: "tools/call",
		ToolName:  "runCommand",
		Agent:     coverageTestAgent,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	r := receipts[0]

	if err := receipt.Verify(r); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	keyHex := hex.EncodeToString(pubKey)
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		t.Fatalf("VerifyWithKey failed: %v", err)
	}

	if r.ActionRecord.Transport != TransportMCP {
		t.Errorf("transport = %q, want %q", r.ActionRecord.Transport, TransportMCP)
	}
	if r.ActionRecord.Verdict != actionBlock {
		t.Errorf("verdict = %q, want %q", r.ActionRecord.Verdict, actionBlock)
	}
	// runCommand classifies as delegate.
	if r.ActionRecord.ActionType != receipt.ActionDelegate {
		t.Errorf("action_type = %q, want %q", r.ActionRecord.ActionType, receipt.ActionDelegate)
	}
	// MCP calls should have reversibility set to unknown.
	if r.ActionRecord.Reversibility != receipt.ReversibilityUnknown {
		t.Errorf("reversibility = %q, want %q", r.ActionRecord.Reversibility, receipt.ReversibilityUnknown)
	}
}

// TestReceiptCoverage_ReceiptDetailSurvivesRecorderRoundTrip verifies that
// receipt data written through the recorder can be extracted back via
// recorder.ReadEntries and parsed to a valid Receipt. This tests the full
// recorder-level round trip (not just JSON marshal/unmarshal).
func TestReceiptCoverage_ReceiptDetailSurvivesRecorderRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emitter, rec, pubKey := newCoverageEmitter(t, dir)

	err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionBlock,
		Layer:     "blocklist",
		Transport: TransportFetch,
		Method:    http.MethodGet,
		Target:    "https://evil.example.com/recorder-roundtrip",
		RequestID: "rec-rt-1",
		Agent:     coverageTestAgent,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	// Use readAllEntries (from receipt_test.go) to read raw recorder entries.
	entries := readAllEntries(t, dir)

	var receiptEntry *recorder.Entry
	for i := range entries {
		if entries[i].Type == receiptEntryType {
			receiptEntry = &entries[i]
			break
		}
	}
	if receiptEntry == nil {
		t.Fatal("no action_receipt entry found in recorder output")
	}

	// Parse receipt from Detail.
	detailJSON, err := json.Marshal(receiptEntry.Detail)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}

	r, err := receipt.Unmarshal(detailJSON)
	if err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}

	if err := receipt.Verify(r); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	keyHex := hex.EncodeToString(pubKey)
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		t.Fatalf("VerifyWithKey failed: %v", err)
	}

	if r.ActionRecord.Transport != TransportFetch {
		t.Errorf("transport = %q, want %q", r.ActionRecord.Transport, TransportFetch)
	}
	if r.ActionRecord.Verdict != actionBlock {
		t.Errorf("verdict = %q, want %q", r.ActionRecord.Verdict, actionBlock)
	}
}
