// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestEmitter_EmitHeartbeatSignedSnapshotCountersAndNonce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	syncErr := errors.New("injected sync failure")
	rec.SetSyncForTest(func(*os.File) error { return syncErr })
	err := e.EmitDurable(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodPost,
		Target:    "https://api.vendor.example/durable",
	})
	if !errors.Is(err, recorder.ErrDurability) {
		t.Fatalf("EmitDurable error = %v, want ErrDurability", err)
	}
	rec.SetSyncForTest(nil)

	receiptsBeforeHeartbeat := readAllReceiptsFromDir(t, dir, pub)
	preHeartbeatTail := mustHash(t, receiptsBeforeHeartbeat[len(receiptsBeforeHeartbeat)-1])
	preHeartbeatSeqHead := uint64(len(receiptsBeforeHeartbeat)) - 1

	if err := e.EmitHeartbeat(); err != nil {
		t.Fatalf("EmitHeartbeat #1: %v", err)
	}
	if err := e.EmitHeartbeat(); err != nil {
		t.Fatalf("EmitHeartbeat #2: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	receipts := readAllReceiptsFromDir(t, dir, pub)
	if res := VerifyChain(receipts, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("VerifyChain: %s", res.Error)
	}
	open := receipts[0].ActionRecord.SessionControl.Open
	hb1 := receipts[len(receipts)-2].ActionRecord.SessionControl.Heartbeat
	hb2 := receipts[len(receipts)-1].ActionRecord.SessionControl.Heartbeat
	if hb1 == nil || hb2 == nil {
		t.Fatalf("tail receipts are not heartbeats: %#v %#v",
			receipts[len(receipts)-2].ActionRecord.SessionControl,
			receipts[len(receipts)-1].ActionRecord.SessionControl)
	}
	if hb1.Beat != 1 || hb2.Beat != 2 {
		t.Fatalf("heartbeat beats = %d,%d; want 1,2", hb1.Beat, hb2.Beat)
	}
	if hb1.ChainHead != preHeartbeatTail || hb1.ChainSeqHead != preHeartbeatSeqHead {
		t.Fatalf("heartbeat snapshot = (%s,%d), want (%s,%d)",
			hb1.ChainHead, hb1.ChainSeqHead, preHeartbeatTail, preHeartbeatSeqHead)
	}
	if hb1.FsyncErrorsGated != 1 || hb1.DurabilityBlocks != 1 {
		t.Fatalf("heartbeat counters fsync=%d blocks=%d, want 1/1", hb1.FsyncErrorsGated, hb1.DurabilityBlocks)
	}
	if hb1.OpenNonce != open.OpenNonce || hb2.OpenNonce != open.OpenNonce {
		t.Fatalf("heartbeat open_nonce did not bind to session_open nonce")
	}
}

func TestEmitter_EmitSessionOpenIsDurableAndGatesOnFsync(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	// session_open is the run anchor: if it cannot be durably persisted, the
	// emit must surface ErrDurability so the caller can fail closed under
	// require_receipts. A non-durable open would swallow the fsync failure.
	syncErr := errors.New("injected sync failure")
	rec.SetSyncForTest(func(*os.File) error { return syncErr })
	err := e.EmitSessionOpen()
	if !errors.Is(err, recorder.ErrDurability) {
		t.Fatalf("EmitSessionOpen error = %v, want ErrDurability (session_open must be emitted durably)", err)
	}
	if e.DurabilityBlocks() != 1 {
		t.Fatalf("DurabilityBlocks = %d, want 1 after gated session_open", e.DurabilityBlocks())
	}
	rec.SetSyncForTest(nil)
	retryErr := e.EmitSessionOpen()
	if !errors.Is(retryErr, recorder.ErrDurability) {
		t.Fatalf("retry EmitSessionOpen error = %v, want sticky ErrDurability", retryErr)
	}
	if !errors.Is(retryErr, syncErr) {
		t.Fatalf("retry EmitSessionOpen error = %v, want original sync error", retryErr)
	}

	// The bytes still reached disk (fsync failed, not the write), so the chain
	// opens correctly and a heartbeat can snapshot it.
	if err := e.EmitHeartbeat(); err != nil {
		t.Fatalf("EmitHeartbeat after gated open: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	receipts := readAllReceiptsFromDir(t, dir, pub)
	if len(receipts) == 0 || !isSessionOpenControl(receipts[0].ActionRecord.SessionControl) {
		t.Fatalf("first receipt is not session_open: %#v", receipts)
	}
	if res := VerifyChain(receipts, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("VerifyChain: %s", res.Error)
	}
}

func TestEmitter_EmitSessionCloseIsDurableAndGatesOnFsync(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
		Target:    "https://api.vendor.example/pre-close",
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	// session_close is the seal over the pre-close tail: if it cannot be durably
	// persisted, the emit must surface ErrDurability so the caller can fail
	// closed under require_receipts. A non-durable close would swallow the fsync
	// failure. The write itself still succeeds (only fsync is injected to fail),
	// so the close receipt reaches disk and the chain still verifies.
	syncErr := errors.New("injected sync failure")
	rec.SetSyncForTest(func(*os.File) error { return syncErr })
	err := e.EmitSessionClose("graceful_shutdown")
	if !errors.Is(err, recorder.ErrDurability) {
		t.Fatalf("EmitSessionClose error = %v, want ErrDurability (session_close must be emitted durably)", err)
	}
	if e.DurabilityBlocks() != 1 {
		t.Fatalf("DurabilityBlocks = %d, want 1 after gated session_close", e.DurabilityBlocks())
	}
	rec.SetSyncForTest(nil)

	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	receipts := readAllReceiptsFromDir(t, dir, pub)
	if len(receipts) == 0 || !isSessionCloseControl(receipts[len(receipts)-1].ActionRecord.SessionControl) {
		t.Fatalf("last receipt is not session_close: %#v", receipts)
	}
	if res := VerifyChain(receipts, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("VerifyChain: %s", res.Error)
	}
}

func TestEmitter_EmitSessionCloseDurabilityFailureRetrySurfacesError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
		Target:    "https://api.vendor.example/pre-close",
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	syncErr := errors.New("injected sync failure")
	rec.SetSyncForTest(func(*os.File) error { return syncErr })
	err := e.EmitSessionClose("graceful_shutdown")
	if !errors.Is(err, recorder.ErrDurability) {
		t.Fatalf("EmitSessionClose error = %v, want ErrDurability", err)
	}
	rec.SetSyncForTest(nil)

	retryErr := e.EmitSessionClose("retry")
	if !errors.Is(retryErr, recorder.ErrDurability) {
		t.Fatalf("retry EmitSessionClose error = %v, want sticky ErrDurability", retryErr)
	}
	if !errors.Is(retryErr, syncErr) {
		t.Fatalf("retry EmitSessionClose error = %v, want original sync error", retryErr)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	receipts := readAllReceiptsFromDir(t, dir, pub)
	closeCount := 0
	for _, r := range receipts {
		if isSessionCloseControl(r.ActionRecord.SessionControl) {
			closeCount++
		}
	}
	if closeCount != 1 {
		t.Fatalf("session_close receipts = %d, want 1", closeCount)
	}
	if res := VerifyChain(receipts, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("VerifyChain: %s", res.Error)
	}
}

func TestEmitter_EmitSessionOpenPopulatesPostureBinding(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	binding := PostureBinding{
		CapsuleSHA256:    strings.Repeat("a", 64),
		SignerKeyID:      strings.Repeat("b", 64),
		ContainmentNonce: "nonce-1",
		ContainedUID:     "966",
	}
	e := NewEmitter(EmitterConfig{
		Recorder:       rec,
		PrivKey:        priv,
		ConfigHash:     testConfigHash,
		Principal:      testPrincipal,
		Actor:          testActor,
		PostureBinding: binding,
	})

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	receipts := readAllReceiptsFromDir(t, dir, pub)
	if len(receipts) != 1 {
		t.Fatalf("receipts = %d, want 1", len(receipts))
	}
	open := receipts[0].ActionRecord.SessionControl.Open
	if open == nil {
		t.Fatalf("session_open missing: %#v", receipts[0].ActionRecord.SessionControl)
	}
	if open.PostureCapsuleSHA256 != binding.CapsuleSHA256 ||
		open.PostureSignerKeyID != binding.SignerKeyID ||
		open.ContainmentNonce != binding.ContainmentNonce ||
		open.ContainedUID != binding.ContainedUID {
		t.Fatalf("posture binding = %+v, want %+v", open, binding)
	}
	if res := VerifyChain(receipts, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("VerifyChain: %s", res.Error)
	}
}

func TestEmitter_EmitSessionCloseFinalReceiptAndRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
		Target:    "https://api.vendor.example/close",
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	preCloseReceipts := readAllReceiptsFromDir(t, dir, pub)
	preCloseTail := mustHash(t, preCloseReceipts[len(preCloseReceipts)-1])
	if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatalf("EmitSessionClose: %v", err)
	}
	if err := e.EmitSessionClose("duplicate"); err != nil {
		t.Fatalf("duplicate EmitSessionClose should no-op before root: %v", err)
	}
	if err := e.EmitTranscriptRoot("session"); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	receipts := readAllReceiptsFromDir(t, dir, pub)
	if len(receipts) != len(preCloseReceipts)+1 {
		t.Fatalf("receipt count after duplicate close = %d, want %d", len(receipts), len(preCloseReceipts)+1)
	}
	if res := VerifyChain(receipts, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("VerifyChain: %s", res.Error)
	}
	closeRecord := receipts[len(receipts)-1].ActionRecord.SessionControl.Close
	if closeRecord == nil {
		t.Fatalf("last receipt is not session_close: %#v", receipts[len(receipts)-1].ActionRecord.SessionControl)
	}
	if closeRecord.FinalSeq != 2 || closeRecord.ReceiptCount != 3 || closeRecord.RootHash != preCloseTail {
		t.Fatalf("close sealed final_seq=%d count=%d root=%s; want 2/3/%s",
			closeRecord.FinalSeq, closeRecord.ReceiptCount, closeRecord.RootHash, preCloseTail)
	}
	if closeRecord.OpenNonce != receipts[0].ActionRecord.SessionControl.Open.OpenNonce {
		t.Fatal("close open_nonce did not bind to session_open nonce")
	}

	root := readTranscriptRootFromDir(t, dir)
	closeHash := mustHash(t, receipts[len(receipts)-1])
	if root.ReceiptCount != uint64(len(receipts)) || root.RootHash != closeHash {
		t.Fatalf("transcript root count/hash = %d/%s, want %d/%s",
			root.ReceiptCount, root.RootHash, len(receipts), closeHash)
	}
}

func TestEmitter_KeyRotationSessionCloseUsesSegmentLocalCount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)

	recA := newTestRecorder(t, dir, privA)
	eA := NewEmitter(EmitterConfig{Recorder: recA, PrivKey: privA, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	if err := eA.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen A: %v", err)
	}
	if err := eA.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
		Target:    "https://api.vendor.example/before-rotation",
	}); err != nil {
		t.Fatalf("Emit A: %v", err)
	}
	if err := recA.Close(); err != nil {
		t.Fatalf("Close A: %v", err)
	}

	recB := newTestRecorder(t, dir, privB)
	eB := NewEmitter(EmitterConfig{Recorder: recB, PrivKey: privB, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	if err := eB.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen B: %v", err)
	}
	if err := eB.EmitHeartbeat(); err != nil {
		t.Fatalf("EmitHeartbeat B: %v", err)
	}
	if err := eB.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatalf("EmitSessionClose B: %v", err)
	}
	if err := recB.Close(); err != nil {
		t.Fatalf("Close B: %v", err)
	}

	receipts, err := ExtractReceiptsFromSessionDir(dir, recorderSessionID)
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	if len(receipts) != 5 {
		t.Fatalf("receipts = %d, want 5", len(receipts))
	}
	rotatedOpen := receipts[2].ActionRecord
	if rotatedOpen.KeyTransition == nil {
		t.Fatal("rotated session_open missing key_transition")
	}
	if rotatedOpen.ChainSeq != 0 {
		t.Fatalf("rotated session_open chain_seq = %d, want reset to 0", rotatedOpen.ChainSeq)
	}

	closeRecord := receipts[len(receipts)-1].ActionRecord.SessionControl.Close
	if closeRecord == nil {
		t.Fatalf("last receipt is not session_close: %#v", receipts[len(receipts)-1].ActionRecord.SessionControl)
	}
	if closeRecord.FinalSeq != 2 || closeRecord.ReceiptCount != 3 {
		t.Fatalf("rotated close claims final_seq=%d receipt_count=%d, want segment-local 2/3",
			closeRecord.FinalSeq, closeRecord.ReceiptCount)
	}
	result := VerifyChainTrusted(receipts, []string{hex.EncodeToString(pubA), hex.EncodeToString(pubB)})
	if !result.Valid {
		t.Fatalf("VerifyChainTrusted rotated session_control chain: %s", result.Error)
	}
}

func TestEmitter_EmitSessionClosePersistFailureCanRetryToDetectableGap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	recipientPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
		RawEscrow:          true,
		EscrowPublicKey:    hex.EncodeToString(recipientPub[:]),
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
		Target:    "https://api.vendor.example/pre-close",
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	closeEscrowPath := filepath.Join(dir, "evidence-proxy-2.raw.enc")
	if err := os.Mkdir(closeEscrowPath, 0o750); err != nil {
		t.Fatalf("mkdir close escrow collision: %v", err)
	}
	closeErr := e.EmitSessionClose("probe")
	if err := os.Remove(closeEscrowPath); err != nil {
		t.Fatalf("remove close escrow collision: %v", err)
	}
	if closeErr == nil {
		t.Fatal("EmitSessionClose unexpectedly succeeded")
	}

	if err := e.EmitSessionClose("retry"); err != nil {
		t.Fatalf("retry EmitSessionClose: %v", err)
	}
	if err := e.EmitTranscriptRoot("session"); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	receipts := readAllReceiptsFromDir(t, dir, pub)
	closeCount := 0
	for _, r := range receipts {
		if isSessionCloseControl(r.ActionRecord.SessionControl) {
			closeCount++
		}
	}
	if closeCount != 1 {
		t.Fatalf("session_close receipts = %d, want 1 retry close", closeCount)
	}
	root := readTranscriptRootFromDir(t, dir)
	if root.ReceiptCount != 4 {
		t.Fatalf("root receipt_count = %d, want 4 including the failed close seq gap", root.ReceiptCount)
	}
	res := VerifyChain(receipts, hex.EncodeToString(pub))
	if res.Valid {
		t.Fatal("VerifyChain unexpectedly accepted chain with missing failed close seq")
	}
	if !strings.Contains(res.Error, "seq gap") {
		t.Fatalf("VerifyChain error = %q, want seq gap", res.Error)
	}
}

func TestEmitter_EmitSessionOpenPersistFailureCanRetryToDetectableGap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	recipientPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
		RawEscrow:          true,
		EscrowPublicKey:    hex.EncodeToString(recipientPub[:]),
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	openEscrowPath := filepath.Join(dir, "evidence-proxy-0.raw.enc")
	if err := os.Mkdir(openEscrowPath, 0o750); err != nil {
		t.Fatalf("mkdir open escrow collision: %v", err)
	}
	openErr := e.EmitSessionOpen()
	if err := os.Remove(openEscrowPath); err != nil {
		t.Fatalf("remove open escrow collision: %v", err)
	}
	if openErr == nil {
		t.Fatal("EmitSessionOpen unexpectedly succeeded")
	}

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("retry EmitSessionOpen: %v", err)
	}
	if err := e.EmitHeartbeat(); err != nil {
		t.Fatalf("EmitHeartbeat: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	receipts := readAllReceiptsFromDir(t, dir, pub)
	openCount := 0
	for _, r := range receipts {
		if isSessionOpenControl(r.ActionRecord.SessionControl) {
			openCount++
		}
	}
	if openCount != 1 {
		t.Fatalf("session_open receipts = %d, want 1 retry open", openCount)
	}
	res := VerifyChain(receipts, hex.EncodeToString(pub))
	if res.Valid {
		t.Fatal("VerifyChain unexpectedly accepted chain with missing failed open seq")
	}
	if !strings.Contains(res.Error, "genesis receipt chain_prev_hash") {
		t.Fatalf("VerifyChain error = %q, want genesis chain_prev_hash gap", res.Error)
	}
}

func TestEmitter_ReceiptHashRecordedUsesRawStoredReceiptBytes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.EmitSessionClose("raw_confirm"); err != nil {
		t.Fatalf("EmitSessionClose: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-proxy-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	for _, entry := range entries {
		if entry.Type != recorderEntryType {
			continue
		}
		rcpt, receiptErr := receiptFromEntry(entry)
		if receiptErr != nil {
			t.Fatalf("receiptFromEntry: %v", receiptErr)
		}
		if !isSessionCloseControl(rcpt.ActionRecord.SessionControl) {
			continue
		}
		rawHash := sha256.Sum256(entry.RawDetail)
		rawHashHex := hex.EncodeToString(rawHash[:])
		if !e.receiptHashRecorded(rawHashHex) {
			t.Fatalf("receiptHashRecorded(%s) = false for stored close receipt", rawHashHex)
		}
		structHash, hashErr := ReceiptHash(*rcpt)
		if hashErr != nil {
			t.Fatalf("ReceiptHash: %v", hashErr)
		}
		if structHash != rawHashHex {
			t.Fatalf("close receipt raw hash = %s, structured hash = %s", rawHashHex, structHash)
		}
		if err := VerifyWithKey(*rcpt, hex.EncodeToString(pub)); err != nil {
			t.Fatalf("VerifyWithKey: %v", err)
		}
		return
	}
	t.Fatal("no session_close receipt found")
}

func TestEmitter_EmitSessionCloseEmptyChainNoOp(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash})
	if err := e.EmitSessionClose("empty"); err != nil {
		t.Fatalf("EmitSessionClose empty: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if receipts := readAllReceiptsFromDir(t, dir, pub); len(receipts) != 0 {
		t.Fatalf("empty close emitted %d receipts, want 0", len(receipts))
	}
}

func TestEmitter_HeartbeatAndCloseWithoutSessionOpenUseEmptyOpenNonce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash})
	if err := e.EmitHeartbeat(); err != nil {
		t.Fatalf("EmitHeartbeat: %v", err)
	}
	if err := e.EmitSessionClose("no_open"); err != nil {
		t.Fatalf("EmitSessionClose: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	receipts := readAllReceiptsFromDir(t, dir, pub)
	if len(receipts) != 2 {
		t.Fatalf("receipts = %d, want heartbeat+close", len(receipts))
	}
	if receipts[0].ActionRecord.SessionControl.Heartbeat.OpenNonce != "" {
		t.Fatalf("heartbeat open_nonce = %q, want empty", receipts[0].ActionRecord.SessionControl.Heartbeat.OpenNonce)
	}
	if receipts[1].ActionRecord.SessionControl.Close.OpenNonce != "" {
		t.Fatalf("close open_nonce = %q, want empty", receipts[1].ActionRecord.SessionControl.Close.OpenNonce)
	}
	for _, r := range receipts {
		if err := VerifyWithKey(r, hex.EncodeToString(pub)); err != nil {
			t.Fatalf("VerifyWithKey without open: %v", err)
		}
	}
}

func TestEmitter_ForgedHeartbeatAndCloseFieldsAreRecomputed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})

	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
		Target:    "https://api.vendor.example/pre-forge",
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	preHeartbeatReceipts := readAllReceiptsFromDir(t, dir, pub)
	preHeartbeatTail := mustHash(t, preHeartbeatReceipts[len(preHeartbeatReceipts)-1])
	preHeartbeatSeqHead := uint64(len(preHeartbeatReceipts)) - 1
	openNonce := preHeartbeatReceipts[0].ActionRecord.SessionControl.Open.OpenNonce

	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: sessionControlTransport,
		Target:    sessionHeartbeatTarget,
		SessionControl: &SessionControl{
			Kind: SessionControlHeartbeat,
			Open: &SessionOpen{
				RunNonce: "forged-open",
			},
			Heartbeat: &SessionHeartbeat{
				RunNonce:         "forged-run",
				OpenNonce:        "forged-open",
				Beat:             999,
				ChainHead:        "forged-chain-head",
				ChainSeqHead:     999,
				HeartbeatTime:    "2099-01-01T00:00:00Z",
				FsyncErrorsGated: 999,
				DurabilityBlocks: 999,
			},
			Close: &SessionClose{
				RootHash: "forged-close",
			},
		},
	}); err != nil {
		t.Fatalf("forged heartbeat Emit: %v", err)
	}
	afterHeartbeatReceipts := readAllReceiptsFromDir(t, dir, pub)
	heartbeat := afterHeartbeatReceipts[len(afterHeartbeatReceipts)-1].ActionRecord.SessionControl.Heartbeat
	if heartbeat == nil {
		t.Fatalf("tail receipt is not heartbeat: %#v", afterHeartbeatReceipts[len(afterHeartbeatReceipts)-1].ActionRecord.SessionControl)
	}
	if heartbeat.RunNonce != e.runNonce ||
		heartbeat.OpenNonce != openNonce ||
		heartbeat.Beat != 1 ||
		heartbeat.ChainHead != preHeartbeatTail ||
		heartbeat.ChainSeqHead != preHeartbeatSeqHead ||
		heartbeat.FsyncErrorsGated != 0 ||
		heartbeat.DurabilityBlocks != 0 {
		t.Fatalf("heartbeat was not recomputed from chain state: %+v", heartbeat)
	}
	if heartbeat.HeartbeatTime == "2099-01-01T00:00:00Z" {
		t.Fatalf("heartbeat_time preserved forged value")
	}
	hbControl := afterHeartbeatReceipts[len(afterHeartbeatReceipts)-1].ActionRecord.SessionControl
	if hbControl.Open != nil {
		t.Fatalf("forged Open sub-struct persisted in heartbeat receipt")
	}
	if hbControl.Close != nil {
		t.Fatalf("forged Close sub-struct persisted in heartbeat receipt")
	}

	preCloseReceipts := readAllReceiptsFromDir(t, dir, pub)
	preCloseTail := mustHash(t, preCloseReceipts[len(preCloseReceipts)-1])
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: sessionControlTransport,
		Target:    sessionCloseTarget,
		SessionControl: &SessionControl{
			Kind: SessionControlClose,
			Open: &SessionOpen{
				RunNonce: "forged-open",
			},
			Heartbeat: &SessionHeartbeat{
				ChainHead: "forged-heartbeat",
			},
			Close: &SessionClose{
				RunNonce:         "forged-run",
				OpenNonce:        "forged-open",
				FinalSeq:         999,
				RootHash:         "forged-root",
				ReceiptCount:     999,
				CloseReason:      "operator_shutdown",
				FsyncErrorsGated: 999,
				DurabilityBlocks: 999,
			},
		},
	}); err != nil {
		t.Fatalf("forged close Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	receipts := readAllReceiptsFromDir(t, dir, pub)
	closeRecord := receipts[len(receipts)-1].ActionRecord.SessionControl.Close
	if closeRecord == nil {
		t.Fatalf("tail receipt is not session_close: %#v", receipts[len(receipts)-1].ActionRecord.SessionControl)
	}
	if closeRecord.RunNonce != e.runNonce ||
		closeRecord.OpenNonce != openNonce ||
		closeRecord.FinalSeq != uint64(len(preCloseReceipts)) ||
		closeRecord.RootHash != preCloseTail ||
		closeRecord.ReceiptCount != uint64(len(preCloseReceipts))+1 ||
		closeRecord.FsyncErrorsGated != 0 ||
		closeRecord.DurabilityBlocks != 0 ||
		closeRecord.CloseReason != "operator_shutdown" {
		t.Fatalf("close was not recomputed from chain state: %+v", closeRecord)
	}
	if res := VerifyChain(receipts, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("VerifyChain: %s", res.Error)
	}
	closeControl := receipts[len(receipts)-1].ActionRecord.SessionControl
	if closeControl.Open != nil {
		t.Fatalf("forged Open sub-struct persisted in close receipt")
	}
	if closeControl.Heartbeat != nil {
		t.Fatalf("forged Heartbeat sub-struct persisted in close receipt")
	}
}

func readTranscriptRootFromDir(t *testing.T, dir string) TranscriptRoot {
	t.Helper()
	entries := readAllEntriesFromDir(t, dir)
	for _, entry := range entries {
		if entry.Type != transcriptRootEntryType {
			continue
		}
		detailJSON, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatalf("json.Marshal(root): %v", err)
		}
		var root TranscriptRoot
		if err := json.Unmarshal(detailJSON, &root); err != nil {
			t.Fatalf("json.Unmarshal(root): %v", err)
		}
		return root
	}
	t.Fatal("transcript root not found")
	return TranscriptRoot{}
}
