// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func testReceiptChain(t *testing.T, n int) ([]receipt.Receipt, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	prev := receipt.GenesisHash
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	receipts := make([]receipt.Receipt, 0, n)
	for i := range n {
		ar := receipt.ActionRecord{
			Version:       receipt.ActionRecordVersion,
			ActionID:      receipt.NewActionID(),
			ActionType:    receipt.ActionRead,
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			Target:        "https://example.test/resource",
			Verdict:       config.ActionAllow,
			Transport:     "fetch",
			ChainPrevHash: prev,
			ChainSeq:      uint64(i),
			PolicyHash:    "policy-test",
		}
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign[%d]: %v", i, err)
		}
		h, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash[%d]: %v", i, err)
		}
		prev = h
		receipts = append(receipts, r)
	}
	return receipts, hex.EncodeToString(pub)
}

func TestLocalLogBundleVerify(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	report := VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, log)
	if !report.Valid {
		t.Fatalf("VerifyBundle invalid: %s", report.Error)
	}
	if report.RootHash != checkpoint.RootHash || report.Proof.EntryHash == "" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestVerifyBundleDetectsReceiptRewrite(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	tampered := append([]receipt.Receipt(nil), receipts...)
	tampered[1].ActionRecord.Target = "https://example.test/rewritten"
	report := VerifyBundle(NewBundle(checkpoint, proof), tampered, []string{keyHex}, log)
	if report.Valid || !strings.Contains(report.Error, "invalid receipt chain") {
		t.Fatalf("tampered receipt report = %+v, want invalid chain", report)
	}
}

func TestVerifyBundleRejectsBackendMismatch(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundle := NewBundle(checkpoint, proof)
	bundle.Backend = "rekor-prod-transparency-log"

	report := VerifyBundle(bundle, receipts, []string{keyHex}, log)
	if report.Valid {
		t.Fatalf("forged backend label produced a valid report: %+v", report)
	}
	if report.Backend != "" {
		t.Fatalf("report.Backend = %q, want empty unverified backend", report.Backend)
	}
	if !strings.Contains(report.Error, "does not match proof backend") {
		t.Fatalf("report.Error = %q, want backend mismatch", report.Error)
	}
}

func TestVerifyBundleReportLimitsAreCanonical(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundle := NewBundle(checkpoint, proof)
	bundle.Limits = []string{"operator-independent witness PROVEN"}

	report := VerifyBundle(bundle, receipts, []string{keyHex}, log)
	if !report.Valid {
		t.Fatalf("VerifyBundle invalid: %s", report.Error)
	}
	if report.Backend != LocalBackend {
		t.Fatalf("report.Backend = %q, want %q", report.Backend, LocalBackend)
	}
	if len(report.Limits) != len(DefaultLimits) {
		t.Fatalf("report.Limits = %v, want DefaultLimits", report.Limits)
	}
	for i := range DefaultLimits {
		if report.Limits[i] != DefaultLimits[i] {
			t.Fatalf("report.Limits[%d] = %q, want %q", i, report.Limits[i], DefaultLimits[i])
		}
	}
}

func TestVerifyBundleDetectsLocalLogRewrite(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	entries, err := ReadLocalLog(log.Path)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	entries[0].Checkpoint.RootHash = strings.Repeat("0", 64)
	data, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(log.Path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	report := VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, log)
	if report.Valid || !strings.Contains(report.Error, "hash mismatch") {
		t.Fatalf("rewritten log report = %+v, want hash mismatch", report)
	}
}

func TestLocalLogSubmitRejectsMixedExistingLogID(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	for range 2 {
		if _, err := log.Submit(checkpoint); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	entries, err := ReadLocalLog(log.Path)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	entries[1].LogID = "other-log"
	entries[1].Hash = localEntryHash(entries[1])
	writeLocalLogEntries(t, log.Path, entries)

	_, err = log.Submit(checkpoint)
	if err == nil || !strings.Contains(err.Error(), "log_id mismatch at index 1") {
		t.Fatalf("Submit err = %v, want mixed log_id rejection", err)
	}
}

func TestLocalLogSubmitSerializesConcurrentAppends(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 3)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}

	const submits = 8
	var wg sync.WaitGroup
	errs := make(chan error, submits)
	for range submits {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := log.Submit(checkpoint)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	entries, err := ReadLocalLog(log.Path)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	if len(entries) != submits {
		t.Fatalf("len(entries) = %d, want %d", len(entries), submits)
	}
	for i, entry := range entries {
		if entry.Index != uint64(i) {
			t.Fatalf("entries[%d].Index = %d", i, entry.Index)
		}
	}
}

func writeLocalLogEntries(t *testing.T, path string, entries []LocalLogEntry) {
	t.Helper()
	var lines []byte
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		lines = append(lines, data...)
		lines = append(lines, '\n')
	}
	if err := os.WriteFile(path, lines, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
