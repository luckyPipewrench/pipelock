// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

var errBackendVerify = errors.New("backend verification failed")

type failingBackend struct{}

func (failingBackend) Submit(Checkpoint) (Proof, error) {
	return Proof{}, errBackendVerify
}

func (failingBackend) Verify(Proof, Checkpoint) error {
	return errBackendVerify
}

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

func TestBundleFileRoundTrip(t *testing.T) {
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
	path := filepath.Join(t.TempDir(), "nested", "bundle.json")
	bundle := NewBundle(checkpoint, proof)
	if err := WriteBundle(path, bundle); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	loaded, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if loaded.Backend != LocalBackend || !checkpointsEqual(loaded.Checkpoint, checkpoint) {
		t.Fatalf("loaded bundle = %+v", loaded)
	}
	if loaded.Version != bundle.Version {
		t.Fatalf("loaded.Version = %d, want %d", loaded.Version, bundle.Version)
	}
	if loaded.Proof != bundle.Proof {
		t.Fatalf("loaded.Proof = %+v, want %+v", loaded.Proof, bundle.Proof)
	}
	if !loaded.CreatedAt.Equal(bundle.CreatedAt) {
		t.Fatalf("loaded.CreatedAt = %s, want %s", loaded.CreatedAt, bundle.CreatedAt)
	}
	if len(loaded.Limits) != len(bundle.Limits) {
		t.Fatalf("loaded.Limits = %v, want %v", loaded.Limits, bundle.Limits)
	}
	for i := range bundle.Limits {
		if loaded.Limits[i] != bundle.Limits[i] {
			t.Fatalf("loaded.Limits[%d] = %q, want %q", i, loaded.Limits[i], bundle.Limits[i])
		}
	}
}

func TestLoadBundleRejectsStrictJSONViolations(t *testing.T) {
	for name, data := range map[string]string{
		"duplicate": `{"version":1,"version":1}`,
		"unknown":   `{"version":1,"backend":"local","created_at":"2026-06-28T12:00:00Z","checkpoint":{},"proof":{},"limits":[],"extra":true}`,
		"trailing":  `{"version":1} {"version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := LoadBundle(path); err == nil {
				t.Fatal("LoadBundle err = nil, want strict JSON failure")
			}
		})
	}
}

func TestBuildCheckpointRejectsTrustErrors(t *testing.T) {
	if _, err := BuildCheckpoint("proxy", nil, []string{"key"}); err == nil || !strings.Contains(err.Error(), "empty receipt chain") {
		t.Fatalf("empty BuildCheckpoint err = %v", err)
	}
	receipts, _ := testReceiptChain(t, 1)
	if _, err := BuildCheckpoint("proxy", receipts, nil); err == nil || !strings.Contains(err.Error(), "trust anchor required") {
		t.Fatalf("missing trust BuildCheckpoint err = %v", err)
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

func TestVerifyBundleRejectsInvalidBundleAndBackendStates(t *testing.T) {
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

	badVersion := bundle
	badVersion.Version = 99
	if report := VerifyBundle(badVersion, receipts, []string{keyHex}, log); report.Valid || !strings.Contains(report.Error, "unsupported") {
		t.Fatalf("bad version report = %+v", report)
	}
	if report := VerifyBundle(bundle, receipts, []string{keyHex}, nil); report.Valid || !strings.Contains(report.Error, "backend required") {
		t.Fatalf("nil backend report = %+v", report)
	}
	rewrittenCheckpoint := bundle
	rewrittenCheckpoint.Checkpoint.RootHash = strings.Repeat("0", 64)
	if report := VerifyBundle(rewrittenCheckpoint, receipts, []string{keyHex}, log); report.Valid || !strings.Contains(report.Error, "checkpoint does not match") {
		t.Fatalf("checkpoint report = %+v", report)
	}
	if report := VerifyBundle(bundle, receipts, []string{keyHex}, failingBackend{}); report.Valid || !strings.Contains(report.Error, errBackendVerify.Error()) {
		t.Fatalf("backend report = %+v", report)
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

func TestLocalLogVerifyRejectsBadProofs(t *testing.T) {
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

	cases := []struct {
		name  string
		proof Proof
		want  string
	}{
		{name: "backend", proof: Proof{Backend: "rekor"}, want: "not"},
		{name: "log id", proof: Proof{Backend: LocalBackend, LogID: "other"}, want: "log_id"},
		{name: "index", proof: Proof{Backend: LocalBackend, LogID: "test-log", LogIndex: 99}, want: "outside local log length"},
		{name: "entry hash", proof: Proof{Backend: LocalBackend, LogID: "test-log", EntryHash: "bad", LogRootHash: proof.LogRootHash}, want: "entry_hash"},
		{name: "root hash", proof: Proof{Backend: LocalBackend, LogID: "test-log", EntryHash: proof.EntryHash, LogRootHash: "bad"}, want: "log_root_hash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := log.Verify(tc.proof, checkpoint); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify err = %v, want %q", err, tc.want)
			}
		})
	}

	changed := checkpoint
	changed.RootHash = strings.Repeat("f", 64)
	if err := log.Verify(proof, changed); err == nil || !strings.Contains(err.Error(), "checkpoint does not match") {
		t.Fatalf("Verify err = %v, want checkpoint mismatch", err)
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

func TestReadLocalLogRejectsCorruptEntries(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	if _, err := log.Submit(checkpoint); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	entries, err := ReadLocalLog(log.Path)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}

	tests := map[string]func([]LocalLogEntry){
		"version": func(in []LocalLogEntry) { in[0].Version = 99 },
		"index":   func(in []LocalLogEntry) { in[0].Index = 3 },
		"prev":    func(in []LocalLogEntry) { in[0].PrevHash = "bad" },
		"hash":    func(in []LocalLogEntry) { in[0].Hash = "bad" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copyEntries := append([]LocalLogEntry(nil), entries...)
			mutate(copyEntries)
			path := filepath.Join(t.TempDir(), "anchor.jsonl")
			writeLocalLogEntries(t, path, copyEntries)
			if _, err := ReadLocalLog(path); err == nil {
				t.Fatal("ReadLocalLog err = nil, want corrupt entry failure")
			}
		})
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

func TestLocalLogDefaults(t *testing.T) {
	if got := (LocalLog{}).logID(); got != DefaultLocalLogID {
		t.Fatalf("logID = %q, want %q", got, DefaultLocalLogID)
	}
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "")
	if got := nowString(); got == "" {
		t.Fatal("nowString returned empty timestamp")
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
