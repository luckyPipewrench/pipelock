// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func newReceiptScanRecorder(t *testing.T, dir string, scans *atomic.Int64) *recorder.Recorder {
	t.Helper()
	r, err := recorder.New(recorder.Config{
		Enabled: true, Dir: dir, Redact: true, CheckpointInterval: 1000,
	}, func(_ context.Context, text string) scanner.TextDLPResult {
		if strings.HasPrefix(text, "{") {
			scans.Add(1)
		}
		return scanner.TextDLPResult{Clean: !strings.Contains(text, "test-sensitive-value") && !strings.Contains(text, `"evil"`)}
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func receiptScanEntry(detail any) recorder.Entry {
	return recorder.Entry{SessionID: "receipt-scan", Type: "action_receipt", Detail: detail}
}

func TestReceiptScanProductionDLPEncodingParity(t *testing.T) {
	secret := "ghp_" + strings.Repeat("D", 40)
	sc := scanner.MustNew(config.Defaults())
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name       string
		detail     map[string]string
		wantReject bool
	}{
		{name: "literal", detail: map[string]string{"value": secret}, wantReject: true},
		{name: "base64", detail: map[string]string{"value": base64.StdEncoding.EncodeToString([]byte(secret))}, wantReject: true},
		{name: "hex", detail: map[string]string{"value": hex.EncodeToString([]byte(secret))}, wantReject: true},
		{name: "URL encoded", detail: map[string]string{"value": strings.Replace(secret, "_", "%5F", 1)}, wantReject: true},
		// JSON field names and punctuation separate these values. The full
		// text scanner does not currently reassemble them into one token.
		{name: "split across fields", detail: map[string]string{"left": secret[:12], "right": secret[12:]}, wantReject: false},
		{name: "clean", detail: map[string]string{"value": "ordinary receipt detail"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.detail)
			if err != nil {
				t.Fatal(err)
			}
			if got := sc.ScanTextForDLP(context.Background(), string(raw)).Clean; got == tc.wantReject {
				t.Fatalf("production DLP clean = %t, want reject = %t", got, tc.wantReject)
			}
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc.ScanTextForDLP, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rec.Close() })
			_, err = rec.PreflightSignedReceiptDetail(tc.detail)
			if got := err != nil; got != tc.wantReject {
				t.Fatalf("recorder rejected = %t, want %t: %v", got, tc.wantReject, err)
			}
			err = rec.Record(receiptScanEntry(tc.detail))
			if got := err != nil; got != tc.wantReject {
				t.Fatalf("direct record rejected = %t, want %t: %v", got, tc.wantReject, err)
			}
		})
	}
}

// The first marshal is the preflight and the second is the write-boundary
// comparison. Any later marshal of the caller's object would expose a secret.
type changingReceiptDetail struct{ calls int }

func (d *changingReceiptDetail) MarshalJSON() ([]byte, error) {
	d.calls++
	if d.calls > 2 {
		return []byte(`{"value":"test-sensitive-value"}`), nil
	}
	return []byte(`{"value":"safe"}`), nil
}

type failingReceiptDetail struct{ calls int }

func (d *failingReceiptDetail) MarshalJSON() ([]byte, error) {
	d.calls++
	if d.calls > 1 {
		return nil, errors.New("injected second marshal failure")
	}
	return []byte(`{"value":"safe"}`), nil
}

type mutatingReceiptObserver struct{}

func (mutatingReceiptObserver) ObserveRecorderEntry(e recorder.Entry) {
	if e.Type != "action_receipt" {
		return
	}
	if raw, ok := e.Detail.(json.RawMessage); ok {
		copy(raw, []byte(`{"value":"evil"}`))
	}
}

func TestReceiptScanRunsOnceAndDirectCallersRejectSecrets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    string
		durable bool
	}{
		{name: "action best effort", kind: "action_receipt"},
		{name: "action durable", kind: "action_receipt", durable: true},
		{name: "evidence best effort", kind: "evidence_receipt"},
		{name: "evidence durable", kind: "evidence_receipt", durable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var scans atomic.Int64
			dir := t.TempDir()
			r := newReceiptScanRecorder(t, dir, &scans)
			clean := receiptScanEntry(json.RawMessage(`{"value":"safe"}`))
			clean.Type = tc.kind
			scan, err := r.PreflightSignedReceiptDetail(clean.Detail)
			if err != nil {
				t.Fatalf("PreflightSignedReceiptDetail: %v", err)
			}
			if tc.durable {
				err = r.RecordDurableWithReceiptScan(clean, &scan)
			} else {
				err = r.RecordWithReceiptScan(clean, &scan)
			}
			if err != nil {
				t.Fatalf("record preflighted detail: %v", err)
			}
			if got := scans.Load(); got != 1 {
				t.Fatalf("DLP scans = %d, want exactly one", got)
			}

			dirty := receiptScanEntry(map[string]string{"value": "test-sensitive-value"})
			dirty.Type = tc.kind
			if tc.durable {
				err = r.RecordDurable(dirty)
			} else {
				err = r.Record(dirty)
			}
			if err == nil || !strings.Contains(err.Error(), "refusing to record unverifiable redaction") {
				t.Fatalf("direct dirty receipt error = %v", err)
			}
			if got := scans.Load(); got != 2 {
				t.Fatalf("DLP scans = %d, want direct caller scanned", got)
			}
			if err := r.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-receipt-scan-0.jsonl"))
			if err != nil {
				t.Fatalf("ReadEntries: %v", err)
			}
			if err := recorder.VerifyChain(entries); err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			var receipts int
			for _, written := range entries {
				if written.Type == tc.kind {
					receipts++
				}
			}
			if receipts != 1 {
				t.Fatalf("receipts = %d, want only clean receipt", receipts)
			}
		})
	}
}

func TestReceiptScanRejectsChangedDetailBeforeWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		durable bool
	}{
		{name: "best effort"},
		{name: "durable", durable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var scans atomic.Int64
			dir := t.TempDir()
			r := newReceiptScanRecorder(t, dir, &scans)
			original := map[string]string{"value": "safe"}
			scan, err := r.PreflightSignedReceiptDetail(original)
			if err != nil {
				t.Fatalf("PreflightSignedReceiptDetail: %v", err)
			}
			// The scanned map is caller-owned. Change it after preflight,
			// then prove the recorder refuses the changed bytes.
			original["value"] = "test-sensitive-value"
			entry := receiptScanEntry(original)
			if tc.durable {
				err = r.RecordDurableWithReceiptScan(entry, &scan)
			} else {
				err = r.RecordWithReceiptScan(entry, &scan)
			}
			if err == nil || !strings.Contains(err.Error(), "changed after DLP scan") {
				t.Fatalf("changed detail error = %v", err)
			}
			if got := scans.Load(); got != 1 {
				t.Fatalf("DLP scans = %d, want only original preflight", got)
			}
			if err := r.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			matches, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
			if err != nil {
				t.Fatalf("Glob: %v", err)
			}
			for _, path := range matches {
				entries, err := recorder.ReadEntries(path)
				if err != nil {
					t.Fatalf("ReadEntries: %v", err)
				}
				for _, written := range entries {
					if written.Type == "action_receipt" {
						t.Fatal("changed receipt was persisted")
					}
				}
			}
		})
	}
}

func TestReceiptScanWritesVerifiedBytesInsteadOfCallerObject(t *testing.T) {
	var scans atomic.Int64
	dir := t.TempDir()
	r := newReceiptScanRecorder(t, dir, &scans)
	detail := &changingReceiptDetail{}
	scan, err := r.PreflightSignedReceiptDetail(detail)
	if err != nil {
		t.Fatalf("PreflightSignedReceiptDetail: %v", err)
	}
	if err := r.RecordWithReceiptScan(receiptScanEntry(detail), &scan); err != nil {
		t.Fatalf("RecordWithReceiptScan: %v", err)
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("DLP scans = %d, want one", got)
	}
	if got := detail.calls; got != 2 {
		t.Fatalf("caller detail marshals = %d, want only preflight and boundary comparison", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-receipt-scan-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	raw, err := json.Marshal(entries[0].Detail)
	if err != nil {
		t.Fatalf("marshal recorded detail: %v", err)
	}
	if string(raw) != `{"value":"safe"}` {
		t.Fatalf("recorded detail = %s, want exact scanned JSON", raw)
	}
}

func TestReceiptScanObserverCannotMutateAttestation(t *testing.T) {
	var scans atomic.Int64
	dir := t.TempDir()
	r := newReceiptScanRecorder(t, dir, &scans)
	r.SetObserver(mutatingReceiptObserver{})
	detail := json.RawMessage(`{"value":"safe"}`)
	scan, err := r.PreflightSignedReceiptDetail(detail)
	if err != nil {
		t.Fatalf("PreflightSignedReceiptDetail: %v", err)
	}
	if err := r.RecordWithReceiptScan(receiptScanEntry(detail), &scan); err != nil {
		t.Fatalf("first RecordWithReceiptScan: %v", err)
	}
	// An observer that received the attestation's backing bytes could turn
	// this reusable clean scan into a permit for bytes the DLP would reject.
	changed := receiptScanEntry(json.RawMessage(`{"value":"evil"}`))
	if err := r.RecordWithReceiptScan(changed, &scan); err == nil || !strings.Contains(err.Error(), "changed after DLP scan") {
		t.Fatalf("reused scan for changed detail error = %v", err)
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("DLP scans = %d, want only original preflight", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-receipt-scan-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	raw, err := json.Marshal(entries[0].Detail)
	if err != nil {
		t.Fatalf("marshal recorded detail: %v", err)
	}
	if string(raw) != `{"value":"safe"}` {
		t.Fatalf("recorded detail = %s, want scanned JSON", raw)
	}
}

func TestReceiptScanRejectsBoundaryMarshalFailure(t *testing.T) {
	var scans atomic.Int64
	dir := t.TempDir()
	r := newReceiptScanRecorder(t, dir, &scans)
	detail := &failingReceiptDetail{}
	scan, err := r.PreflightSignedReceiptDetail(detail)
	if err != nil {
		t.Fatalf("PreflightSignedReceiptDetail: %v", err)
	}
	err = r.RecordWithReceiptScan(receiptScanEntry(detail), &scan)
	if err == nil || !strings.Contains(err.Error(), "marshal signed receipt detail at write boundary") {
		t.Fatalf("boundary marshal error = %v", err)
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("DLP scans = %d, want one clean preflight", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	for _, path := range matches {
		entries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatalf("ReadEntries: %v", err)
		}
		for _, written := range entries {
			if written.Type == "action_receipt" {
				t.Fatal("receipt with unmarshalable final detail was persisted")
			}
		}
	}
}

func TestReceiptScanConcurrentWritersKeepChain(t *testing.T) {
	var scans atomic.Int64
	dir := t.TempDir()
	r := newReceiptScanRecorder(t, dir, &scans)
	const writers = 32
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			detail := map[string]int{"writer": id}
			scan, err := r.PreflightSignedReceiptDetail(detail)
			if err == nil {
				entry := receiptScanEntry(detail)
				if id%2 == 0 {
					err = r.RecordWithReceiptScan(entry, &scan)
				} else {
					err = r.RecordDurableWithReceiptScan(entry, &scan)
				}
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent record: %v", err)
		}
	}
	if got := scans.Load(); got != writers {
		t.Fatalf("DLP scans = %d, want %d", got, writers)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-receipt-scan-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain after %d concurrent writers: %v", writers, err)
	}
	var receipts int
	for i, entry := range entries {
		if entry.Sequence != uint64(i) {
			t.Fatalf("sequence %d = %d", i, entry.Sequence)
		}
		if entry.Type == "action_receipt" {
			receipts++
		}
	}
	if receipts != writers {
		t.Fatalf("receipts = %d, want %d", receipts, writers)
	}
}

func TestReceiptScanInvalidAttestationCannotWrite(t *testing.T) {
	var scans atomic.Int64
	r := newReceiptScanRecorder(t, t.TempDir(), &scans)
	entry := receiptScanEntry(map[string]string{"value": "test-sensitive-value"})
	if err := r.RecordWithReceiptScan(entry, &recorder.ReceiptScan{}); err == nil || !strings.Contains(err.Error(), "attestation is invalid") {
		t.Fatalf("zero attestation error = %v", err)
	}
	if err := r.RecordWithReceiptScan(entry, nil); err == nil || !strings.Contains(err.Error(), "refusing to record unverifiable redaction") {
		t.Fatalf("missing attestation error = %v", err)
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("DLP scans = %d, want one fallback scan", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
