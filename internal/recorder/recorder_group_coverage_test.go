// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRecorderGroupWriterRefusesWritesAfterFinalization(t *testing.T) {
	r, key, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if got := (*Recorder)(nil).SigningKeyHex(); got != "" {
		t.Fatalf("nil signer ID=%q", got)
	}
	if got := r.SigningKeyHex(); got != hex.EncodeToString(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("checkpoint signer ID=%q", got)
	}
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	if err := r.FinalizeGroupSessions(); err != nil {
		t.Fatal(err)
	}
	entry := Entry{SessionID: sessions[0], Type: "test", Summary: "after group close"}
	if err := r.Record(entry); err == nil || !strings.Contains(err.Error(), "group is closing") {
		t.Fatalf("finalized group accepted write: %v", err)
	}
	if err := r.RecordDurable(entry); err == nil || !strings.Contains(err.Error(), "group is closing") {
		t.Fatalf("finalized group accepted durable write: %v", err)
	}
}

func TestRecorderNoopPreadvanceCallbacksRunExactlyOnce(t *testing.T) {
	r, err := New(Config{Enabled: false}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	advance := func() { count++ }
	entry := Entry{SessionID: "proxy", Type: "test"}
	if err := r.RecordWithReceiptScanPreAdvance(entry, nil, advance); err != nil || count != 1 {
		t.Fatalf("noop ordinary advance count=%d err=%v", count, err)
	}
	if err := r.RecordDurableWithReceiptScanPreAdvance(entry, nil, advance); err != nil || count != 2 {
		t.Fatalf("noop durable advance count=%d err=%v", count, err)
	}
}

func TestRecorderOversizedPreAdvanceRejectsBeforeConsumingPosition(t *testing.T) {
	r, _, _ := newGroupRecorder(t)
	count := 0
	entry := Entry{SessionID: "proxy", Type: "test", Detail: strings.Repeat("x", MaxEntryLineBytes)}
	err := r.RecordWithReceiptScanPreAdvance(entry, nil, func() { count++ })
	if !errors.Is(err, ErrSerializedEntryTooLarge) || count != 0 || r.seq != 0 {
		t.Fatalf("oversized entry err=%v advance=%d seq=%d", err, count, r.seq)
	}
	err = r.RecordDurableWithReceiptScanPreAdvance(entry, nil, func() { count++ })
	if !errors.Is(err, ErrSerializedEntryTooLarge) || count != 0 || r.seq != 0 {
		t.Fatalf("oversized durable entry err=%v advance=%d seq=%d", err, count, r.seq)
	}
}

func TestRecorderGroupDurableSyncFailureDoesNotReportSuccess(t *testing.T) {
	r, _, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	want := errors.New("injected group sync failure")
	r.SetSyncForTest(func(*os.File) error { return want })
	err := r.RecordDurable(Entry{SessionID: sessions[0], Type: "test", Summary: "not durable"})
	if !errors.Is(err, want) {
		t.Fatalf("failed group sync reported success: %v", err)
	}
}
