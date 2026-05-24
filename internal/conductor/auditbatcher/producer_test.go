// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package auditbatcher

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestProducer_EnqueuesSignedCheckpointSegment(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	q, err := Open(Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	producer, err := NewProducer(ProducerConfig{
		Queue:            q,
		OrgID:            "org-main",
		FleetID:          "prod",
		InstanceID:       "pl-prod-1",
		AuditSignerKeyID: "audit-key-1",
		RecorderKeyID:    "recorder-key-1",
		AuditSigner:      priv,
		Now:              func() time.Time { return time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                filepath.Join(t.TempDir(), "recorder"),
		CheckpointInterval: 2,
		SignCheckpoints:    true,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	rec.SetObserver(producer)
	if err := rec.Record(testRecorderEntry("first")); err != nil {
		t.Fatalf("Record first: %v", err)
	}
	if err := rec.Record(testRecorderEntry("second")); err != nil {
		t.Fatalf("Record second: %v", err)
	}

	waitForPending(t, q, producer, 1)
	lease, err := q.Claim()
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	batch := lease.Batch
	if err := batch.Envelope.VerifySignatures(func(id string) (conductor.SignatureKey, error) {
		if id != "audit-key-1" {
			return conductor.SignatureKey{}, errors.New("unknown key")
		}
		return conductor.SignatureKey{PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning}, nil
	}); err != nil {
		t.Fatalf("VerifySignatures: %v", err)
	}
	if err := batch.Envelope.ValidatePayload(batch.Payload); err != nil {
		t.Fatalf("ValidatePayload: %v", err)
	}
	if batch.Envelope.SeqStart != 0 || batch.Envelope.SeqEnd != 2 {
		t.Fatalf("seq range = %d-%d, want 0-2", batch.Envelope.SeqStart, batch.Envelope.SeqEnd)
	}
	if batch.Envelope.EventCount != 3 {
		t.Fatalf("event_count = %d, want 3", batch.Envelope.EventCount)
	}
	if batch.Envelope.Chain.CheckpointSeq != 2 {
		t.Fatalf("checkpoint_seq = %d, want 2", batch.Envelope.Chain.CheckpointSeq)
	}
	if batch.Envelope.Chain.CheckpointSignerKeyID != "recorder-key-1" {
		t.Fatalf("checkpoint signer = %q", batch.Envelope.Chain.CheckpointSignerKeyID)
	}
	if batch.Envelope.Chain.FollowerRecorderPubHex != hex.EncodeToString(pub) {
		t.Fatalf("recorder public key mismatch")
	}
	var decoded []recorder.Entry
	for _, line := range splitJSONLines(batch.Payload) {
		var entry recorder.Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("payload entry decode: %v", err)
		}
		decoded = append(decoded, entry)
	}
	if len(decoded) != 3 || decoded[2].Type != "checkpoint" {
		t.Fatalf("decoded entries = %#v, want two records plus checkpoint", decoded)
	}
}

func TestProducer_CloseRacesWithObserver(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	q, err := Open(Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	producer, err := NewProducer(ProducerConfig{
		Queue:            q,
		OrgID:            "org-main",
		FleetID:          "prod",
		InstanceID:       "pl-prod-1",
		AuditSignerKeyID: "audit-key-1",
		RecorderKeyID:    "recorder-key-1",
		AuditSigner:      priv,
		BufferSize:       1,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				producer.ObserveRecorderEntry(recorder.Entry{Version: recorder.EntryVersion})
			}
		}()
	}
	time.Sleep(10 * time.Millisecond)
	if err := producer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	stop.Store(true)
	wg.Wait()
}

func testRecorderEntry(summary string) recorder.Entry {
	return recorder.Entry{
		SessionID: "proxy",
		Type:      "action_receipt",
		EventKind: "read",
		Transport: "fetch",
		Summary:   summary,
		Detail: map[string]any{
			"summary": summary,
		},
	}
}

func waitForPending(t *testing.T, q *Queue, producer *Producer, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stats, err := q.Stats()
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if stats.Pending == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats, err := q.Stats()
	if err != nil {
		t.Fatalf("Stats after wait: %v", err)
	}
	t.Fatalf("pending = %d, want %d; dropped=%#v", stats.Pending, want, producer.droppedAccounting())
}

func splitJSONLines(payload []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range payload {
		if b != '\n' {
			continue
		}
		if i > start {
			lines = append(lines, payload[start:i])
		}
		start = i + 1
	}
	return lines
}
