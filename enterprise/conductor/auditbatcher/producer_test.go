//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestHomogeneousRecorderNamespace(t *testing.T) {
	base := recorder.Entry{Version: recorder.LatestEntryVersion, SessionID: "session-a", ChainKind: recorder.ChainKindRecorder, WriterInstanceID: "writer-a"}
	for _, tc := range []struct {
		name   string
		mutate func(*recorder.Entry)
	}{
		{"version", func(e *recorder.Entry) { e.Version = recorder.CurrentWriteEntryVersion }},
		{"session_id", func(e *recorder.Entry) { e.SessionID = "session-b" }},
		{"chain_kind", func(e *recorder.Entry) { e.ChainKind = "receipt" }},
		{"writer_instance_id", func(e *recorder.Entry) { e.WriterInstanceID = "writer-b" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.mutate(&changed)
			if homogeneousRecorderNamespace([]recorder.Entry{base, changed}) {
				t.Fatalf("homogeneousRecorderNamespace() = true after %s change", tc.name)
			}
		})
	}
	if !homogeneousRecorderNamespace([]recorder.Entry{base, base}) {
		t.Fatal("homogeneousRecorderNamespace() = false for identical namespace")
	}
	legacy := recorder.Entry{Version: recorder.CurrentWriteEntryVersion}
	if !homogeneousRecorderNamespace([]recorder.Entry{legacy, legacy}) {
		t.Fatal("homogeneousRecorderNamespace() = false for v2 entries without namespace")
	}
}

func TestRecorderNamespaceLimit(t *testing.T) {
	known := make(map[string]struct{})
	for i := 0; i < maxActiveRecorderNamespaces; i++ {
		if !admitRecorderNamespace(known, fmt.Sprintf("v3-%d", i)) {
			t.Fatalf("namespace %d rejected below limit", i)
		}
	}
	if admitRecorderNamespace(known, "overflow") {
		t.Fatal("namespace above limit accepted")
	}
	if !admitRecorderNamespace(known, "v3-0") {
		t.Fatal("known namespace rejected at limit")
	}
}

func TestProducerRejectsTransportUnsupportedV1Segment(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProducer(t, q, &transportMetricsRecorder{}, priv)
	segment := checkpointSegment(0)
	for i := range segment {
		segment[i].Version = 1
		p.ObserveRecorderEntry(segment[i])
	}
	for _, entry := range checkpointSegment(2) {
		p.ObserveRecorderEntry(entry)
	}
	for _, entry := range namespacedCheckpointSegment(0, "writer-a") {
		p.ObserveRecorderEntry(entry)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	stats, err := q.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 1 || p.previousSegmentTail != "" {
		t.Fatalf("v1 segment pending=%d tail=%q, want legacy quarantined and v3 pending", stats.Pending, p.previousSegmentTail)
	}
}

func TestProducerRejectsLegacyNamespaceBeforeEnvelope(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProducer(t, q, &transportMetricsRecorder{}, priv)
	segment := checkpointSegment(0)
	for i := range segment {
		segment[i].ChainKind = recorder.ChainKindRecorder
		segment[i].WriterInstanceID = "unhashed"
		p.ObserveRecorderEntry(segment[i])
	}
	for _, entry := range checkpointSegment(2) {
		p.ObserveRecorderEntry(entry)
	}
	for _, entry := range namespacedCheckpointSegment(0, "writer-a") {
		p.ObserveRecorderEntry(entry)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	stats, err := q.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 1 || p.previousSegmentTail != "" {
		t.Fatalf("invalid namespace pending=%d tail=%q, want legacy quarantined and v3 pending", stats.Pending, p.previousSegmentTail)
	}
	lease, err := q.Claim()
	if err != nil {
		t.Fatal(err)
	}
	if got := lease.Batch.Envelope.Chain.WriterInstanceID; got != "writer-a" {
		t.Fatalf("independent v3 writer = %q, want writer-a", got)
	}
}

func TestProducerQuarantinesOnlyInvalidV3Namespace(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProducer(t, q, &transportMetricsRecorder{}, priv)
	invalid := namespacedCheckpointSegment(0, "writer-bad")
	for i := range invalid {
		invalid[i].WriterInstanceID = ""
		invalid[i].Hash = recorder.ComputeHash(invalid[i])
		p.ObserveRecorderEntry(invalid[i])
	}
	for _, entry := range namespacedCheckpointSegment(0, "writer-good") {
		p.ObserveRecorderEntry(entry)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	stats, err := q.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 1 {
		t.Fatalf("pending = %d, want independent valid namespace queued", stats.Pending)
	}
}

func TestProducer_EnqueuesSignedCheckpointSegment(t *testing.T) {
	auditPub, auditPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey audit: %v", err)
	}
	recorderPub, recorderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey recorder: %v", err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	producer, err := NewProducer(ProducerConfig{
		Queue:             q,
		OrgID:             "org-main",
		FleetID:           "prod",
		InstanceID:        "pl-prod-1",
		AuditSignerKeyID:  "audit-key-1",
		RecorderKeyID:     "recorder-key-1",
		AuditSigner:       auditPriv,
		RecorderPublicKey: recorderPub,
		Now:               func() time.Time { return time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC) },
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
	}, nil, recorderPriv)
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
	if batch.Envelope.Chain.SessionID != "" {
		t.Fatalf("v2 chain session_id = %q, want omitted for wire compatibility", batch.Envelope.Chain.SessionID)
	}
	if err := batch.Envelope.VerifySignatures(func(id string) (conductor.SignatureKey, error) {
		if id != "audit-key-1" {
			return conductor.SignatureKey{}, errors.New("unknown key")
		}
		return conductor.SignatureKey{PublicKey: auditPub, KeyPurpose: signing.PurposeAuditBatchSigning}, nil
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
	if batch.Envelope.Chain.FollowerRecorderPubHex != hex.EncodeToString(recorderPub) {
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
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	producer, err := NewProducer(ProducerConfig{
		Queue:             q,
		OrgID:             "org-main",
		FleetID:           "prod",
		InstanceID:        "pl-prod-1",
		AuditSignerKeyID:  "audit-key-1",
		RecorderKeyID:     "recorder-key-1",
		AuditSigner:       priv,
		RecorderPublicKey: priv.Public().(ed25519.PublicKey),
		BufferSize:        1,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}

	var stop atomic.Bool
	var observed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				producer.ObserveRecorderEntry(recorder.Entry{Version: recorder.EntryVersion})
				observed.Add(1)
			}
		}()
	}
	// Close must race against Observe in flight, not before the goroutines are
	// scheduled. Wait until contention is genuinely underway (observable, not a
	// timing guess) so the -race coverage is deterministic.
	testwait.For(t, time.Second, func() bool {
		return observed.Load() >= 100
	}, "producers to start observing under contention")
	if err := producer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	stop.Store(true)
	wg.Wait()
}

func TestNewProducer_RequiresRecorderPublicKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	_, err = NewProducer(ProducerConfig{
		Queue:            q,
		OrgID:            "org-main",
		FleetID:          "prod",
		InstanceID:       "pl-prod-1",
		AuditSignerKeyID: "audit-key-1",
		RecorderKeyID:    "recorder-key-1",
		AuditSigner:      priv,
	})
	if err == nil || !strings.Contains(err.Error(), "recorder public key length=0") {
		t.Fatalf("NewProducer() = %v, want recorder public key length error", err)
	}
}

func TestNewProducer_RejectsInvalidConfig(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ProducerConfig)
		want   string
	}{
		{
			name:   "missing_queue",
			mutate: func(cfg *ProducerConfig) { cfg.Queue = nil },
			want:   "queue required",
		},
		{
			name:   "bad_audit_signer",
			mutate: func(cfg *ProducerConfig) { cfg.AuditSigner = ed25519.PrivateKey("short") },
			want:   "private key length",
		},
		{
			name:   "bad_recorder_public_key",
			mutate: func(cfg *ProducerConfig) { cfg.RecorderPublicKey = ed25519.PublicKey("short") },
			want:   "recorder public key length",
		},
		{
			name:   "bad_identifier",
			mutate: func(cfg *ProducerConfig) { cfg.InstanceID = "-bad" },
			want:   "instance_id must start",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ProducerConfig{
				Queue:             q,
				OrgID:             "org-main",
				FleetID:           "prod",
				InstanceID:        "pl-prod-1",
				AuditSignerKeyID:  "audit-key-1",
				RecorderKeyID:     "recorder-key-1",
				AuditSigner:       priv,
				RecorderPublicKey: pub,
			}
			tc.mutate(&cfg)
			producer, err := NewProducer(cfg)
			if producer != nil {
				_ = producer.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewProducer() = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestProducer_AdvancesChainTailOnDroppedSegment proves the evidence chain
// stays continuous across a dropped segment. When a segment cannot ship (here:
// a full durable queue) the recorder has already committed its checkpoint
// locally, so previousSegmentTail must still advance - otherwise the next
// segment would claim continuity across a checkpoint that actually exists in
// the local recorder file, and a verifier replaying that file would reject the
// chain.
func TestProducer_AdvancesChainTailOnDroppedSegment(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue"), MaxPending: 1})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	metrics := &transportMetricsRecorder{}
	p := newTestProducer(t, q, metrics, priv)
	defer func() { _ = p.Close() }()

	// Segment A succeeds and fills the MaxPending=1 queue.
	segA := checkpointSegment(0)
	if err := p.enqueueSegment(segA); err != nil {
		t.Fatalf("segA enqueue: %v", err)
	}
	if p.previousSegmentTail != segA[1].Hash {
		t.Fatalf("tail after A = %q, want %q", p.previousSegmentTail, segA[1].Hash)
	}

	// Segment B is dropped because the queue is full, but its checkpoint was
	// recorded locally - the tail must advance to B's checkpoint hash.
	segB := checkpointSegment(2)
	if err := p.enqueueSegment(segB); err == nil {
		t.Fatal("segB enqueue: expected failure on full queue")
	}
	if p.previousSegmentTail != segB[1].Hash {
		t.Fatalf("tail after dropped B = %q, want advanced to %q", p.previousSegmentTail, segB[1].Hash)
	}
	if got := metrics.delivery["drop:queue_full"]; got != 1 {
		t.Fatalf("queue_full drop metric = %d, want 1", got)
	}

	// Free the queue and ship segment C. It must link back to dropped B's
	// tail, demonstrating the chain is continuous across the gap.
	if _, err := q.Claim(); err != nil {
		t.Fatalf("Claim segA: %v", err)
	}
	segC := checkpointSegment(4)
	if err := p.enqueueSegment(segC); err != nil {
		t.Fatalf("segC enqueue: %v", err)
	}
	lease, err := q.Claim()
	if err != nil {
		t.Fatalf("Claim segC: %v", err)
	}
	if got := lease.Batch.Envelope.Chain.PreviousSegmentTail; got != segB[1].Hash {
		t.Fatalf("segC PreviousSegmentTail = %q, want dropped-B tail %q", got, segB[1].Hash)
	}
	// The carried drop accounting from B must surface in C's signed envelope.
	if want := droppedActionReceiptCount(segB); lease.Batch.Envelope.Dropped.Count != want {
		t.Fatalf("segC dropped action count = %d, want %d", lease.Batch.Envelope.Dropped.Count, want)
	}
}

// TestProducer_QuarantinesInvalidCheckpoint covers the fail-closed boundary:
// an invalid checkpoint cannot become a trusted tail, and later entries in the
// same namespace cannot be emitted with stale continuity.
func TestProducer_QuarantinesInvalidCheckpoint(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	metrics := &transportMetricsRecorder{}
	p := newTestProducer(t, q, metrics, priv)

	seg := checkpointSegment(0)
	seg[1].Detail = recorder.CheckpointDetail{} // strip the checkpoint signature
	for _, entry := range append(seg, checkpointSegment(2)...) {
		p.ObserveRecorderEntry(entry)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if p.previousSegmentTail != "" {
		t.Fatalf("tail advanced from invalid checkpoint: %q", p.previousSegmentTail)
	}
	if got := metrics.delivery["drop:invalid_checkpoint"]; got != 2 {
		t.Fatalf("invalid_checkpoint drop metric = %d, want 2", got)
	}
	stats, err := q.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Pending != 0 {
		t.Fatalf("pending = %d, want 0 after namespace quarantine", stats.Pending)
	}
}

func TestProducer_AdvancesTailOnMixedNamespaceRejection(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProducer(t, q, &transportMetricsRecorder{}, priv)
	defer func() { _ = p.Close() }()
	seg := checkpointSegment(0)
	seg[1].Version = recorder.LatestEntryVersion
	seg[1].ChainKind = recorder.ChainKindRecorder
	seg[1].WriterInstanceID = "writer-a"
	if err := p.enqueueSegment(seg); err == nil {
		t.Fatal("mixed namespace segment accepted")
	}
	key := recorderNamespaceKey(seg[1])
	if got := p.previousSegmentTailFor(key); got != "" {
		t.Fatalf("tail advanced after mixed namespace rejection: %q", got)
	}
}

func TestProducer_IsolatesInterleavedV3Namespaces(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProducer(t, q, &transportMetricsRecorder{}, priv)

	firstA := namespacedCheckpointSegment(0, "writer-a")
	firstB := namespacedCheckpointSegment(0, "writer-b")
	for _, entry := range []recorder.Entry{firstA[0], firstB[0], firstA[1], firstB[1]} {
		p.ObserveRecorderEntry(entry)
	}
	secondA := namespacedCheckpointSegment(2, "writer-a")
	secondB := namespacedCheckpointSegment(2, "writer-b")
	for _, entry := range append(secondA, secondB...) {
		p.ObserveRecorderEntry(entry)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	wantPrevious := []string{"", "", firstA[1].Hash, firstB[1].Hash}
	wantWriters := []string{"writer-a", "writer-b", "writer-a", "writer-b"}
	for i := range wantPrevious {
		lease, err := q.Claim()
		if err != nil {
			t.Fatalf("Claim batch %d: %v", i, err)
		}
		chain := lease.Batch.Envelope.Chain
		if chain.WriterInstanceID != wantWriters[i] || chain.PreviousSegmentTail != wantPrevious[i] {
			t.Fatalf("batch %d writer/tail = %q/%q, want %q/%q", i, chain.WriterInstanceID, chain.PreviousSegmentTail, wantWriters[i], wantPrevious[i])
		}
	}
}

func TestProducer_IsolatesInterleavedV3Sessions(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProducer(t, q, &transportMetricsRecorder{}, priv)

	first := namespacedCheckpointSegment(0, "writer-a")
	second := namespacedCheckpointSegment(0, "writer-a")
	for i := range first {
		first[i].SessionID = "session-a"
		second[i].SessionID = "session-b"
	}
	for _, entry := range []recorder.Entry{first[0], second[0], first[1], second[1]} {
		p.ObserveRecorderEntry(entry)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	for i, wantSession := range []string{"session-a", "session-b"} {
		lease, err := q.Claim()
		if err != nil {
			t.Fatalf("Claim batch %d: %v", i, err)
		}
		chain := lease.Batch.Envelope.Chain
		if chain.SessionID != wantSession || chain.PreviousSegmentTail != "" {
			t.Fatalf("batch %d session/tail = %q/%q, want %q/empty", i, chain.SessionID, chain.PreviousSegmentTail, wantSession)
		}
	}
}

func TestProducer_ReleaseDroppedPreservesConcurrentDrops(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	p := newTestProducer(t, q, nil, priv)
	defer func() { _ = p.Close() }()

	p.drop(producerDropQueueFull, 2)
	included := p.droppedAccounting()
	p.drop(producerDropQueueFull, 1)
	p.drop(producerDropChannelFull, 1)

	p.releaseDropped(included)
	got := p.droppedAccounting()
	if got.Count != 2 {
		t.Fatalf("dropped count after release = %d, want 2", got.Count)
	}
	reasons := map[string]uint64{}
	for _, reason := range got.Reasons {
		reasons[reason.Reason] = reason.Count
	}
	if reasons[producerDropQueueFull] != 1 {
		t.Fatalf("remaining queue_full drops = %d, want 1", reasons[producerDropQueueFull])
	}
	if reasons[producerDropChannelFull] != 1 {
		t.Fatalf("remaining channel_full drops = %d, want 1", reasons[producerDropChannelFull])
	}
}

func TestProducer_EnqueueSegmentDropPaths(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tests := []struct {
		name   string
		mutate func([]recorder.Entry) []recorder.Entry
		want   string
	}{
		{
			name: "marshal_error",
			mutate: func(seg []recorder.Entry) []recorder.Entry {
				seg[0].Detail = map[string]any{"bad": make(chan int)}
				return seg
			},
			want: producerDropEnqueueError,
		},
		{
			name: "payload_too_large",
			mutate: func(seg []recorder.Entry) []recorder.Entry {
				seg[0].Detail = map[string]any{"large": strings.Repeat("x", conductor.MaxAuditPayloadBytes)}
				return seg
			},
			want: producerDropPayloadTooLarge,
		},
		{
			name: "non_checkpoint_tail",
			mutate: func(seg []recorder.Entry) []recorder.Entry {
				seg[1].Type = "action_receipt"
				return seg
			},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
			if err != nil {
				t.Fatalf("Open queue: %v", err)
			}
			p := newTestProducer(t, q, nil, priv)
			defer func() { _ = p.Close() }()

			seg := tc.mutate(checkpointSegment(0))
			err = p.enqueueSegment(seg)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("enqueueSegment() = %v, want nil", err)
				}
				if got := p.droppedAccounting().Count; got != 0 {
					t.Fatalf("dropped count = %d, want 0", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("enqueueSegment() = %v, want substring %q", err, tc.want)
			}
			accounting := p.droppedAccounting()
			if want := droppedActionReceiptCount(seg); accounting.Count != want {
				t.Fatalf("dropped action count = %d, want %d", accounting.Count, want)
			}
		})
	}
}

func TestProducerHelpers(t *testing.T) {
	if got := ed25519SignatureString("ed25519:abc"); got != "ed25519:abc" {
		t.Fatalf("prefixed signature = %q", got)
	}
	if got := ed25519SignatureString("abc"); got != "ed25519:abc" {
		t.Fatalf("unprefixed signature = %q", got)
	}
	if got := segmentID(recorder.Entry{Sequence: 1}, 2); got != "segment-recorder-00000000000000000001-00000000000000000002" {
		t.Fatalf("segmentID(empty) = %q", got)
	}
	entry := recorder.Entry{
		Version: recorder.LatestEntryVersion, SessionID: "proxy", Sequence: 1,
		ChainKind: recorder.ChainKindRecorder, WriterInstanceID: "writer-a",
	}
	if got := segmentID(entry, 2); got != "segment-proxy-840f4f71315f14ee-00000000000000000001-00000000000000000002" {
		t.Fatalf("segmentID(v3) = %q", got)
	}
	if got := safeSegmentPart("a/b:c"); got != "abc" {
		t.Fatalf("safeSegmentPart() = %q", got)
	}
	if got := safeSegmentPart("///"); got != "recorder" {
		t.Fatalf("safeSegmentPart(empty) = %q", got)
	}
}

func newTestProducer(t *testing.T, q *Queue, metrics MetricsSink, priv ed25519.PrivateKey) *Producer {
	t.Helper()
	p, err := NewProducer(ProducerConfig{
		Queue:             q,
		Metrics:           metrics,
		OrgID:             "org-main",
		FleetID:           "prod",
		InstanceID:        "pl-prod-1",
		AuditSignerKeyID:  "audit-key-1",
		RecorderKeyID:     "recorder-key-1",
		AuditSigner:       priv,
		RecorderPublicKey: priv.Public().(ed25519.PublicKey),
		Now:               func() time.Time { return time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	return p
}

// checkpointSegment builds a [regular, checkpoint] entry pair with valid
// 64-hex chain hashes and a well-formed checkpoint signature so the producer
// can construct and sign a valid envelope. start and start+1 are the two
// sequence numbers.
func checkpointSegment(start uint64) []recorder.Entry {
	reg := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  start,
		SessionID: "proxy",
		Type:      "action_receipt",
		Hash:      segmentHashHex(fmt.Sprintf("head-%d", start)),
	}
	cp := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  start + 1,
		SessionID: "proxy",
		Type:      "checkpoint",
		Hash:      segmentHashHex(fmt.Sprintf("tail-%d", start+1)),
		Detail: recorder.CheckpointDetail{
			EntryCount: 2,
			FirstSeq:   start,
			LastSeq:    start + 1,
			Signature:  strings.Repeat("ab", ed25519.SignatureSize),
		},
	}
	return []recorder.Entry{reg, cp}
}

func namespacedCheckpointSegment(start uint64, writer string) []recorder.Entry {
	segment := checkpointSegment(start)
	for i := range segment {
		segment[i].Version = 3
		segment[i].ChainKind = recorder.ChainKindRecorder
		segment[i].WriterInstanceID = writer
	}
	return segment
}

func segmentHashHex(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
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
	// Poll without time.Sleep. A ticker (not testwait.For) is used here so the
	// failure diagnostic can include the live droppedAccounting() snapshot,
	// which testwait.For's eagerly-evaluated format args cannot capture.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(2 * time.Second)
	for {
		stats, err := q.Stats()
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if stats.Pending == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("pending = %d, want %d; dropped=%#v", stats.Pending, want, producer.droppedAccounting())
		case <-ticker.C:
		}
	}
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
