//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTransportDeliverOnceSuccessAcksRecord(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	if _, err := q.Enqueue(signedTestBatch(t, "batch-transport-success", priv)); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	var sawPath, sawMethod bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path == AuditBatchesPath
		sawMethod = r.Method == http.MethodPost
		var upload batchUpload
		if err := json.NewDecoder(r.Body).Decode(&upload); err != nil {
			t.Fatalf("Decode(upload) error = %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	metrics := &transportMetricsRecorder{}
	tr, err := NewTransport(TransportConfig{
		BaseURL: srv.URL,
		Client:  srv.Client(),
		Queue:   q,
		Metrics: metrics,
	})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	if err := tr.DeliverOnce(t.Context()); err != nil {
		t.Fatalf("DeliverOnce() error = %v", err)
	}
	if !sawPath || !sawMethod {
		t.Fatalf("request path/method mismatch: sawPath=%v sawMethod=%v", sawPath, sawMethod)
	}
	assertStats(t, q, Stats{})
	if got := metrics.delivery["success:success"]; got != 1 {
		t.Fatalf("success metric = %d, want 1", got)
	}
	if metrics.lastStats != (Stats{}) {
		t.Fatalf("last queue stats = %+v, want empty", metrics.lastStats)
	}
}

func TestTransportDeliverOnceRetryReleasesRecord(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	id, err := q.Enqueue(signedTestBatch(t, "batch-transport-retry", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	metrics := &transportMetricsRecorder{}
	tr, err := NewTransport(TransportConfig{BaseURL: srv.URL, Client: srv.Client(), Queue: q, Metrics: metrics})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	if err := tr.DeliverOnce(t.Context()); err == nil {
		t.Fatal("DeliverOnce() error = nil, want retry error")
	}
	assertStats(t, q, Stats{Pending: 1})

	record, err := readRecord(filepath.Join(q.pendingDir, id), q.maxPayloadBytes)
	if err != nil {
		t.Fatalf("readRecord(pending) error = %v", err)
	}
	if record.RetryCount != 1 {
		t.Fatalf("RetryCount = %d, want 1", record.RetryCount)
	}
	if got := metrics.delivery["retry:http_server_error"]; got != 1 {
		t.Fatalf("retry metric = %d, want 1", got)
	}
}

func TestTransportDeliverOnceClientErrorDropsRecord(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	id, err := q.Enqueue(signedTestBatch(t, "batch-transport-drop", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	metrics := &transportMetricsRecorder{}
	tr, err := NewTransport(TransportConfig{BaseURL: srv.URL, Client: srv.Client(), Queue: q, Metrics: metrics})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	if err := tr.DeliverOnce(t.Context()); err == nil {
		t.Fatal("DeliverOnce() error = nil, want terminal delivery error")
	}
	assertStats(t, q, Stats{Dead: 1})

	record, err := readRecord(filepath.Join(q.deadDir, id), q.maxPayloadBytes)
	if err != nil {
		t.Fatalf("readRecord(dead) error = %v", err)
	}
	if record.DroppedReason != deliveryReasonClientError {
		t.Fatalf("DroppedReason = %q, want %q", record.DroppedReason, deliveryReasonClientError)
	}
	if got := metrics.delivery["drop:http_client_error"]; got != 1 {
		t.Fatalf("drop metric = %d, want 1", got)
	}
}

func TestTransportDeliverOnceQueueEmpty(t *testing.T) {
	q := openTestQueue(t, Config{})
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	tr, err := NewTransport(TransportConfig{BaseURL: srv.URL, Client: srv.Client(), Queue: q})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	if err := tr.DeliverOnce(t.Context()); !errors.Is(err, ErrQueueEmpty) {
		t.Fatalf("DeliverOnce() = %v, want ErrQueueEmpty", err)
	}
}

func TestNewTransportRequiresHTTPSBaseURL(t *testing.T) {
	q := openTestQueue(t, Config{})
	_, err := NewTransport(TransportConfig{BaseURL: "http://conductor.example", Client: http.DefaultClient, Queue: q})
	if err == nil {
		t.Fatal("NewTransport() error = nil, want HTTPS requirement")
	}
}

// TestTransportWireFormat_StableContract pins the JSON contract Boss-side
// ingest will need to honor. Drift in field names or shape breaks every
// deployed follower the moment Boss is built. Decode-side checks are
// intentionally strict: top-level keys are exactly {envelope, payload};
// payload is a base64-encoded string of the raw bytes; envelope round-trips
// to the same AuditBatchEnvelope the queue stored.
func TestTransportWireFormat_StableContract(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	batch := signedTestBatch(t, "batch-wire-format", priv)
	if _, err := q.Enqueue(batch); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	type wireShape struct {
		Envelope json.RawMessage `json:"envelope"`
		Payload  string          `json:"payload"`
	}
	var capturedRaw json.RawMessage
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll(body) error = %v", err)
		}
		capturedRaw = body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tr, err := NewTransport(TransportConfig{BaseURL: srv.URL, Client: srv.Client(), Queue: q})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	if err := tr.DeliverOnce(t.Context()); err != nil {
		t.Fatalf("DeliverOnce() error = %v", err)
	}

	// Top-level shape: exactly {envelope, payload}.
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(capturedRaw, &topLevel); err != nil {
		t.Fatalf("Unmarshal(topLevel) error = %v", err)
	}
	if len(topLevel) != 2 {
		t.Fatalf("top-level keys = %d, want exactly 2 (envelope, payload). got=%v", len(topLevel), topLevel)
	}
	if _, ok := topLevel["envelope"]; !ok {
		t.Fatal(`top-level missing "envelope" key`)
	}
	if _, ok := topLevel["payload"]; !ok {
		t.Fatal(`top-level missing "payload" key`)
	}

	// Strict decode against the contract.
	var wire wireShape
	dec := json.NewDecoder(bytes.NewReader(capturedRaw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		t.Fatalf("strict decode error = %v; wire format must be {envelope, payload} with no extra keys", err)
	}
	decodedPayload, err := base64.StdEncoding.DecodeString(wire.Payload)
	if err != nil {
		t.Fatalf("payload not standard base64: %v", err)
	}
	if string(decodedPayload) != string(batch.Payload) {
		t.Fatalf("payload round-trip mismatch: got=%q want=%q", decodedPayload, batch.Payload)
	}
	// Envelope must include the signed BatchID — proves the producer envelope
	// was forwarded, not a sanitized copy.
	var envCheck struct {
		BatchID string `json:"batch_id"`
	}
	if err := json.Unmarshal(wire.Envelope, &envCheck); err != nil {
		t.Fatalf("envelope decode error = %v", err)
	}
	if envCheck.BatchID != "batch-wire-format" {
		t.Fatalf("envelope.batch_id = %q, want batch-wire-format", envCheck.BatchID)
	}
}

// TestTransportRun_GracefulShutdown spins Run on a server that returns 503
// (forcing the retry path), cancels ctx, and asserts Run returns ctx.Err()
// within a bounded window. Without this, a stuck transport could hang
// pipelock shutdown indefinitely.
func TestTransportRun_GracefulShutdown(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	if _, err := q.Enqueue(signedTestBatch(t, "batch-shutdown", priv)); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	tr, err := NewTransport(TransportConfig{
		BaseURL:    srv.URL,
		Client:     srv.Client(),
		Queue:      q,
		RetryDelay: 10 * time.Millisecond,
		EmptyDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	runErrCh := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErrCh <- tr.Run(ctx)
	}()

	// Give the loop a turn so we exercise the retry-sleep path before cancel.
	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case err := <-runErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not return within 1s after context cancellation")
	}
	wg.Wait()

	// Record must still be present (retry kept it pending) or back in pending.
	// Either way, no data loss on shutdown.
	stats, err := q.Stats()
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Pending+stats.Inflight+stats.Dead != 1 {
		t.Fatalf("total records = %d, want 1 (no loss on shutdown). stats=%+v", stats.Pending+stats.Inflight+stats.Dead, stats)
	}
	if stats.Dead != 0 {
		t.Fatalf("dead=%d, want 0 (5xx is retry, not dead-letter)", stats.Dead)
	}
}

func TestTransportRunRejectsNilContext(t *testing.T) {
	q := openTestQueue(t, Config{})
	tr, err := NewTransport(TransportConfig{BaseURL: "https://conductor.example", Client: http.DefaultClient, Queue: q})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	if err := tr.Run(nilTestContext()); err == nil || err.Error() != "auditbatcher: nil context" {
		t.Fatalf("Run(nil) = %v, want nil context error", err)
	}
}

func nilTestContext() context.Context {
	return nil
}

type transportMetricsRecorder struct {
	delivery  map[string]int
	lastStats Stats
}

func (r *transportMetricsRecorder) RecordConductorAuditQueue(stats Stats) {
	r.lastStats = stats
}

func (r *transportMetricsRecorder) RecordConductorAuditDelivery(outcome, reason string) {
	if r.delivery == nil {
		r.delivery = make(map[string]int)
	}
	r.delivery[outcome+":"+reason]++
}
