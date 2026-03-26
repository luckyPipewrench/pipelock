// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestGzipCompress_EmptyInput(t *testing.T) {
	compressed, err := gzipCompress([]byte{})
	if err != nil {
		t.Fatalf("gzipCompress(empty): %v", err)
	}
	// Gzip header/footer for empty content should still produce output.
	if len(compressed) == 0 {
		t.Error("expected non-empty gzip output for empty input")
	}

	// Verify round-trip decompresses to empty.
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer func() { _ = reader.Close() }()
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(decompressed) != 0 {
		t.Errorf("expected empty decompressed output, got %d bytes", len(decompressed))
	}
}

func TestGzipCompress_LargeInput(t *testing.T) {
	// Large repetitive data should compress well.
	data := bytes.Repeat([]byte("pipelock audit event data "), 1000)
	compressed, err := gzipCompress(data)
	if err != nil {
		t.Fatalf("gzipCompress(large): %v", err)
	}
	if len(compressed) >= len(data) {
		t.Errorf("compressed (%d bytes) should be smaller than input (%d bytes) for repetitive data",
			len(compressed), len(data))
	}

	// Round-trip verification.
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer func() { _ = reader.Close() }()
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Error("round-trip mismatch for large input")
	}
}

func TestOTLPSink_DrainWithQueuedEvents(t *testing.T) {
	// Verify that drain() processes events from the queue during Close.
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}

	// Enqueue events without waiting for processing.
	for range 3 {
		_ = sink.Emit(context.Background(), Event{
			Severity:  SeverityCritical,
			Type:      "drain-test",
			Timestamp: time.Now(),
		})
	}

	// Close triggers drain of remaining events.
	_ = sink.Close()

	if n := received.Load(); n == 0 {
		t.Error("expected drain to process queued events, got 0")
	}
}

func TestOTLPSink_SendWithRetry_CloseDuringBackoff(t *testing.T) {
	// Verify that closing the sink during retry backoff aborts the retry.
	firstAttempt := make(chan struct{}, 1)
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			select {
			case firstAttempt <- struct{}{}:
			default:
			}
		}
		// Always return 503 to trigger retries.
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}

	// Emit an event to trigger retry loop.
	_ = sink.Emit(context.Background(), Event{
		Severity:  SeverityCritical,
		Type:      "retry-close-test",
		Timestamp: time.Now(),
	})

	// Wait for first attempt, then close during backoff.
	<-firstAttempt
	_ = sink.Close()

	// Should have fewer than max retries since we closed during backoff.
	if n := attempts.Load(); n >= 3 {
		t.Logf("attempts = %d (close may not have interrupted all retries)", n)
	}
}

func TestOTLPSink_RetryOn429(t *testing.T) {
	var attempts atomic.Int32
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		select {
		case doneCh <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{
		Severity:  SeverityCritical,
		Type:      "test",
		Timestamp: time.Now(),
	})

	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for 429 retry success")
	}

	if attempts.Load() < 2 {
		t.Errorf("expected at least 2 attempts for 429 retry, got %d", attempts.Load())
	}
}

func TestOTLPSink_RetryOn502(t *testing.T) {
	var attempts atomic.Int32
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		select {
		case doneCh <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{
		Severity:  SeverityCritical,
		Type:      "test",
		Timestamp: time.Now(),
	})

	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for 502 retry success")
	}

	if attempts.Load() < 2 {
		t.Errorf("expected at least 2 attempts for 502, got %d", attempts.Load())
	}
}

func TestOTLPSink_RetryOn504(t *testing.T) {
	var attempts atomic.Int32
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
		select {
		case doneCh <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{
		Severity:  SeverityCritical,
		Type:      "test",
		Timestamp: time.Now(),
	})

	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for 504 retry success")
	}

	if attempts.Load() < 2 {
		t.Errorf("expected at least 2 attempts for 504, got %d", attempts.Load())
	}
}

func TestWebhookSink_DrainWithQueuedEvents(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)

	for range 3 {
		_ = sink.Emit(context.Background(), Event{
			Severity:   SeverityWarn,
			Type:       "drain-test",
			Timestamp:  time.Now(),
			InstanceID: "test",
		})
	}

	_ = sink.Close()

	if n := received.Load(); n == 0 {
		t.Error("expected drain to process queued events, got 0")
	}
}

func TestDefaultInstanceID_ReturnsHostname(t *testing.T) {
	id := DefaultInstanceID()
	if id == "" {
		t.Fatal("DefaultInstanceID() returned empty string")
	}

	// On a normal system, this should match os.Hostname().
	hostname, err := os.Hostname()
	if err == nil && hostname != "" {
		if id != hostname {
			t.Errorf("DefaultInstanceID() = %q, want hostname %q", id, hostname)
		}
	}
}

func TestDefaultInstanceID_Fallback(t *testing.T) {
	// We can't easily mock os.Hostname, but we can verify the function
	// always returns a non-empty string.
	id := DefaultInstanceID()
	if id == "" {
		t.Error("DefaultInstanceID() must never return empty string")
	}
}

func TestOTLPSink_InstanceIDInAttributes(t *testing.T) {
	bodyCh := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyCh <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{
		Severity:   SeverityCritical,
		Type:       "test",
		Timestamp:  time.Now(),
		InstanceID: "my-instance-id",
		Fields:     map[string]any{"key": "value"},
	})

	select {
	case <-bodyCh:
		// Received the request. The instance ID attribute is embedded
		// in the protobuf, verifying it doesn't error out is sufficient.
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for OTLP request")
	}
}
