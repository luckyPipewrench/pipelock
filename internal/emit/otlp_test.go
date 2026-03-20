// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestOTLPSink_EmitEvent(t *testing.T) {
	var received atomic.Int32
	var lastBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/logs" {
			t.Errorf("expected path /v1/logs, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("expected protobuf content type, got %s", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		lastBody = body
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "test-instance", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:   SeverityWarn,
		Type:       "blocked",
		Timestamp:  time.Now(),
		InstanceID: "test-instance",
		Fields:     map[string]any{"url": "https://evil.com", "scanner": "dlp"},
	}

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	// Wait for async delivery.
	time.Sleep(200 * time.Millisecond)

	if received.Load() != 1 {
		t.Fatalf("expected 1 request, got %d", received.Load())
	}

	// Verify protobuf body is valid: parse the ExportLogsServiceRequest wrapper.
	// Field 1 = ResourceLogs (bytes).
	_, typ, n := protowire.ConsumeTag(lastBody)
	if typ != protowire.BytesType {
		t.Fatalf("expected bytes type for field 1, got %v", typ)
	}
	rlBytes, _ := protowire.ConsumeBytes(lastBody[n:])

	var rl logspb.ResourceLogs
	if err := proto.Unmarshal(rlBytes, &rl); err != nil {
		t.Fatalf("unmarshal ResourceLogs: %v", err)
	}

	if len(rl.ScopeLogs) == 0 || len(rl.ScopeLogs[0].LogRecords) == 0 {
		t.Fatal("expected at least one log record")
	}

	record := rl.ScopeLogs[0].LogRecords[0]
	if record.SeverityNumber != otlpSeverityWarn {
		t.Errorf("expected severity %d, got %d", otlpSeverityWarn, record.SeverityNumber)
	}
	if record.Body.GetStringValue() != "blocked" {
		t.Errorf("expected body 'blocked', got %q", record.Body.GetStringValue())
	}

	// Verify resource attributes.
	foundService := false
	for _, attr := range rl.Resource.Attributes {
		if attr.Key == "service.name" && attr.Value.GetStringValue() == "pipelock" {
			foundService = true
		}
	}
	if !foundService {
		t.Error("expected service.name=pipelock in resource attributes")
	}
}

func TestOTLPSink_SeverityFilter(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "test", "1.0.0", SeverityWarn, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	// Info event should be filtered.
	_ = sink.Emit(context.Background(), Event{Severity: SeverityInfo, Type: "allowed", Timestamp: time.Now()})
	// Warn event should pass.
	_ = sink.Emit(context.Background(), Event{Severity: SeverityWarn, Type: "blocked", Timestamp: time.Now()})

	time.Sleep(200 * time.Millisecond)

	if received.Load() != 1 {
		t.Errorf("expected 1 request (warn only), got %d", received.Load())
	}
}

func TestOTLPSink_QueueFull(t *testing.T) {
	// Server that blocks briefly — long enough for queue to fill.
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-blocked
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(blocked)

	sink, err := NewOTLPSink(srv.URL, "test", "1.0.0", SeverityInfo, nil, 5*time.Second, 2, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()}

	// Fill queue + one sending.
	var queueFullCount int
	for range 10 {
		if err := sink.Emit(context.Background(), event); err != nil {
			queueFullCount++
		}
	}
	if queueFullCount == 0 {
		t.Error("expected at least one ErrOTLPQueueFull")
	}
}

func TestOTLPSink_RetryOn503(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "test", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	// Wait for retry cycle (1s backoff + delivery).
	time.Sleep(2 * time.Second)

	if attempts.Load() < 2 {
		t.Errorf("expected at least 2 attempts (retry), got %d", attempts.Load())
	}
}

func TestOTLPSink_Gzip(t *testing.T) {
	type gzipResult struct {
		encoding string
		bodyLen  int
	}
	resultCh := make(chan gzipResult, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc := r.Header.Get("Content-Encoding")
		reader, gzErr := gzip.NewReader(r.Body)
		if gzErr != nil {
			resultCh <- gzipResult{encoding: enc}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = reader.Close() }()
		body, _ := io.ReadAll(reader)
		resultCh <- gzipResult{encoding: enc, bodyLen: len(body)}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "test", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, true)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	select {
	case r := <-resultCh:
		if r.encoding != "gzip" {
			t.Errorf("expected Content-Encoding: gzip, got %q", r.encoding)
		}
		if r.bodyLen == 0 {
			t.Error("expected non-empty decompressed body")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for gzip request")
	}
}

func TestOTLPSink_CustomHeaders(t *testing.T) {
	authCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCh <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	headers := map[string]string{"Authorization": "Bearer test-token-123"}
	sink, err := NewOTLPSink(srv.URL, "test", "1.0.0", SeverityInfo, headers, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	select {
	case auth := <-authCh:
		if auth != "Bearer test-token-123" {
			t.Errorf("expected auth header, got %q", auth)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for request")
	}
}

func TestOTLPSink_CloseIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "test", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}

	if err := sink.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestOTLPSink_InvalidEndpoint(t *testing.T) {
	_, err := NewOTLPSink("://bad", "test", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err == nil {
		t.Error("expected error for invalid endpoint")
	}
}

func TestOTLPSink_EmitAfterClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "test", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	_ = sink.Close()

	err = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error when emitting after close")
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input   Severity
		wantNum logspb.SeverityNumber
		wantStr string
	}{
		{SeverityInfo, otlpSeverityInfo, "INFO"},
		{SeverityWarn, otlpSeverityWarn, "WARN"},
		{SeverityCritical, otlpSeverityError, "ERROR"},
	}
	for _, tt := range tests {
		num, str := mapSeverity(tt.input)
		if num != tt.wantNum {
			t.Errorf("mapSeverity(%v) number = %d, want %d", tt.input, num, tt.wantNum)
		}
		if str != tt.wantStr {
			t.Errorf("mapSeverity(%v) text = %q, want %q", tt.input, str, tt.wantStr)
		}
	}
}
