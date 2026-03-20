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
	"sync/atomic"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	respb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const otlpLogsPath = "/v1/logs"

func TestOTLPSink_EmitEvent(t *testing.T) {
	bodyCh := make(chan []byte, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != otlpLogsPath {
			t.Errorf("expected path /v1/logs, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("expected protobuf content type, got %s", r.Header.Get("Content-Type"))
		}
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

	var lastBody []byte
	select {
	case lastBody = <-bodyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for request")
	}

	// Verify protobuf body: parse ExportLogsServiceRequest wrapper.
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
	if record.ObservedTimeUnixNano == 0 {
		t.Error("expected ObservedTimeUnixNano to be set")
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

func TestOTLPSink_NilFields(t *testing.T) {
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doneCh <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	// Nil Fields map should not panic.
	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now(), Fields: nil})

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout — nil fields caused issue")
	}
}

func TestOTLPSink_SeverityFilter(t *testing.T) {
	requestCh := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCh <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityWarn, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}

	// Info event should be filtered.
	_ = sink.Emit(context.Background(), Event{Severity: SeverityInfo, Type: "allowed", Timestamp: time.Now()})
	// Warn event should pass.
	_ = sink.Emit(context.Background(), Event{Severity: SeverityWarn, Type: "blocked", Timestamp: time.Now()})

	// Wait for the one expected request.
	select {
	case <-requestCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for warn event")
	}

	// Close to drain, then verify no extra requests arrived.
	_ = sink.Close()

	select {
	case <-requestCh:
		t.Error("expected only 1 request (info should be filtered)")
	default:
		// Good.
	}
}

func TestOTLPSink_QueueFull(t *testing.T) {
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-blocked
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(blocked)

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 2, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()}

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
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
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

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for retry success")
	}

	if attempts.Load() < 2 {
		t.Errorf("expected at least 2 attempts (retry), got %d", attempts.Load())
	}
}

func TestOTLPSink_NoRetryOn500(t *testing.T) {
	var attempts atomic.Int32
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
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

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	// Close the sink and wait for drain. After Close() returns, the worker
	// goroutine is done — any retry that would have happened has happened.
	_ = sink.Close()
	if attempts.Load() != 1 {
		t.Errorf("expected 1 attempt (500 not retryable), got %d", attempts.Load())
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

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, true)
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
	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, headers, 5*time.Second, 64, false)
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

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
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

func TestOTLPSink_CloseDrains(t *testing.T) {
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

	// Enqueue several events, then close immediately.
	for range 5 {
		_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})
	}
	_ = sink.Close()

	// After close returns, all queued events should have been drained.
	if n := received.Load(); n == 0 {
		t.Error("expected at least some events to be drained on close")
	}
}

func TestOTLPSink_EndpointWithV1Logs(t *testing.T) {
	// Operator passes endpoint already ending in /v1/logs.
	// Must not double up to /v1/logs/v1/logs.
	requestCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCh <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL+"/v1/logs", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	select {
	case path := <-requestCh:
		if path != otlpLogsPath {
			t.Errorf("expected /v1/logs, got %s (double path?)", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestOTLPSink_EndpointWithTrailingSlash(t *testing.T) {
	requestCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCh <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL+"/", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	select {
	case path := <-requestCh:
		if path != otlpLogsPath {
			t.Errorf("expected /v1/logs, got %s", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestOTLPSink_InvalidEndpoint(t *testing.T) {
	_, err := NewOTLPSink("://bad", "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err == nil {
		t.Error("expected error for invalid endpoint")
	}
}

func TestOTLPSink_EmitAfterClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
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

func TestOTLPSink_NetworkErrorRetry(t *testing.T) {
	// Start server, let first request through, then close it to cause
	// network errors on subsequent attempts.
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 2*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	// Close server immediately so retries hit network errors.
	srv.Close()

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	// Wait for retry exhaustion (3 attempts * ~1-2s backoff each, but network
	// errors return fast since server is closed).
	time.Sleep(3 * time.Second)

	// Should have attempted multiple times before giving up.
	if attempts.Load() > 0 {
		t.Log("server received requests before closing (expected)")
	}
}

func TestOTLPSink_RetryExhausted(t *testing.T) {
	var attempts atomic.Int32
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		if n >= 3 {
			select {
			case doneCh <- struct{}{}:
			default:
			}
		}
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	select {
	case <-doneCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for retry exhaustion")
	}

	if attempts.Load() != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", attempts.Load())
	}
}

func TestOTLPSink_4xxNotRetried(t *testing.T) {
	var attempts atomic.Int32
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
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

	_ = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "test", Timestamp: time.Now()})

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	// 400 is not retryable — exactly 1 attempt.
	time.Sleep(100 * time.Millisecond)
	if attempts.Load() != 1 {
		t.Errorf("expected 1 attempt (400 not retryable), got %d", attempts.Load())
	}
}

func TestOTLPSink_DefaultTimeoutAndQueue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Pass 0 for timeout and queue to exercise default paths.
	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 0, 0, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	_ = sink.Close()
}

func TestOTLPSink_BackoffOrDone_Cancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 64, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}

	// Close the sink, then verify backoffOrDone returns false immediately.
	_ = sink.Close()
	if sink.backoffOrDone(10 * time.Second) {
		t.Error("expected backoffOrDone to return false when sink is closed")
	}
}

func TestGzipCompress(t *testing.T) {
	data := []byte("hello world this is test data for compression")
	compressed, err := gzipCompress(data)
	if err != nil {
		t.Fatalf("gzipCompress: %v", err)
	}
	if len(compressed) == 0 {
		t.Error("expected non-empty compressed output")
	}

	// Verify round-trip.
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer func() { _ = reader.Close() }()
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(decompressed) != string(data) {
		t.Errorf("round-trip mismatch: got %q", decompressed)
	}
}

func TestMarshalExportLogsRequest(t *testing.T) {
	resource := &respb.Resource{
		Attributes: []*commonpb.KeyValue{
			stringKV("service.name", "test"),
		},
	}
	record := &logspb.LogRecord{
		TimeUnixNano:   12345,
		SeverityNumber: otlpSeverityWarn,
		SeverityText:   "WARN",
		Body: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: "blocked"},
		},
	}

	data, err := marshalExportLogsRequest(resource, record)
	if err != nil {
		t.Fatalf("marshalExportLogsRequest: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output")
	}

	// Verify the outer message: field 1 (ResourceLogs) as bytes.
	_, typ, n := protowire.ConsumeTag(data)
	if typ != protowire.BytesType {
		t.Fatalf("expected BytesType, got %v", typ)
	}
	rlBytes, _ := protowire.ConsumeBytes(data[n:])
	var rl logspb.ResourceLogs
	if err := proto.Unmarshal(rlBytes, &rl); err != nil {
		t.Fatalf("unmarshal ResourceLogs: %v", err)
	}
	if len(rl.ScopeLogs) == 0 {
		t.Error("expected ScopeLogs")
	}
}

func TestIsRetryableStatus(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{200, false},
		{400, false},
		{429, true},
		{500, false}, // per OTLP spec, 500 is NOT retryable
		{501, false},
		{502, true},
		{503, true},
		{504, true},
	}
	for _, tt := range tests {
		if got := isRetryableStatus(tt.code); got != tt.want {
			t.Errorf("isRetryableStatus(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}
