// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	respb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

var errOTLPAccountingTest = errors.New("otlp accounting test failure")

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type panicStringError struct{}

func (panicStringError) Error() string {
	panic("diagnostic error string panic")
}

func newManualOTLPSink() *OTLPSink {
	return &OTLPSink{
		endpoint: "http://collector.example/v1/logs",
		client:   &http.Client{Timeout: time.Second},
		resource: &respb.Resource{},
		queue:    make(chan Event, 2),
		done:     make(chan struct{}),
	}
}

func waitOTLPStats(t *testing.T, sink *OTLPSink, match func(OTLPStats) bool, desc string) OTLPStats {
	t.Helper()
	var stats OTLPStats
	testwait.For(t, 5*time.Second, func() bool {
		stats = sink.Stats()
		return match(stats)
	}, "%s", desc)
	return stats
}

func withFastOTLPRetry(t *testing.T) {
	t.Helper()
	oldRetryBase := otlpRetryBase
	otlpRetryBase = time.Millisecond
	t.Cleanup(func() { otlpRetryBase = oldRetryBase })
}

func TestOTLPSink_StatsSnapshotDelivered(t *testing.T) {
	requestCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCh <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 4, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if err := sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "stats-delivered", Timestamp: time.Now()}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-requestCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for OTLP request")
	}

	stats := waitOTLPStats(t, sink, func(stats OTLPStats) bool {
		return stats.Delivered == 1
	}, "OTLP delivered counter")
	if stats.Failed != 0 || stats.Dropped != 0 || stats.Abandoned != 0 || stats.Degraded || stats.LastError != "" {
		t.Fatalf("stats = %+v, want only delivered counter", stats)
	}
	if stats.QueueCap != 4 {
		t.Fatalf("QueueCap = %d, want 4", stats.QueueCap)
	}
}

func TestOTLPSink_AccountingSnapshotEdgeCases(t *testing.T) {
	var nilSink *OTLPSink
	if stats := nilSink.Stats(); stats != (OTLPStats{}) {
		t.Fatalf("nil Stats = %+v, want empty snapshot", stats)
	}
	if err := nilSink.Emit(context.Background(), Event{Severity: SeverityCritical}); err == nil {
		t.Fatal("nil Emit error = nil, want uninitialized sink error")
	}

	sink := newManualOTLPSink()
	sink.recordDropped("drop_error", errOTLPAccountingTest)
	stats := sink.Stats()
	if stats.Dropped != 1 || stats.LastError != errOTLPAccountingTest.Error() {
		t.Fatalf("stats = %+v, want dropped error recorded", stats)
	}

	sink.recordAbandoned("zero_count", Event{Type: "zero-count"}, 0)
	stats = sink.Stats()
	if stats.Abandoned != 1 || stats.LastError != "zero_count" {
		t.Fatalf("stats = %+v, want zero count normalized to one abandoned event", stats)
	}
}

func TestOTLPSink_RecordsBuildFailures(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testing.T, *OTLPSink)
		wantLast  string
	}{
		{
			name: "marshal",
			configure: func(t *testing.T, _ *OTLPSink) {
				t.Helper()
				oldMarshal := otlpMarshalExportLogsRequest
				otlpMarshalExportLogsRequest = func(*respb.Resource, *logspb.LogRecord) ([]byte, error) {
					return nil, errOTLPAccountingTest
				}
				t.Cleanup(func() { otlpMarshalExportLogsRequest = oldMarshal })
			},
			wantLast: errOTLPAccountingTest.Error(),
		},
		{
			name: "gzip",
			configure: func(t *testing.T, sink *OTLPSink) {
				t.Helper()
				sink.useGzip = true
				oldGzip := otlpGzipCompress
				otlpGzipCompress = func([]byte) ([]byte, error) {
					return nil, errOTLPAccountingTest
				}
				t.Cleanup(func() { otlpGzipCompress = oldGzip })
			},
			wantLast: errOTLPAccountingTest.Error(),
		},
		{
			name: "request",
			configure: func(t *testing.T, sink *OTLPSink) {
				t.Helper()
				sink.endpoint = "\n"
			},
			wantLast: "net/url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := newManualOTLPSink()
			tt.configure(t, sink)
			sink.send(Event{Severity: SeverityCritical, Type: "build-" + tt.name, Timestamp: time.Now()})

			stats := sink.Stats()
			if stats.Failed != 1 || stats.Delivered != 0 || !stats.Degraded || stats.LastError == "" {
				t.Fatalf("stats = %+v, want one degraded failure", stats)
			}
			if !strings.Contains(stats.LastError, tt.wantLast) {
				t.Fatalf("LastError = %q, want substring %q", stats.LastError, tt.wantLast)
			}
		})
	}
}

func TestOTLPSink_RetryOutcomesAccounting(t *testing.T) {
	withFastOTLPRetry(t)

	tests := []struct {
		name          string
		handler       http.HandlerFunc
		configure     func(*OTLPSink, *atomic.Int32)
		waitAttempts  int32
		wantAttempts  int32
		wantDelivered uint64
		wantFailed    uint64
	}{
		{
			name: "retry_then_success_counts_one_delivery",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			waitAttempts:  2,
			wantAttempts:  2,
			wantDelivered: 1,
		},
		{
			name: "retryable_status_exhausted_counts_failure",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			waitAttempts: 3,
			wantAttempts: 3,
			wantFailed:   1,
		},
		{
			name: "non_retryable_status_counts_failure",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			waitAttempts: 1,
			wantAttempts: 1,
			wantFailed:   1,
		},
		{
			name: "send_error_exhausted_counts_failure",
			configure: func(sink *OTLPSink, attempts *atomic.Int32) {
				sink.client = &http.Client{
					Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
						attempts.Add(1)
						return nil, errOTLPAccountingTest
					}),
				}
			},
			waitAttempts: 3,
			wantAttempts: 3,
			wantFailed:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			var sink *OTLPSink
			var srv *httptest.Server
			if tt.configure == nil {
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := attempts.Add(1)
					if tt.name == "retry_then_success_counts_one_delivery" && n == 2 {
						w.WriteHeader(http.StatusOK)
						return
					}
					tt.handler(w, r)
				}))
				defer srv.Close()
				var err error
				sink, err = NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 8, false)
				if err != nil {
					t.Fatalf("NewOTLPSink: %v", err)
				}
				defer func() { _ = sink.Close() }()
				if err := sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: tt.name, Timestamp: time.Now()}); err != nil {
					t.Fatalf("Emit: %v", err)
				}
				testwait.For(t, 5*time.Second, func() bool {
					return attempts.Load() >= tt.waitAttempts
				}, "OTLP retry attempts")
			} else {
				sink = newManualOTLPSink()
				tt.configure(sink, &attempts)
				sink.send(Event{Severity: SeverityCritical, Type: tt.name, Timestamp: time.Now()})
			}

			stats := waitOTLPStats(t, sink, func(stats OTLPStats) bool {
				return stats.Delivered == tt.wantDelivered && stats.Failed == tt.wantFailed
			}, "OTLP retry outcome counters")
			if got := attempts.Load(); got != tt.wantAttempts {
				t.Fatalf("attempts = %d, want %d", got, tt.wantAttempts)
			}
			if stats.Dropped != 0 || stats.Abandoned != 0 {
				t.Fatalf("stats = %+v, want no dropped/abandoned retry outcome", stats)
			}
			if tt.wantFailed > 0 && (!stats.Degraded || stats.LastError == "") {
				t.Fatalf("stats = %+v, want degraded failure with last error", stats)
			}
			if tt.wantDelivered > 0 && stats.Degraded {
				t.Fatalf("stats = %+v, want successful retry to clear degraded state", stats)
			}
		})
	}
}

func TestOTLPSink_DegradedAdvisoryAndRecovery(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 4, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if err := sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "first-fails", Timestamp: time.Now()}); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	degradedStats := waitOTLPStats(t, sink, func(stats OTLPStats) bool {
		return stats.Failed == 1 && stats.Degraded
	}, "OTLP degraded after async failure")
	if degradedStats.LastError == "" {
		t.Fatalf("LastError empty while degraded, stats = %+v", degradedStats)
	}

	err = sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "second-recovers", Timestamp: time.Now()})
	if !errors.Is(err, ErrOTLPDegraded) {
		t.Fatalf("second Emit error = %v, want ErrOTLPDegraded", err)
	}
	stats := waitOTLPStats(t, sink, func(stats OTLPStats) bool {
		return stats.Delivered == 1 && stats.Failed == 1 && !stats.Degraded
	}, "OTLP successful send clears degraded state")
	if stats.Dropped != 0 || stats.Abandoned != 0 {
		t.Fatalf("stats = %+v, want no dropped/abandoned events", stats)
	}
	if stats.LastError != "" {
		t.Fatalf("LastError = %q after recovery, want cleared", stats.LastError)
	}
}

func TestOTLPSink_QueueFullDropAccountingAndPrecedence(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 1, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}

	event := Event{Severity: SeverityCritical, Type: "queue-full", Timestamp: time.Now()}
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for worker to block in OTLP handler")
	}
	sink.degraded.Store(true)
	if err := sink.Emit(context.Background(), event); !errors.Is(err, ErrOTLPDegraded) {
		t.Fatalf("second Emit error = %v, want ErrOTLPDegraded accepted event", err)
	}
	if err := sink.Emit(context.Background(), event); !errors.Is(err, ErrOTLPQueueFull) {
		t.Fatalf("third Emit error = %v, want ErrOTLPQueueFull precedence", err)
	}

	stats := sink.Stats()
	if stats.Dropped != 1 || !stats.Degraded || stats.LastError != "queue_full" {
		t.Fatalf("stats = %+v, want one queue_full drop and degraded state", stats)
	}
	close(release)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestOTLPSink_PanicDropsOnlyCurrentEvent(t *testing.T) {
	oldMarshal := otlpMarshalExportLogsRequest
	var marshalCalls atomic.Int32
	otlpMarshalExportLogsRequest = func(resource *respb.Resource, record *logspb.LogRecord) ([]byte, error) {
		if marshalCalls.Add(1) == 1 {
			panic("otlp marshal panic")
		}
		return oldMarshal(resource, record)
	}
	t.Cleanup(func() { otlpMarshalExportLogsRequest = oldMarshal })

	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 4, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if err := sink.Emit(context.Background(), Event{
		Severity:  SeverityCritical,
		Type:      "panic-event",
		Timestamp: time.Now(),
	}); err != nil {
		t.Fatalf("panic Emit: %v", err)
	}
	// ErrOTLPDegraded means the event WAS accepted for delivery (the prior panic
	// set the degraded advisory); it is not a failure to emit. Accepting it makes
	// this deterministic instead of racing the panic event's async failure.
	if err := sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "after-panic", Timestamp: time.Now()}); err != nil && !errors.Is(err, ErrOTLPDegraded) {
		t.Fatalf("post-panic Emit: %v", err)
	}

	stats := waitOTLPStats(t, sink, func(stats OTLPStats) bool {
		return stats.Failed == 1 && stats.Delivered == 1
	}, "OTLP panic recovery counters")
	if stats.Dropped != 0 || stats.Abandoned != 0 || stats.Degraded {
		t.Fatalf("stats = %+v, want panic failure and later success-cleared degraded state", stats)
	}
	if got := received.Load(); got != 1 {
		t.Fatalf("received = %d, want only non-panicking event delivered", got)
	}
	if got := marshalCalls.Load(); got != 2 {
		t.Fatalf("marshal calls = %d, want 2", got)
	}
}

func TestOTLPSink_DrainTimeoutAbandonsQueuedEvents(t *testing.T) {
	oldTimeout := otlpDrainTimeout
	otlpDrainTimeout = -time.Nanosecond
	t.Cleanup(func() { otlpDrainTimeout = oldTimeout })

	sink := newManualOTLPSink()
	sink.queue <- Event{Severity: SeverityCritical, Type: "abandon-1", Timestamp: time.Now()}
	sink.queue <- Event{Severity: SeverityCritical, Type: "abandon-2", Timestamp: time.Now()}

	start := time.Now()
	sink.drain()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("drain took %s, want bounded wait", elapsed)
	}

	stats := sink.Stats()
	if stats.Abandoned != 2 || !stats.Degraded || stats.LastError != "drain_timeout" {
		t.Fatalf("stats = %+v, want two abandoned queued events", stats)
	}
}

func TestOTLPSink_CloseDuringRetryAbandonsEvent(t *testing.T) {
	oldRetryBase := otlpRetryBase
	otlpRetryBase = time.Hour
	t.Cleanup(func() { otlpRetryBase = oldRetryBase })

	firstAttempt := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case firstAttempt <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 4, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	if err := sink.Emit(context.Background(), Event{Severity: SeverityCritical, Type: "close-during-retry", Timestamp: time.Now()}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-firstAttempt:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first OTLP retry attempt")
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	stats := sink.Stats()
	if stats.Abandoned != 1 || stats.Failed != 0 || stats.Delivered != 0 || !stats.Degraded || stats.LastError != "close_during_retry" {
		t.Fatalf("stats = %+v, want abandoned close_during_retry event", stats)
	}
}

func TestOTLPSink_EmitDuringCloseRejectedAfterCloseGate(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 4, false)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}

	event := Event{Severity: SeverityCritical, Type: "emit-during-close", Timestamp: time.Now()}
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("initial Emit: %v", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for worker to enter OTLP handler")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- sink.Close()
	}()
	testwait.For(t, 5*time.Second, func() bool {
		sink.closeMu.Lock()
		defer sink.closeMu.Unlock()
		return sink.closed
	}, "OTLP close gate to be set")

	err = sink.Emit(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), errOTLPClosed) {
		t.Fatalf("Emit during Close after close gate = %v, want closed error", err)
	}

	close(release)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Close")
	}
}

func TestOTLPSink_LogDiagnosticStructuredJSON(t *testing.T) {
	readStderr, writeStderr, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = writeStderr
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = readStderr.Close()
	})

	sink := newManualOTLPSink()
	readDone := make(chan []byte, 1)
	go func() {
		data, _ := bufio.NewReader(readStderr).ReadBytes('\n')
		readDone <- data
	}()

	// recordFailure runs on the background goroutine (not the Emit hot path), so
	// it is the diagnostic that still writes structured JSON to stderr. The
	// queue-full drop path deliberately no longer logs synchronously.
	sink.recordFailure("send_error", Event{Type: "diagnostic-event"}, errOTLPAccountingTest)

	var data []byte
	select {
	case data = <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for OTLP diagnostic")
	}
	line := bytes.TrimSpace(data)
	var fields map[string]any
	if err := json.Unmarshal(line, &fields); err != nil {
		t.Fatalf("diagnostic is not JSON: %v\n%s", err, line)
	}
	if fields["component"] != "emit.otlp" || fields["event"] != "delivery_failed" || fields["reason"] != "send_error" {
		t.Fatalf("diagnostic fields = %v", fields)
	}
	if fmt.Sprint(fields["failed"]) != "1" {
		t.Fatalf("diagnostic failed = %v, want 1", fields["failed"])
	}
}

// TestOTLPSink_QueueFullDropDoesNotWriteStderr proves the Emit hot-path drop
// accounting is non-blocking: it updates counters but must not perform a
// synchronous stderr write, which could block the request path when the sink is
// under backpressure and stderr is stalled.
func TestOTLPSink_QueueFullDropDoesNotWriteStderr(t *testing.T) {
	readStderr, writeStderr, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = writeStderr
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = readStderr.Close()
	})

	sink := newManualOTLPSink()
	sink.recordDropped("queue_full", nil)

	// Close the write end so a read returns promptly at EOF instead of blocking.
	os.Stderr = oldStderr
	_ = writeStderr.Close()
	data, _ := io.ReadAll(readStderr)
	if len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("queue-full drop wrote to stderr on the hot path: %q", data)
	}

	stats := sink.Stats()
	if stats.Dropped != 1 || !stats.Degraded || stats.LastError != "queue_full" {
		t.Fatalf("stats = %+v, want dropped=1 degraded LastError=queue_full", stats)
	}
}

func TestOTLPSink_LogDiagnosticMarshalErrorDoesNotPanic(t *testing.T) {
	oldMarshalDiagnostic := otlpMarshalDiagnostic
	otlpMarshalDiagnostic = func(any) ([]byte, error) {
		return nil, errOTLPAccountingTest
	}
	t.Cleanup(func() { otlpMarshalDiagnostic = oldMarshalDiagnostic })

	sink := newManualOTLPSink()
	sink.recordFailure("panic_error_string", Event{Type: "diagnostic-marshal-error"}, panicStringError{})

	stats := sink.Stats()
	if stats.Failed != 1 || !stats.Degraded {
		t.Fatalf("stats = %+v, want degraded failure despite diagnostic marshal error", stats)
	}
	if !strings.Contains(stats.LastError, "diagnostic error string panic") {
		t.Fatalf("LastError = %q, want recovered error string panic", stats.LastError)
	}
}

func TestOTLPSink_SuccessDoesNotEraseConcurrentDropDegraded(t *testing.T) {
	// Mirrors WebhookSink protection: a successful send must not clear the
	// degraded flag when a failure, drop, or abandonment is recorded while that
	// send is in flight. Covers all three counter classes the snapshot guard
	// compares (failed, dropped, abandoned).
	cases := []struct {
		name    string
		inject  func(s *OTLPSink)
		wantErr string
		count   func(st OTLPStats) uint64
	}{
		{"drop", func(s *OTLPSink) { s.recordDropped("queue_full", nil) }, "queue_full", func(st OTLPStats) uint64 { return st.Dropped }},
		{"failure", func(s *OTLPSink) { s.recordFailure("send_error", Event{}, errors.New("send failed")) }, "", func(st OTLPStats) uint64 { return st.Failed }},
		{"abandon", func(s *OTLPSink) { s.recordAbandoned("drain_timeout", Event{}, 1) }, "drain_timeout", func(st OTLPStats) uint64 { return st.Abandoned }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sink *OTLPSink
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.inject(sink)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			var err error
			sink, err = NewOTLPSink(srv.URL, "1.0.0", SeverityInfo, nil, 5*time.Second, 4, false)
			if err != nil {
				t.Fatalf("NewOTLPSink: %v", err)
			}
			defer func() { _ = sink.Close() }()

			sink.send(Event{Type: "blocked", Timestamp: time.Now()})

			st := sink.Stats()
			if st.Delivered != 1 {
				t.Fatalf("delivered = %d, want 1", st.Delivered)
			}
			if got := tc.count(st); got != 1 {
				t.Fatalf("%s counter = %d, want 1", tc.name, got)
			}
			if !st.Degraded {
				t.Fatalf("degraded was erased despite a concurrent %s during the send", tc.name)
			}
			// recordFailure derives LastError from the error (not the reason),
			// so the failure case only asserts a non-empty preserved error;
			// drop/abandon assert the exact reason.
			if tc.wantErr != "" && st.LastError != tc.wantErr {
				t.Fatalf("LastError = %q, want %q preserved", st.LastError, tc.wantErr)
			}
			if st.LastError == "" {
				t.Fatalf("LastError was cleared; want the concurrent %s error preserved", tc.name)
			}
		})
	}
}
