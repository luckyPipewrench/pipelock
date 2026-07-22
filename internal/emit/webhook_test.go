// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testSeverityWarn = "warn"
	testEventBlocked = "blocked"
)

func TestWebhookSink_BelowMinSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected request: event below minSev should be dropped")
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL, WithMinSeverity(SeverityWarn))
	defer func() { _ = sink.Close() }()

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityInfo,
		Type:       verdictAllowed,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	})
	if err != nil {
		t.Fatalf("expected nil error for dropped event, got %v", err)
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestWebhookSink_SuccessfulPost(t *testing.T) {
	var received webhookPayload
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		defer close(done)

		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)
	defer func() { _ = sink.Close() }()

	ts := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  ts,
		InstanceID: testHostName,
		Fields:     map[string]any{testFieldURL: testEvilURL, testFieldReason: testBlocklistRsn},
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for webhook POST")
	}

	if received.Severity != testSeverityWarn {
		t.Errorf("payload severity = %q, want %q", received.Severity, testSeverityWarn)
	}

	if received.Type != testEventBlocked {
		t.Errorf("payload type = %q, want %q", received.Type, testEventBlocked)
	}
	if received.Instance != testHostName {
		t.Errorf("payload instance = %q, want %q", received.Instance, testHostName)
	}

	// Verify timestamp is in RFC3339Nano format.
	_, parseErr := time.Parse(time.RFC3339Nano, received.Timestamp)
	if parseErr != nil {
		t.Errorf("timestamp %q is not RFC3339Nano: %v", received.Timestamp, parseErr)
	}

	if received.Fields[testFieldURL] != testEvilURL {
		t.Errorf("fields[url] = %v, want %q", received.Fields[testFieldURL], testEvilURL)
	}
}

func TestWebhookSink_BearerToken(t *testing.T) {
	var gotAuth string
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		close(done)
	}))
	defer srv.Close()

	token := testStr + "-secret-token"
	sink := NewWebhookSink(srv.URL, WithBearerToken(token))
	defer func() { _ = sink.Close() }()

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for webhook POST")
	}

	want := "Bearer " + token
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestWebhookSink_NoAuthHeaderWithoutToken(t *testing.T) {
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("unexpected Authorization header: %q", auth)
		}
		close(done)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)
	defer func() { _ = sink.Close() }()

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for webhook POST")
	}
}

func TestWebhookSink_QueueFull(t *testing.T) {
	// Server blocks long enough for the queue to fill.
	blocker := make(chan struct{})
	started := make(chan struct{})
	var startedOnce sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-blocker
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL,
		WithQueueSize(2),
		WithWebhookTimeout(30*time.Second),
	)

	event := Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	}

	// Fill the queue. One item may be pulled by the goroutine, so send extra.
	readStderr, writeStderr, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = writeStderr
	var queueFullSeen bool
	for i := 0; i < 20; i++ {
		if err := sink.Emit(context.Background(), event); errors.Is(err, ErrQueueFull) {
			queueFullSeen = true
			break
		}
		select {
		case <-started:
		default:
		}
	}
	os.Stderr = oldStderr
	_ = writeStderr.Close()
	data, _ := io.ReadAll(readStderr)
	_ = readStderr.Close()
	stats := sink.Stats()

	// Unblock the server before assertions so a regression cannot strand the
	// handler and hang httptest.Server.Close during test cleanup.
	close(blocker)
	_ = sink.Close()

	if !queueFullSeen {
		t.Error("expected ErrQueueFull after filling queue")
	}
	if len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("queue-full drop wrote to stderr on the Emit hot path: %q", data)
	}
	if stats.Dropped != 1 || !stats.Degraded || stats.LastError != "queue_full" {
		t.Fatalf("stats = %+v, want queue_full drop", stats)
	}
	if stats.QueueCap != 2 {
		t.Fatalf("QueueCap = %d, want 2", stats.QueueCap)
	}
}

func TestWebhookSink_CloseDrainsPending(t *testing.T) {
	var count atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		count.Add(1)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL, WithQueueSize(128))

	// Enqueue several events.
	for i := 0; i < 5; i++ {
		err := sink.Emit(context.Background(), Event{
			Severity:   SeverityWarn,
			Type:       testEventBlocked,
			Timestamp:  time.Now(),
			InstanceID: testStr,
		})
		if err != nil {
			t.Fatalf("Emit %d returned error: %v", i, err)
		}
	}

	// Close should drain all pending.
	_ = sink.Close()

	got := count.Load()
	if got != 5 {
		t.Errorf("expected 5 events delivered, got %d", got)
	}
	if stats := sink.Stats(); stats.Delivered != 5 || stats.Failed != 0 || stats.Degraded {
		t.Fatalf("stats = %+v, want 5 delivered and healthy", stats)
	}
}

func TestWebhookSink_ServerErrorDoesNotBlock(t *testing.T) {
	var count atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)

	for i := 0; i < 3; i++ {
		err := sink.Emit(context.Background(), Event{
			Severity:   SeverityWarn,
			Type:       testEventBlocked,
			Timestamp:  time.Now(),
			InstanceID: testStr,
		})
		if err != nil {
			t.Fatalf("Emit %d returned error: %v", i, err)
		}
	}

	_ = sink.Close()

	// All 3 events should have been attempted despite 500 errors.
	got := count.Load()
	if got != 3 {
		t.Errorf("expected 3 requests attempted, got %d", got)
	}
	stats := sink.Stats()
	if stats.Failed != 3 || !stats.Degraded || stats.LastError != "HTTP 500" {
		t.Fatalf("stats = %+v, want 3 failed HTTP status deliveries", stats)
	}
}

func TestWebhookSink_ConcurrentEmit(t *testing.T) {
	var count atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		count.Add(1)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL, WithQueueSize(256))

	const goroutines = 10
	const eventsPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				_ = sink.Emit(context.Background(), Event{
					Severity:   SeverityWarn,
					Type:       testEventBlocked,
					Timestamp:  time.Now(),
					InstanceID: testStr,
				})
			}
		}()
	}

	wg.Wait()
	_ = sink.Close()

	got := count.Load()
	if got != goroutines*eventsPerGoroutine {
		t.Errorf("expected %d events delivered, got %d", goroutines*eventsPerGoroutine, got)
	}
}

func TestWebhookSink_CustomQueueSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL, WithQueueSize(128))
	defer func() { _ = sink.Close() }()

	if cap(sink.queue) != 128 {
		t.Errorf("queue capacity = %d, want 128", cap(sink.queue))
	}
}

func TestWebhookSink_DefaultQueueSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)
	defer func() { _ = sink.Close() }()

	if cap(sink.queue) != DefaultQueueSize {
		t.Errorf("queue capacity = %d, want %d", cap(sink.queue), DefaultQueueSize)
	}
}

func TestWebhookSink_DoubleClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)

	// First close should succeed.
	if err := sink.Close(); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}

	// Second close should NOT panic (sync.Once protects the done channel).
	if err := sink.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

func TestWebhookSink_NilFieldsInPayload(t *testing.T) {
	var received webhookPayload
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		defer close(done)
		_ = json.NewDecoder(r.Body).Decode(&received)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)
	defer func() { _ = sink.Close() }()

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
		Fields:     nil,
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for webhook POST")
	}

	// nil map should serialize as JSON null, not cause an error.
	if received.Type != testEventBlocked {
		t.Errorf("payload type = %q, want %q", received.Type, testEventBlocked)
	}
}

func TestWebhookSink_EmitAfterClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)
	_ = sink.Close()

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	})
	if err == nil {
		t.Error("expected error when emitting to closed sink")
	}
}

func TestWebhookSink_SendMarshalError(t *testing.T) {
	// Events with unmarshalable fields (channels) should be silently dropped,
	// not panic or block the goroutine.
	var count atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		count.Add(1)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)
	defer func() { _ = sink.Close() }()

	// Emit event with unmarshalable field - json.Marshal will fail.
	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
		Fields:     map[string]any{"bad": make(chan int)},
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}
	// Wait for the async marshal failure to be accounted so the follow-up
	// Emit deterministically observes the degraded state.
	waitWebhookStats(t, sink, func(stats WebhookStats) bool {
		return stats.Failed == 1 && stats.Degraded
	})

	// Follow up with a valid event to prove the goroutine survived. The
	// degraded advisory is expected; the event is still enqueued.
	err = sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	})
	if !errors.Is(err, ErrWebhookDegraded) {
		t.Fatalf("Emit after failure = %v, want ErrWebhookDegraded", err)
	}

	_ = sink.Close()

	if got := count.Load(); got != 1 {
		t.Errorf("expected 1 successful request (bad event skipped), got %d", got)
	}
	stats := sink.Stats()
	if stats.Delivered != 1 || stats.Failed != 1 || stats.Degraded || stats.LastError != "" {
		t.Fatalf("stats = %+v, want one marshal failure and recovered delivery", stats)
	}
}

func TestWebhookSink_SendInvalidURL(t *testing.T) {
	// A sink with an invalid URL should log errors, not panic or block.
	sink := NewWebhookSink("://invalid-url")
	defer func() { _ = sink.Close() }()

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	// Close should not hang even with errors.
	_ = sink.Close()
	stats := sink.Stats()
	if stats.Failed != 1 || !stats.Degraded || stats.LastError == "" {
		t.Fatalf("stats = %+v, want request-build failure accounting", stats)
	}
}

func TestWebhookSink_SendConnectionRefused(t *testing.T) {
	// Start a server and immediately close it - the URL will refuse connections.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()

	sink := NewWebhookSink(url, WithWebhookTimeout(100*time.Millisecond))

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	// Close should drain without hanging despite connection errors.
	_ = sink.Close()
	stats := sink.Stats()
	if stats.Failed != 1 || !stats.Degraded || stats.LastError == "" {
		t.Fatalf("stats = %+v, want send failure accounting", stats)
	}
}

func TestWebhookSink_EmitClosedDuringQueueWait(t *testing.T) {
	// Create a sink with a tiny queue so the second select path is exercised.
	blocker := make(chan struct{})
	started := make(chan struct{})
	var startedOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-blocker
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL, WithQueueSize(1))

	event := Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	}

	// Fill the queue: first event goes to goroutine (blocked on HTTP), second fills channel.
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first webhook request")
	}
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("second Emit: %v", err)
	}

	// Close while queue is full - exercises the <-w.done path in the second select.
	close(blocker)
	_ = sink.Close()

	// Emit after close should return error
	err := sink.Emit(context.Background(), event)
	if err == nil {
		t.Error("expected error when emitting to closed sink")
	}
}

func TestWebhookSink_EmitSignalsPriorDegradedStateThenRecovers(t *testing.T) {
	requests := make(chan int, 2)
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(count.Add(1))
		requests <- n
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL, WithQueueSize(2))
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	}
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	waitWebhookStats(t, sink, func(stats WebhookStats) bool {
		return stats.Failed == 1 && stats.Degraded
	})

	if err := sink.Emit(context.Background(), event); !errors.Is(err, ErrWebhookDegraded) {
		t.Fatalf("second Emit error = %v, want ErrWebhookDegraded", err)
	}
	waitWebhookStats(t, sink, func(stats WebhookStats) bool {
		return stats.Delivered == 1 && stats.Failed == 1 && !stats.Degraded
	})
	if stats := sink.Stats(); stats.LastError != "" {
		t.Fatalf("LastError = %q after recovery, want cleared", stats.LastError)
	}

	for i := 1; i <= 2; i++ {
		select {
		case got := <-requests:
			if got != i {
				t.Fatalf("request order = %d, want %d", got, i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for request %d", i)
		}
	}
}

func TestWebhookSink_StatsNilAndAbandoned(t *testing.T) {
	var nilSink *WebhookSink
	if got := nilSink.Stats(); got != (WebhookStats{}) {
		t.Fatalf("nil Stats() = %+v, want zero value", got)
	}

	sink := &WebhookSink{queue: make(chan Event, 2)}
	sink.recordAbandoned("drain_timeout", 2)
	stats := sink.Stats()
	if stats.Abandoned != 2 || !stats.Degraded || stats.LastError != "drain_timeout" || stats.QueueCap != 2 {
		t.Fatalf("stats = %+v, want abandoned degraded snapshot", stats)
	}
}

func TestWebhookSink_SafeSendAccountsPanic(t *testing.T) {
	sink := &WebhookSink{
		url:   "https://api.vendor.example/hook",
		queue: make(chan Event, 1),
	}
	sink.safeSend(Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
	})
	stats := sink.Stats()
	if stats.Failed != 1 || !stats.Degraded || stats.LastError == "" {
		t.Fatalf("stats = %+v, want panic failure accounting", stats)
	}
}

func waitWebhookStats(t *testing.T, sink *WebhookSink, accept func(WebhookStats) bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		stats := sink.Stats()
		if accept(stats) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for webhook stats, last stats = %+v", stats)
		case <-ticker.C:
		}
	}
}

func TestWebhookSink_ConcurrentEmitCloseAccountsEveryAcceptedEvent(t *testing.T) {
	// Accounting invariant under concurrent Emit/Close: an event accepted by
	// Emit (nil or ErrWebhookDegraded) must never be silently lost. After
	// Close returns, every accepted event is delivered, failed, or abandoned.
	// The closeMu admission guard (mirroring the syslog sink) is what makes
	// this hold; the historical lost-event interleaving is too narrow to
	// reproduce deterministically, so this asserts the invariant, not the
	// specific race.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	const emitters = 8
	const perEmitter = 50

	sink := NewWebhookSink(srv.URL, WithQueueSize(emitters*perEmitter))

	var accepted atomic.Uint64
	start := make(chan struct{})
	admitted := make(chan struct{})
	var admitOnce sync.Once
	var wg sync.WaitGroup
	for range emitters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range perEmitter {
				err := sink.Emit(context.Background(), Event{
					Severity:   SeverityWarn,
					Type:       testEventBlocked,
					Timestamp:  time.Now(),
					InstanceID: testStr,
				})
				if err == nil || errors.Is(err, ErrWebhookDegraded) {
					accepted.Add(1)
					admitOnce.Do(func() { close(admitted) })
				}
			}
		}()
	}
	close(start)
	// Guarantee overlap: wait until at least one event has actually been
	// admitted before racing Close, so the test cannot pass vacuously with
	// accepted==accounted==0.
	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("no event was admitted before timeout")
	}
	// Race Close against the emitters so admission overlaps shutdown.
	closeErr := sink.Close()
	wg.Wait()
	// Close is idempotent; a second call after all emitters finished makes
	// sure the worker fully drained before we snapshot stats.
	_ = sink.Close()
	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	stats := sink.Stats()
	if accepted.Load() == 0 {
		t.Fatalf("no events were accepted; test would be vacuous (stats = %+v)", stats)
	}
	accounted := stats.Delivered + stats.Failed + stats.Abandoned
	if accounted != accepted.Load() {
		t.Fatalf("accepted %d events but accounted for %d (stats = %+v): accepted events were silently lost",
			accepted.Load(), accounted, stats)
	}
}

func TestWebhookSink_ErrorStringsRedactWebhookURL(t *testing.T) {
	// A send failure to an unreachable URL carrying a secret query token must
	// not leak that token into Stats().LastError or the stderr diagnostics.
	const canary = "supersecret-canary-token"
	sink := NewWebhookSink("http://127.0.0.1:0/hook?token=" + canary)
	defer func() { _ = sink.Close() }()

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Now(),
		InstanceID: testStr,
	})
	if err != nil && !errors.Is(err, ErrWebhookDegraded) {
		t.Fatalf("Emit: %v", err)
	}
	waitWebhookStats(t, sink, func(s WebhookStats) bool { return s.Failed >= 1 })
	if got := sink.Stats().LastError; strings.Contains(got, canary) {
		t.Fatalf("LastError leaked the webhook URL token: %q", got)
	}
}

func TestWebhookSink_SuccessDoesNotEraseConcurrentDropDegraded(t *testing.T) {
	// A successful send must not clear the degraded flag when a drop is
	// recorded while that send is in flight. Drive the real send path: the
	// server records a queue-full drop (which sets degraded and advances the
	// drop counter) before returning 204, so send's post-success snapshot
	// guard observes the counter moved and must leave degraded set. This
	// exercises the production failSnapshot guard rather than re-implementing
	// it inline.
	var sink *WebhookSink
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sink.recordDropped("queue_full", nil)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sink = NewWebhookSink(srv.URL)
	defer func() { _ = sink.Close() }()

	sink.send(Event{Type: testEventBlocked, Timestamp: time.Now()})

	stats := sink.Stats()
	if stats.Delivered != 1 {
		t.Fatalf("delivered = %d, want 1", stats.Delivered)
	}
	if stats.Dropped != 1 {
		t.Fatalf("dropped = %d, want 1", stats.Dropped)
	}
	if !stats.Degraded {
		t.Fatal("degraded was erased despite a concurrent drop during the send")
	}
	if stats.LastError != "queue_full" {
		t.Fatalf("LastError = %q, want concurrent drop error preserved", stats.LastError)
	}
}

func TestWebhookSink_SuccessHealthTransitionIsAtomic(t *testing.T) {
	requestDone := make(chan struct{})
	sink := &WebhookSink{
		url: "https://api.vendor.example/hook",
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			close(requestDone)
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       http.NoBody,
			}, nil
		})},
		queue: make(chan Event, 1),
	}
	sink.degraded.Store(true)
	sink.lastErr = "prior failure"

	// Hold the LastError lock while the request completes. Degraded must remain
	// true until the successful recovery can clear both health fields together.
	sink.lastErrMu.Lock()
	done := make(chan struct{})
	go func() {
		sink.send(Event{Severity: SeverityWarn, Type: testEventBlocked, Timestamp: time.Now()})
		close(done)
	}()
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		sink.lastErrMu.Unlock()
		t.Fatal("timeout waiting for webhook request")
	}
	deadline := time.After(2 * time.Second)
	for sink.delivered.Load() != 1 {
		select {
		case <-deadline:
			sink.lastErrMu.Unlock()
			t.Fatal("timeout waiting for webhook delivery")
		default:
		}
	}
	if !sink.degraded.Load() {
		sink.lastErrMu.Unlock()
		t.Fatal("Degraded cleared before LastError could be cleared")
	}
	sink.lastErrMu.Unlock()
	<-done

	if stats := sink.Stats(); stats.Degraded || stats.LastError != "" {
		t.Fatalf("stats = %+v, want atomic successful recovery", stats)
	}
}

func TestWebhookSink_RepeatedDegradeRecoverCycles(t *testing.T) {
	sink := &WebhookSink{
		url: "https://api.vendor.example/hook",
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       http.NoBody,
			}, nil
		})},
		queue: make(chan Event, 1),
	}

	for cycle := 1; cycle <= 3; cycle++ {
		sink.recordDropped("queue_full", nil)
		if stats := sink.Stats(); !stats.Degraded || stats.LastError != "queue_full" {
			t.Fatalf("cycle %d degraded stats = %+v", cycle, stats)
		}

		sink.send(Event{Severity: SeverityWarn, Type: testEventBlocked, Timestamp: time.Now()})
		stats := sink.Stats()
		if stats.Degraded || stats.LastError != "" || stats.Delivered != uint64(cycle) || stats.Dropped != uint64(cycle) {
			t.Fatalf("cycle %d recovered stats = %+v", cycle, stats)
		}
	}
}

func TestWebhookSink_RecordDroppedWithErrorAndAbandonedZeroCount(t *testing.T) {
	sink := &WebhookSink{queue: make(chan Event, 1)}

	sink.recordDropped("test_reason", errors.New("boom"))
	if stats := sink.Stats(); stats.Dropped != 1 || stats.LastError != "boom" {
		t.Fatalf("stats after dropped-with-error = %+v, want Dropped=1 LastError=boom", stats)
	}

	// A zero or negative abandon count must be a no-op.
	sink.recordAbandoned("drain_timeout", 0)
	if stats := sink.Stats(); stats.Abandoned != 0 {
		t.Fatalf("stats after zero-count abandon = %+v, want Abandoned=0", stats)
	}
}
