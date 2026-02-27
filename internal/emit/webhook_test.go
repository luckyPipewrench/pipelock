package emit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
		Type:       "allowed",
		Timestamp:  time.Now(),
		InstanceID: "test",
	})
	if err != nil {
		t.Fatalf("expected nil error for dropped event, got %v", err)
	}

	// Give background goroutine a moment — no request should arrive.
	time.Sleep(50 * time.Millisecond)
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

	ts := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       "blocked",
		Timestamp:  ts,
		InstanceID: "test-host",
		Fields:     map[string]any{"url": "https://evil.com", "reason": "blocklist"},
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for webhook POST")
	}

	//nolint:goconst // test value
	if received.Severity != "warn" {
		t.Errorf("payload severity = %q, want %q", received.Severity, "warn")
	}
	//nolint:goconst // test value
	if received.Type != "blocked" {
		t.Errorf("payload type = %q, want %q", received.Type, "blocked")
	}
	if received.Instance != "test-host" {
		t.Errorf("payload instance = %q, want %q", received.Instance, "test-host")
	}

	// Verify timestamp is in RFC3339Nano format.
	_, parseErr := time.Parse(time.RFC3339Nano, received.Timestamp)
	if parseErr != nil {
		t.Errorf("timestamp %q is not RFC3339Nano: %v", received.Timestamp, parseErr)
	}

	if received.Fields["url"] != "https://evil.com" {
		t.Errorf("fields[url] = %v, want %q", received.Fields["url"], "https://evil.com")
	}

	_ = sink.Close()
}

func TestWebhookSink_BearerToken(t *testing.T) {
	var gotAuth string
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		close(done)
	}))
	defer srv.Close()

	//nolint:goconst // test value
	token := "test" + "-secret-token"
	sink := NewWebhookSink(srv.URL, WithBearerToken(token))

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       "blocked",
		Timestamp:  time.Now(),
		InstanceID: "test",
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

	_ = sink.Close()
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

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       "blocked",
		Timestamp:  time.Now(),
		InstanceID: "test",
	})
	if err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for webhook POST")
	}

	_ = sink.Close()
}

func TestWebhookSink_QueueFull(t *testing.T) {
	// Server blocks long enough for the queue to fill.
	blocker := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-blocker
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL,
		WithQueueSize(2),
		WithWebhookTimeout(30*time.Second),
	)

	event := Event{
		Severity:   SeverityWarn,
		Type:       "blocked",
		Timestamp:  time.Now(),
		InstanceID: "test",
	}

	// Fill the queue. One item may be pulled by the goroutine, so send extra.
	var queueFullSeen bool
	for i := 0; i < 20; i++ {
		if err := sink.Emit(context.Background(), event); errors.Is(err, ErrQueueFull) {
			queueFullSeen = true
			break
		}
		// Brief pause to let the goroutine pick up the first event and block on HTTP.
		time.Sleep(time.Millisecond)
	}

	if !queueFullSeen {
		t.Error("expected ErrQueueFull after filling queue")
	}

	// Unblock the server so Close can drain without hanging.
	close(blocker)
	_ = sink.Close()
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
			Type:       "blocked",
			Timestamp:  time.Now(),
			InstanceID: "test",
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
			Type:       "blocked",
			Timestamp:  time.Now(),
			InstanceID: "test",
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
					Type:       "blocked",
					Timestamp:  time.Now(),
					InstanceID: "test",
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

	err := sink.Emit(context.Background(), Event{
		Severity:   SeverityWarn,
		Type:       "blocked",
		Timestamp:  time.Now(),
		InstanceID: "test",
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
	if received.Type != "blocked" { //nolint:goconst // test value
		t.Errorf("payload type = %q, want %q", received.Type, "blocked")
	}

	_ = sink.Close()
}
