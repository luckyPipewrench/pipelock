// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Default values for WebhookSink configuration.
const (
	DefaultQueueSize      = 64
	DefaultWebhookTimeout = 5 * time.Second
	drainTimeout          = 10 * time.Second
)

// ErrQueueFull is returned when the event queue is at capacity.
var ErrQueueFull = errors.New("emit: webhook queue full, event dropped")

// ErrWebhookDegraded is returned after a prior async delivery failure.
// The event may still be accepted for queueing; this error signals that the
// sink is not currently proving successful delivery.
var ErrWebhookDegraded = errors.New("emit: webhook sink degraded")

// WebhookStats reports delivery health for a WebhookSink.
type WebhookStats = sinkStats

// webhookPayload is the JSON structure sent to the webhook endpoint.
type webhookPayload struct {
	Severity  string         `json:"severity"`
	Type      string         `json:"type"`
	Timestamp string         `json:"timestamp"`
	Instance  string         `json:"pipelock_instance"`
	Fields    map[string]any `json:"fields"`
}

// WebhookSink sends formatted audit events to an HTTP endpoint.
// Events are queued and sent asynchronously by a single background goroutine.
type WebhookSink struct {
	url       string
	token     string // optional bearer token
	minSev    Severity
	client    *http.Client
	queue     chan Event
	done      chan struct{}
	closeMu   sync.Mutex
	closed    bool
	closeWG   sync.WaitGroup
	closeOnce sync.Once

	delivered atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
	abandoned atomic.Uint64
	degraded  atomic.Bool
	lastErrMu sync.Mutex
	lastErr   string
	format    string
	version   string
}

// WebhookOption configures a WebhookSink.
type WebhookOption func(*WebhookSink)

// WithQueueSize sets the buffered channel capacity for pending events.
func WithQueueSize(n int) WebhookOption {
	return func(w *WebhookSink) {
		if n > 0 {
			w.queue = make(chan Event, n)
		}
	}
}

// WithWebhookTimeout sets the HTTP client timeout for each POST.
func WithWebhookTimeout(d time.Duration) WebhookOption {
	return func(w *WebhookSink) {
		if d > 0 {
			w.client.Timeout = d
		}
	}
}

// WithBearerToken sets the Authorization: Bearer header value.
func WithBearerToken(tok string) WebhookOption {
	return func(w *WebhookSink) {
		w.token = tok
	}
}

// WithMinSeverity sets the minimum severity for events to be emitted.
func WithMinSeverity(sev Severity) WebhookOption {
	return func(w *WebhookSink) {
		w.minSev = sev
	}
}

// WithWebhookFormat sets the HTTP event wire format. Format names come from
// emitformat; rendering is shared with syslog through formatEvent.
func WithWebhookFormat(format, deviceVersion string) WebhookOption {
	return func(w *WebhookSink) {
		w.format = format
		w.version = deviceVersion
	}
}

// NewWebhookSink creates a WebhookSink that POSTs events to the given URL.
// The background goroutine starts immediately and runs until Close is called.
func NewWebhookSink(url string, opts ...WebhookOption) *WebhookSink {
	w := &WebhookSink{
		url:    url,
		format: FormatJSON,
		client: &http.Client{Timeout: DefaultWebhookTimeout},
		queue:  make(chan Event, DefaultQueueSize),
		done:   make(chan struct{}),
	}
	for _, opt := range opts {
		opt(w)
	}

	w.closeWG.Add(1)
	go w.run()

	return w
}

// Emit enqueues an event for async delivery.
// Events below the minimum severity are silently dropped.
// Returns ErrQueueFull if the queue is at capacity, ErrWebhookDegraded if
// a prior async delivery failed, or an error if the sink is closed.
func (w *WebhookSink) Emit(_ context.Context, event Event) error {
	if event.Severity < w.minSev {
		return nil
	}

	degraded := w.degraded.Load()
	w.closeMu.Lock()
	if w.closed {
		w.closeMu.Unlock()
		return errors.New("emit: webhook sink closed")
	}
	select {
	case w.queue <- event:
		w.closeMu.Unlock()
		if degraded {
			return ErrWebhookDegraded
		}
		return nil
	default:
		w.closeMu.Unlock()
		w.recordDropped("queue_full", nil)
		return ErrQueueFull
	}
}

// Close signals the background goroutine to drain remaining events and stop.
// It blocks until all pending events are sent or the drain timeout expires.
// Close is safe to call multiple times.
func (w *WebhookSink) Close() error {
	w.closeOnce.Do(func() {
		w.closeMu.Lock()
		w.closed = true
		w.closeMu.Unlock()
		close(w.done)
	})
	w.closeWG.Wait()
	return nil
}

// run is the background goroutine that sends queued events.
func (w *WebhookSink) run() {
	defer w.closeWG.Done()
	defer func() {
		if r := recover(); r != nil {
			w.recordFailure("panic", Event{Type: "unknown"}, fmt.Errorf("%v", r))
		}
	}()

	for {
		select {
		case event := <-w.queue:
			w.safeSend(event)
		case <-w.done:
			w.drain()
			return
		}
	}
}

// drain sends remaining queued events with a deadline.
func (w *WebhookSink) drain() {
	deadline := time.After(drainTimeout)
	for {
		select {
		case event := <-w.queue:
			w.safeSend(event)
		case <-deadline:
			w.recordAbandoned(len(w.queue))
			return
		default:
			return
		}
	}
}

func (w *WebhookSink) safeSend(event Event) {
	defer func() {
		if r := recover(); r != nil {
			w.recordFailure("panic", event, fmt.Errorf("%v", r))
		}
	}()
	w.send(event)
}

// send formats and POSTs a single event to the webhook URL.
func (w *WebhookSink) send(event Event) {
	// Snapshot the health-change counters before the send so a successful
	// delivery only clears degraded health if no failure, drop, or abandonment
	// was recorded while this send was in flight. Without this, a concurrent
	// queue-full drop could be silently erased by this send's success.
	failedSnapshot := w.failed.Load()
	droppedSnapshot := w.dropped.Load()
	abandonedSnapshot := w.abandoned.Load()

	body, contentType, err := formatEvent(event, w.format, w.version)
	if err != nil {
		reason := "format_error"
		if w.format == "" || w.format == FormatJSON {
			reason = "marshal_error"
		}
		w.recordFailure(reason, event, err)
		return
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		w.recordFailure("request_error", event, err)
		return
	}

	req.Header.Set("Content-Type", contentType)
	if w.token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		w.recordFailure("send_error", event, err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		w.recordFailure("http_status", event, fmt.Errorf("HTTP %d", resp.StatusCode))
		return
	}
	w.delivered.Add(1)
	w.lastErrMu.Lock()
	// Clear paired health only if no newer failure, drop, or abandonment was
	// recorded while this request was in flight. Rechecking under the same lock
	// that guards health updates closes the check-then-clear race.
	if w.failed.Load() == failedSnapshot &&
		w.dropped.Load() == droppedSnapshot &&
		w.abandoned.Load() == abandonedSnapshot {
		w.degraded.Store(false)
		w.lastErr = ""
	}
	w.lastErrMu.Unlock()
}

// Stats returns a consistent snapshot of webhook sink delivery health.
func (w *WebhookSink) Stats() WebhookStats {
	if w == nil {
		return WebhookStats{}
	}
	w.lastErrMu.Lock()
	lastErr := w.lastErr
	degraded := w.degraded.Load()
	w.lastErrMu.Unlock()
	stats := WebhookStats{
		Delivered: w.delivered.Load(),
		Failed:    w.failed.Load(),
		Dropped:   w.dropped.Load(),
		Abandoned: w.abandoned.Load(),
		Degraded:  degraded,
		LastError: lastErr,
	}
	if w.queue != nil {
		stats.QueueLen = len(w.queue)
		stats.QueueCap = cap(w.queue)
	}
	return stats
}

// sanitizeWebhookErr returns an error message safe to store and log. net/http
// returns a *url.Error whose Error() embeds the full request URL, which for a
// webhook endpoint can carry a secret path or query token; strip the URL and
// keep only the operation and underlying cause so LastError and stderr
// diagnostics never leak it.
func sanitizeWebhookErr(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Err != nil {
			return fmt.Sprintf("%s: %v", urlErr.Op, sanitizeWebhookErr(urlErr.Err))
		}
		return urlErr.Op
	}
	return err.Error()
}

func (w *WebhookSink) recordFailure(reason string, event Event, err error) {
	w.failed.Add(1)
	w.lastErrMu.Lock()
	w.degraded.Store(true)
	if err != nil {
		w.lastErr = sanitizeWebhookErr(err)
	}
	w.lastErrMu.Unlock()
	w.logDiagnostic("delivery_failed", reason, event, err, 0)
}

// recordDropped accounts for an event dropped on the Emit hot path (queue full).
// It only updates atomic counters and lastErr and MUST NOT write a diagnostic
// synchronously: Emit runs on the request/enforcement path, and a queue-full
// drop means the system is already under telemetry backpressure, so a synchronous
// stderr write (which can block on a stalled pipe/journald) could turn that
// backpressure into request-path blocking. The drop is observable via
// Stats().Dropped / LastError / Degraded (and, once wired, sink health metrics).
func (w *WebhookSink) recordDropped(reason string, err error) {
	w.dropped.Add(1)
	lastErr := reason
	if err != nil {
		lastErr = sanitizeWebhookErr(err)
	}
	w.lastErrMu.Lock()
	w.degraded.Store(true)
	w.lastErr = lastErr
	w.lastErrMu.Unlock()
}

func (w *WebhookSink) recordAbandoned(count int) {
	if count < 1 {
		return
	}
	const reason = "drain_timeout" // the only path that abandons webhook events is a drain deadline
	w.abandoned.Add(uint64(count))
	w.lastErrMu.Lock()
	w.degraded.Store(true)
	w.lastErr = reason
	w.lastErrMu.Unlock()
	w.logDiagnostic("events_abandoned", reason, Event{Type: "unknown"}, nil, count)
}

func (w *WebhookSink) logDiagnostic(eventName, reason string, event Event, err error, count int) {
	defer func() {
		_ = recover()
	}()
	fields := map[string]any{
		"component":  "emit.webhook",
		"event":      eventName,
		"reason":     reason,
		"event_type": event.Type,
		"delivered":  w.delivered.Load(),
		"failed":     w.failed.Load(),
		"dropped":    w.dropped.Load(),
		"abandoned":  w.abandoned.Load(),
		"queue_len":  len(w.queue),
		"queue_cap":  cap(w.queue),
	}
	if err != nil {
		fields["error"] = sanitizeWebhookErr(err)
	}
	if count > 0 {
		fields["count"] = count
	}
	encoded, marshalErr := json.Marshal(fields)
	if marshalErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "emit: webhook diagnostic marshal error: %v\n", marshalErr)
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, string(encoded))
}
