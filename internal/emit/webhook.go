package emit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
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

// webhookPayload is the JSON structure sent to the webhook endpoint.
type webhookPayload struct {
	Severity  string         `json:"severity"`
	Type      string         `json:"type"`
	Timestamp string         `json:"timestamp"`
	Instance  string         `json:"pipelock_instance"`
	Fields    map[string]any `json:"fields"`
}

// WebhookSink sends audit events as JSON to an HTTP endpoint.
// Events are queued and sent asynchronously by a single background goroutine.
type WebhookSink struct {
	url       string
	token     string // optional bearer token
	minSev    Severity
	client    *http.Client
	queue     chan Event
	done      chan struct{}
	closeWG   sync.WaitGroup
	closeOnce sync.Once
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

// NewWebhookSink creates a WebhookSink that POSTs JSON events to the given URL.
// The background goroutine starts immediately and runs until Close is called.
func NewWebhookSink(url string, opts ...WebhookOption) *WebhookSink {
	w := &WebhookSink{
		url:    url,
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
// Returns ErrQueueFull if the queue is at capacity, or an error if the sink is closed.
func (w *WebhookSink) Emit(_ context.Context, event Event) error {
	if event.Severity < w.minSev {
		return nil
	}

	select {
	case <-w.done:
		return errors.New("emit: webhook sink closed")
	default:
	}

	select {
	case w.queue <- event:
		return nil
	case <-w.done:
		return errors.New("emit: webhook sink closed")
	default:
		return ErrQueueFull
	}
}

// Close signals the background goroutine to drain remaining events and stop.
// It blocks until all pending events are sent or the drain timeout expires.
// Close is safe to call multiple times.
func (w *WebhookSink) Close() error {
	w.closeOnce.Do(func() {
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
			fmt.Fprintf(os.Stderr, "emit: webhook goroutine panic: %v\n", r)
		}
	}()

	for {
		select {
		case event := <-w.queue:
			w.send(event)
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
			w.send(event)
		case <-deadline:
			return
		default:
			return
		}
	}
}

// send POSTs a single event as JSON to the webhook URL.
func (w *WebhookSink) send(event Event) {
	payload := webhookPayload{
		Severity:  event.Severity.String(),
		Type:      event.Type,
		Timestamp: event.Timestamp.UTC().Format(time.RFC3339Nano),
		Instance:  event.InstanceID,
		Fields:    event.Fields,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "emit: webhook marshal error: %v\n", err)
		return
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "emit: webhook request error: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if w.token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "emit: webhook send error: %v\n", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "emit: webhook returned HTTP %d for event %s\n", resp.StatusCode, event.Type)
	}
}
