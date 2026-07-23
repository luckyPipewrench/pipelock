// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	respb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Default values for OTLPSink configuration.
const (
	DefaultOTLPQueueSize = 256
	DefaultOTLPTimeout   = 10 * time.Second

	// OTLP severity numbers per the spec.
	// https://opentelemetry.io/docs/specs/otel/logs/data-model/#severity-fields
	otlpSeverityInfo  = 9
	otlpSeverityWarn  = 13
	otlpSeverityError = 17

	otlpSeverityTextInfo  = "INFO"
	otlpSeverityTextWarn  = "WARN"
	otlpSeverityTextError = "ERROR"

	// Retry backoff schedule for 429/5xx responses and network errors.
	otlpMaxRetries  = 3
	otlpRetryFactor = 2
)

var (
	otlpDrainTimeout = 10 * time.Second
	otlpRetryBase    = 1 * time.Second
)

var (
	otlpMarshalExportLogsRequest = marshalExportLogsRequest
	otlpGzipCompress             = gzipCompress
	otlpMarshalDiagnostic        = json.Marshal
)

// ErrOTLPQueueFull is returned when the OTLP event queue is at capacity.
var ErrOTLPQueueFull = errors.New("emit: otlp queue full, event dropped")

// ErrOTLPDegraded is returned after a prior async delivery failure.
// The event may still be accepted for queueing; this error signals that the
// sink is not currently proving successful delivery.
var ErrOTLPDegraded = errors.New("emit: otlp sink degraded")

const errOTLPClosed = "emit: otlp sink closed"

// OTLPStats reports delivery health for an OTLPSink.
type OTLPStats = sinkStats

// OTLPSink sends audit events as OTLP log records over HTTP/protobuf.
// Events are queued and sent asynchronously by a single background goroutine.
type OTLPSink struct {
	endpoint  string // full URL including /v1/logs
	headers   map[string]string
	minSev    Severity
	useGzip   bool
	version   string // Pipelock binary version, used for pipelock-core@<v> ruleset suffix
	client    *http.Client
	resource  *respb.Resource
	queue     chan Event
	done      chan struct{}
	closed    bool // guarded by closeMu
	closeMu   sync.Mutex
	closeWG   sync.WaitGroup
	closeOnce sync.Once

	delivered atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
	abandoned atomic.Uint64
	degraded  atomic.Bool
	lastErrMu sync.Mutex
	lastErr   string

	// agentThreatDetection toggles the unstable OTel
	// `agent.threat.detection.*` attribute set on scanner-decision
	// log records. Off by default; enabled via EnableAgentThreatDetection.
	// atomic.Bool because EnableAgentThreatDetection may be called from
	// the main goroutine after run() has started (the constructor spawns
	// run() before returning), and eventToLogRecord reads the flag from
	// the run() goroutine. See docs/observability/agent-threat-detection.md.
	agentThreatDetection atomic.Bool
}

// NewOTLPSink creates an OTLPSink that sends log records to the given endpoint.
// The endpoint is the base URL (e.g. "http://collector:4318"); /v1/logs is
// appended automatically. The version string is set as the service.version
// resource attribute.
func NewOTLPSink(endpoint, version string, minSev Severity, headers map[string]string, timeout time.Duration, queueSize int, useGzip bool) (*OTLPSink, error) {
	// Normalize: strip trailing /v1/logs if the operator already included it,
	// then append it. Prevents http://collector:4318/v1/logs/v1/logs.
	endpoint = strings.TrimRight(endpoint, "/")
	endpoint = strings.TrimSuffix(endpoint, "/v1/logs")
	u, err := url.JoinPath(endpoint, "/v1/logs")
	if err != nil {
		return nil, fmt.Errorf("otlp: invalid endpoint %q: %w", endpoint, err)
	}

	if timeout <= 0 {
		timeout = DefaultOTLPTimeout
	}
	if queueSize <= 0 {
		queueSize = DefaultOTLPQueueSize
	}

	// Resource carries stable attributes. instance_id is NOT baked here -
	// it comes from the event (set by the Emitter) so it stays consistent
	// with webhook/syslog across hot-reloads.
	resource := &respb.Resource{
		Attributes: []*commonpb.KeyValue{
			stringKV("service.name", "pipelock"),
			stringKV("service.version", version),
		},
	}

	// Defensive copy: headers may come from config that gets swapped on reload.
	hdrs := make(map[string]string, len(headers))
	for k, v := range headers {
		hdrs[k] = v
	}

	s := &OTLPSink{
		endpoint: u,
		headers:  hdrs,
		minSev:   minSev,
		useGzip:  useGzip,
		version:  version,
		client:   &http.Client{Timeout: timeout},
		resource: resource,
		queue:    make(chan Event, queueSize),
		done:     make(chan struct{}),
	}

	s.closeWG.Add(1)
	go s.run()

	return s, nil
}

// EnableAgentThreatDetection turns on the unstable OTel
// `agent.threat.detection.*` attribute set on scanner-decision log records.
// Convention attribute names may change in subsequent Pipelock releases
// until the OTel SIG accepts the proposal. Tracks
// open-telemetry/semantic-conventions-genai#132.
//
// Safe to call after construction; the flag is atomic and read by the
// background emit goroutine on each event.
//
// See docs/observability/agent-threat-detection.md for the attribute
// mapping and ruleset namespace strategy.
func (s *OTLPSink) EnableAgentThreatDetection() {
	s.agentThreatDetection.Store(true)
}

// AgentThreatDetectionEnabled reports whether the unstable OTel
// `agent.threat.detection.*` attribute set is being appended to
// scanner-decision log records. Used by runtime construction tests
// and operator introspection.
func (s *OTLPSink) AgentThreatDetectionEnabled() bool {
	return s.agentThreatDetection.Load()
}

// Emit enqueues an event for async delivery.
// Events below the minimum severity are silently dropped.
//
// Return-value contract: a nil error and ErrOTLPDegraded both mean the event
// WAS accepted for delivery; ErrOTLPDegraded is an advisory that a prior async
// delivery failed, not a rejection, so callers must not retry or fail closed on
// it (distinguish with errors.Is). ErrOTLPQueueFull and the sink-closed error
// mean the event was NOT accepted. Degraded state is also observable via Stats().
// The closed flag is checked under closeMu so no enqueue can succeed
// after Close() sets the flag.
func (s *OTLPSink) Emit(_ context.Context, event Event) error {
	if s == nil || s.client == nil || s.queue == nil {
		return errors.New("emit: otlp sink not initialized")
	}
	if event.Severity < s.minSev {
		return nil
	}

	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return errors.New(errOTLPClosed)
	}
	degraded := s.degraded.Load()
	select {
	case s.queue <- event:
		s.closeMu.Unlock()
		if degraded {
			return ErrOTLPDegraded
		}
		return nil
	default:
		s.closeMu.Unlock()
		s.recordDropped("queue_full", nil)
		return ErrOTLPQueueFull
	}
}

// Close signals the background goroutine to drain remaining events and stop.
// No new events can be enqueued after Close() returns.
func (s *OTLPSink) Close() error {
	s.closeOnce.Do(func() {
		s.closeMu.Lock()
		s.closed = true
		s.closeMu.Unlock()
		close(s.done)
	})
	s.closeWG.Wait()
	return nil
}

// run is the background goroutine that sends queued events.
func (s *OTLPSink) run() {
	defer s.closeWG.Done()

	for {
		select {
		case event := <-s.queue:
			s.safeSend(event)
		case <-s.done:
			s.drain()
			return
		}
	}
}

// drain sends remaining queued events with a deadline.
func (s *OTLPSink) drain() {
	deadline := time.Now().Add(otlpDrainTimeout)
	for {
		select {
		case event := <-s.queue:
			if time.Now().After(deadline) {
				s.recordAbandoned("drain_timeout", event, len(s.queue)+1)
				return
			}
			s.safeSend(event)
		default:
			return
		}
	}
}

func (s *OTLPSink) safeSend(event Event) {
	defer func() {
		if r := recover(); r != nil {
			s.recordFailure("panic", event, fmt.Errorf("%v", r))
		}
	}()
	s.send(event)
}

// send marshals and POSTs a single event as an OTLP ExportLogsServiceRequest.
func (s *OTLPSink) send(event Event) {
	record := s.eventToLogRecord(event)

	// Snapshot the health-change counters before the send so a successful
	// delivery only clears degraded health if no failure, drop, or abandonment
	// was recorded while this send was in flight (mirrors WebhookSink.send);
	// otherwise a concurrent queue-full drop would be silently erased.
	failedSnapshot := s.failed.Load()
	droppedSnapshot := s.dropped.Load()
	abandonedSnapshot := s.abandoned.Load()

	// Build ExportLogsServiceRequest without importing collector/logs/v1
	// (which pulls in gRPC). The wire format is just field 1 = ResourceLogs.
	body, err := otlpMarshalExportLogsRequest(s.resource, record)
	if err != nil {
		s.recordFailure("marshal_error", event, err)
		return
	}

	if s.useGzip {
		body, err = otlpGzipCompress(body)
		if err != nil {
			s.recordFailure("gzip_error", event, err)
			return
		}
	}

	result := s.sendWithRetry(body)
	if result.abandoned {
		s.recordAbandoned(result.reason, event, 1)
		return
	}
	if result.err != nil {
		s.recordFailure(result.reason, event, result.err)
		return
	}
	s.delivered.Add(1)
	// Clear paired health only if no newer failure, drop, or abandonment was
	// recorded while this request was in flight. Rechecking under the same lock
	// that guards health updates closes the check-then-clear race; otherwise a
	// concurrent queue-full drop would be silently erased and Stats() would
	// report Degraded=false with a stale error.
	s.lastErrMu.Lock()
	if s.failed.Load() == failedSnapshot &&
		s.dropped.Load() == droppedSnapshot &&
		s.abandoned.Load() == abandonedSnapshot {
		s.degraded.Store(false)
		s.lastErr = ""
	}
	s.lastErrMu.Unlock()
}

// isRetryableStatus returns true for OTLP-spec-defined retryable status codes.
// Per the OTLP/HTTP spec, only 429, 502, 503, and 504 are retryable.
// 500 and 501 indicate server bugs and are not retryable.
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

type otlpSendResult struct {
	reason    string
	err       error
	abandoned bool
}

// sendWithRetry POSTs the body with bounded retry on retryable errors.
// Retries on 429/502/503/504 and network errors per OTLP spec.
// Transient failed attempts are not counted when a later retry succeeds; only
// the final export outcome updates delivery accounting.
// The done channel is checked between retries so Close() is not blocked
// by a stalled collector during drain.
func (s *OTLPSink) sendWithRetry(body []byte) otlpSendResult {
	backoff := otlpRetryBase
	for attempt := range otlpMaxRetries {
		httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.endpoint, bytes.NewReader(body))
		if err != nil {
			return otlpSendResult{reason: "request_error", err: err}
		}

		// Apply custom headers first, then set transport headers.
		// This prevents config from accidentally overriding Content-Type
		// or Content-Encoding, which would break every export silently.
		for k, v := range s.headers {
			httpReq.Header.Set(k, v)
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		if s.useGzip {
			httpReq.Header.Set("Content-Encoding", "gzip")
		}

		resp, doErr := s.client.Do(httpReq)
		if doErr != nil {
			if attempt < otlpMaxRetries-1 {
				if !s.backoffOrDone(backoff) {
					return otlpSendResult{reason: "close_during_retry", abandoned: true}
				}
				backoff *= otlpRetryFactor
				continue
			}
			return otlpSendResult{reason: "send_error", err: doErr}
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return otlpSendResult{}
		}
		if isRetryableStatus(resp.StatusCode) {
			if attempt < otlpMaxRetries-1 {
				if !s.backoffOrDone(backoff) {
					return otlpSendResult{reason: "close_during_retry", abandoned: true}
				}
				backoff *= otlpRetryFactor
				continue
			}
			return otlpSendResult{
				reason: "http_status",
				err:    fmt.Errorf("otlp HTTP %d after %d attempts", resp.StatusCode, otlpMaxRetries),
			}
		}
		return otlpSendResult{
			reason: "http_status",
			err:    fmt.Errorf("otlp HTTP %d (not retryable)", resp.StatusCode),
		}
	}
	return otlpSendResult{reason: "send_error", err: errors.New("otlp retry loop exited without an attempt")}
}

// backoffOrDone sleeps for the backoff duration or returns false if the
// sink is closing. Returns true if the sleep completed (should retry).
func (s *OTLPSink) backoffOrDone(d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-s.done:
		return false
	}
}

// Stats returns a consistent snapshot of OTLP sink delivery health.
func (s *OTLPSink) Stats() OTLPStats {
	if s == nil {
		return OTLPStats{}
	}
	s.lastErrMu.Lock()
	lastErr := s.lastErr
	s.lastErrMu.Unlock()
	stats := OTLPStats{
		Delivered: s.delivered.Load(),
		Failed:    s.failed.Load(),
		Dropped:   s.dropped.Load(),
		Abandoned: s.abandoned.Load(),
		Degraded:  s.degraded.Load(),
		LastError: lastErr,
	}
	if s.queue != nil {
		stats.QueueLen = len(s.queue)
		stats.QueueCap = cap(s.queue)
	}
	return stats
}

func (s *OTLPSink) recordFailure(reason string, event Event, err error) {
	lastErr := safeOTLPErrorString(err)
	s.failed.Add(1)
	s.degraded.Store(true)
	if lastErr != "" {
		s.lastErrMu.Lock()
		s.lastErr = lastErr
		s.lastErrMu.Unlock()
	}
	s.logDiagnostic("delivery_failed", reason, event, lastErr, 0)
}

// recordDropped accounts for an event dropped on the Emit hot path (queue full).
// It only updates atomic counters and lastErr and MUST NOT write a diagnostic
// synchronously: Emit runs on the request/enforcement path, and a queue-full
// drop means the system is already under telemetry backpressure, so a synchronous
// stderr write (which can block on a stalled pipe/journald) could turn that
// backpressure into request-path blocking. The drop is observable via
// Stats().Dropped / LastError / Degraded (and, once wired, sink health metrics).
func (s *OTLPSink) recordDropped(reason string, err error) {
	s.dropped.Add(1)
	s.degraded.Store(true)
	lastErr := reason
	if err != nil {
		lastErr = safeOTLPErrorString(err)
	}
	s.lastErrMu.Lock()
	s.lastErr = lastErr
	s.lastErrMu.Unlock()
}

func (s *OTLPSink) recordAbandoned(reason string, event Event, count int) {
	if count < 1 {
		count = 1
	}
	s.abandoned.Add(uint64(count))
	s.degraded.Store(true)
	s.lastErrMu.Lock()
	s.lastErr = reason
	s.lastErrMu.Unlock()
	s.logDiagnostic("events_abandoned", reason, event, "", count)
}

func (s *OTLPSink) logDiagnostic(eventName, reason string, event Event, errText string, count int) {
	defer func() {
		_ = recover()
	}()

	fields := map[string]any{
		"component":  "emit.otlp",
		"event":      eventName,
		"reason":     reason,
		"event_type": event.Type,
		"delivered":  s.delivered.Load(),
		"failed":     s.failed.Load(),
		"dropped":    s.dropped.Load(),
		"abandoned":  s.abandoned.Load(),
		"queue_len":  len(s.queue),
		"queue_cap":  cap(s.queue),
	}
	if errText != "" {
		fields["error"] = errText
	}
	if count > 0 {
		fields["count"] = count
	}
	encoded, marshalErr := otlpMarshalDiagnostic(fields)
	if marshalErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "emit: otlp diagnostic marshal error: %v\n", marshalErr)
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, string(encoded))
}

// safeOTLPErrorString returns err.Error() without letting a hostile error
// implementation panic the caller (the delivery goroutine records failures with
// arbitrary error values). Returns "" for a nil error.
func safeOTLPErrorString(err error) (msg string) {
	if err == nil {
		return ""
	}
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprintf("error string panic: %v", r)
		}
	}()
	return err.Error()
}

// eventToLogRecord converts an emit.Event to an OTLP LogRecord.
func (s *OTLPSink) eventToLogRecord(event Event) *logspb.LogRecord {
	sevNum, sevText := mapSeverity(event.Severity)

	var attrs []*commonpb.KeyValue
	for k, v := range event.Fields {
		attrs = append(attrs, stringKV(k, fmt.Sprint(v)))
	}
	// Add instance ID as an attribute for per-event queryability.
	attrs = append(attrs, stringKV("pipelock.instance", event.InstanceID))
	// Optional: append OTel `agent.threat.detection.*` attributes when
	// the feature flag is on and the event represents a scanner decision
	// with a verdict in the convention's vocabulary. The mapper returns
	// nil for non-qualifying events, in which case nothing is appended.
	if s.agentThreatDetection.Load() {
		attrs = append(attrs, agentThreatDetectionAttrs(event, s.version)...)
	}

	tsNano := uint64(event.Timestamp.UnixNano())
	return &logspb.LogRecord{
		TimeUnixNano:         tsNano,
		ObservedTimeUnixNano: tsNano, // same as emit time; prevents collector clock drift
		SeverityNumber:       sevNum,
		SeverityText:         sevText,
		Body: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: event.Type},
		},
		Attributes: attrs,
	}
}

// mapSeverity converts pipelock's 3-level severity to OTLP severity numbers.
func mapSeverity(sev Severity) (logspb.SeverityNumber, string) {
	switch sev {
	case SeverityWarn:
		return otlpSeverityWarn, otlpSeverityTextWarn
	case SeverityCritical:
		return otlpSeverityError, otlpSeverityTextError
	default:
		return otlpSeverityInfo, otlpSeverityTextInfo
	}
}

// stringKV creates an OTLP KeyValue with a string value.
func stringKV(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: value},
		},
	}
}

// marshalExportLogsRequest builds the ExportLogsServiceRequest protobuf
// without importing the collector/logs/v1 package (which pulls in gRPC).
// The message has a single field: repeated ResourceLogs resource_logs = 1.
func marshalExportLogsRequest(resource *respb.Resource, record *logspb.LogRecord) ([]byte, error) {
	rl := &logspb.ResourceLogs{
		Resource: resource,
		ScopeLogs: []*logspb.ScopeLogs{
			{LogRecords: []*logspb.LogRecord{record}},
		},
	}
	rlBytes, err := proto.Marshal(rl)
	if err != nil {
		return nil, err
	}
	// ExportLogsServiceRequest field 1 = ResourceLogs (length-delimited).
	const resourceLogsFieldNumber = 1
	var out []byte
	out = protowire.AppendTag(out, resourceLogsFieldNumber, protowire.BytesType)
	out = protowire.AppendBytes(out, rlBytes)
	return out, nil
}

// gzipCompress compresses data using gzip.
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
