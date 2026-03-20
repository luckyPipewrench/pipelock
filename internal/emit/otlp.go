// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
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

	// Retry backoff schedule for 429/5xx responses and network errors.
	otlpMaxRetries   = 3
	otlpRetryBase    = 1 * time.Second
	otlpRetryFactor  = 2
	otlpDrainTimeout = 10 * time.Second
)

// ErrOTLPQueueFull is returned when the OTLP event queue is at capacity.
var ErrOTLPQueueFull = errors.New("emit: otlp queue full, event dropped")

const errOTLPClosed = "emit: otlp sink closed"

// OTLPSink sends audit events as OTLP log records over HTTP/protobuf.
// Events are queued and sent asynchronously by a single background goroutine.
type OTLPSink struct {
	endpoint  string // full URL including /v1/logs
	headers   map[string]string
	minSev    Severity
	useGzip   bool
	client    *http.Client
	resource  *respb.Resource
	queue     chan Event
	done      chan struct{}
	closeWG   sync.WaitGroup
	closeOnce sync.Once
}

// NewOTLPSink creates an OTLPSink that sends log records to the given endpoint.
// The endpoint is the base URL (e.g. "http://collector:4318"); /v1/logs is
// appended automatically. The version string is set as the service.version
// resource attribute.
func NewOTLPSink(endpoint, instanceID, version string, minSev Severity, headers map[string]string, timeout time.Duration, queueSize int, useGzip bool) (*OTLPSink, error) {
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

	resource := &respb.Resource{
		Attributes: []*commonpb.KeyValue{
			stringKV("service.name", "pipelock"),
			stringKV("service.instance.id", instanceID),
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
		client:   &http.Client{Timeout: timeout},
		resource: resource,
		queue:    make(chan Event, queueSize),
		done:     make(chan struct{}),
	}

	s.closeWG.Add(1)
	go s.run()

	return s, nil
}

// Emit enqueues an event for async delivery.
// Events below the minimum severity are silently dropped.
func (s *OTLPSink) Emit(_ context.Context, event Event) error {
	if event.Severity < s.minSev {
		return nil
	}

	select {
	case <-s.done:
		return errors.New(errOTLPClosed)
	default:
	}

	select {
	case s.queue <- event:
		return nil
	case <-s.done:
		return errors.New(errOTLPClosed)
	default:
		return ErrOTLPQueueFull
	}
}

// Close signals the background goroutine to drain and stop.
func (s *OTLPSink) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
	})
	s.closeWG.Wait()
	return nil
}

// run is the background goroutine that sends queued events.
func (s *OTLPSink) run() {
	defer s.closeWG.Done()
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(os.Stderr, "emit: otlp goroutine panic: %v\n", r)
		}
	}()

	for {
		select {
		case event := <-s.queue:
			s.send(event)
		case <-s.done:
			s.drain()
			return
		}
	}
}

// drain sends remaining queued events with a deadline.
func (s *OTLPSink) drain() {
	deadline := time.After(otlpDrainTimeout)
	for {
		select {
		case event := <-s.queue:
			s.send(event)
		case <-deadline:
			return
		default:
			return
		}
	}
}

// send marshals and POSTs a single event as an OTLP ExportLogsServiceRequest.
func (s *OTLPSink) send(event Event) {
	record := s.eventToLogRecord(event)

	// Build ExportLogsServiceRequest without importing collector/logs/v1
	// (which pulls in gRPC). The wire format is just field 1 = ResourceLogs.
	body, err := marshalExportLogsRequest(s.resource, record)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "emit: otlp marshal error: %v\n", err)
		return
	}

	if s.useGzip {
		body, err = gzipCompress(body)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "emit: otlp gzip error: %v\n", err)
			return
		}
	}

	s.sendWithRetry(body)
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

// sendWithRetry POSTs the body with bounded retry on retryable errors.
// Retries on 429/502/503/504 and network errors per OTLP spec.
// The done channel is checked between retries so Close() is not blocked
// by a stalled collector during drain.
func (s *OTLPSink) sendWithRetry(body []byte) {
	backoff := otlpRetryBase
	for attempt := range otlpMaxRetries {
		httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.endpoint, bytes.NewReader(body))
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "emit: otlp request error: %v\n", err)
			return
		}

		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		if s.useGzip {
			httpReq.Header.Set("Content-Encoding", "gzip")
		}
		for k, v := range s.headers {
			httpReq.Header.Set(k, v)
		}

		resp, doErr := s.client.Do(httpReq)
		if doErr != nil {
			if attempt < otlpMaxRetries-1 {
				if !s.backoffOrDone(backoff) {
					return // sink closing, abort retry
				}
				backoff *= otlpRetryFactor
				continue
			}
			_, _ = fmt.Fprintf(os.Stderr, "emit: otlp send error (final): %v\n", doErr)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		if isRetryableStatus(resp.StatusCode) {
			if attempt < otlpMaxRetries-1 {
				if !s.backoffOrDone(backoff) {
					return
				}
				backoff *= otlpRetryFactor
				continue
			}
			_, _ = fmt.Fprintf(os.Stderr, "emit: otlp HTTP %d after %d retries\n", resp.StatusCode, otlpMaxRetries)
			return
		}
		_, _ = fmt.Fprintf(os.Stderr, "emit: otlp HTTP %d (not retryable)\n", resp.StatusCode)
		return
	}
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

// eventToLogRecord converts an emit.Event to an OTLP LogRecord.
func (s *OTLPSink) eventToLogRecord(event Event) *logspb.LogRecord {
	sevNum, sevText := mapSeverity(event.Severity)

	var attrs []*commonpb.KeyValue
	for k, v := range event.Fields {
		attrs = append(attrs, stringKV(k, fmt.Sprint(v)))
	}
	// Add instance ID as an attribute for per-event queryability.
	attrs = append(attrs, stringKV("pipelock.instance", event.InstanceID))

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
		return otlpSeverityWarn, "WARN"
	case SeverityCritical:
		return otlpSeverityError, "ERROR"
	default:
		return otlpSeverityInfo, "INFO"
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
