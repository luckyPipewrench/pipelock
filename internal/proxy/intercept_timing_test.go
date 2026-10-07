// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// slowRT waits before answering, or until the request is canceled.
type slowRT struct {
	delay   time.Duration
	reached chan struct{}
}

func (s *slowRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if s.reached != nil {
		close(s.reached)
	}
	if trace := httptrace.ContextClientTrace(r.Context()); trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
	select {
	case <-time.After(s.delay):
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "text/plain")
	_, _ = rec.WriteString("ok")
	return rec.Result(), nil
}

func interceptTimingEntries(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e map[string]any
		if json.Unmarshal(line, &e) == nil && e["event"] == string(audit.EventInterceptHTTP) {
			out = append(out, e)
		}
	}
	return out
}

func runInterceptTiming(t *testing.T, cfg *config.Config, rt http.RoundTripper, ctx context.Context, target string) (map[string]any, int) {
	t.Helper()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{captureObs: capture.NopObserver{}, metrics: metrics.New()}
	p.cfgPtr.Store(cfg)
	handler := newInterceptHandler(&InterceptContext{
		TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc,
		Logger: logger, Metrics: metrics.New(), ClientIP: "203.0.113.10",
		RequestID: "intercept-timing", Proxy: p,
	}, rt)
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	logger.Close()
	entries := interceptTimingEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("intercept_http entries = %d, want exactly 1", len(entries))
	}
	return entries[0], w.Code
}

func timingConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.MaxResponseBytes = 1024 * 1024
	return cfg
}

func TestInterceptTiming_AllowedSplitsUpstreamWait(t *testing.T) {
	const delay = 150 * time.Millisecond
	e, code := runInterceptTiming(t, timingConfig(), &slowRT{delay: delay}, t.Context(), "https://api.vendor.example/health")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if e["status_code"] != float64(http.StatusOK) || e["size_bytes"] != float64(2) {
		t.Fatalf("status/size = %v/%v", e["status_code"], e["size_bytes"])
	}
	up, ok := e["upstream_ms"].(float64)
	if !ok || up < float64(delay.Milliseconds()) {
		t.Fatalf("upstream_ms = %v, want >= %d", e["upstream_ms"], delay.Milliseconds())
	}
	total, _ := e["duration_ms"].(float64)
	if total < up {
		t.Fatalf("duration_ms %v < upstream_ms %v", total, up)
	}
	if e["client_canceled"] != false {
		t.Fatalf("client_canceled = %v", e["client_canceled"])
	}
}

func TestInterceptTiming_BlockedBeforeUpstreamHasNoUpstreamWait(t *testing.T) {
	cfg := timingConfig()
	cfg.FetchProxy.Monitoring.Blocklist = []string{"api.vendor.example"}
	rt := &slowRT{reached: make(chan struct{})}
	e, code := runInterceptTiming(t, cfg, rt, t.Context(), "https://api.vendor.example/health")
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
	select {
	case <-rt.reached:
		t.Fatal("blocked request reached upstream")
	default:
	}
	if _, ok := e["upstream_ms"]; ok {
		t.Fatalf("upstream_ms present on a request blocked before upstream: %v", e)
	}
	if e["status_code"] != float64(http.StatusForbidden) {
		t.Fatalf("status_code = %v", e["status_code"])
	}
}

func TestInterceptTiming_ClientCancelWhileUpstreamWaits(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	rt := &slowRT{delay: time.Minute, reached: make(chan struct{})}
	go func() {
		<-rt.reached
		time.AfterFunc(100*time.Millisecond, cancel)
	}()
	e, _ := runInterceptTiming(t, timingConfig(), rt, ctx, "https://api.vendor.example/slow")
	if e["client_canceled"] != true {
		t.Fatalf("client_canceled = %v, want true", e["client_canceled"])
	}
	up, ok := e["upstream_ms"].(float64)
	if !ok || up < 100 {
		t.Fatalf("upstream_ms = %v, want the wait until cancel", e["upstream_ms"])
	}
}

// dialRefusedRT reports what the dial guard returns for a refused destination.
type dialRefusedRT struct{}

func (dialRefusedRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &ssrfDialBlockError{reason: blockreason.SSRFPrivateIP, detail: "test refusal"}
}

func TestInterceptTiming_DialRefusedHasNoUpstreamWait(t *testing.T) {
	e, code := runInterceptTiming(t, timingConfig(), dialRefusedRT{}, t.Context(), "https://api.vendor.example/health")
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
	if _, ok := e["upstream_ms"]; ok {
		t.Fatalf("upstream_ms present for a dial the guard refused: %v", e)
	}
}

func TestInterceptTiming_URLIsDestinationOnly(t *testing.T) {
	cfg := timingConfig()
	cfg.FetchProxy.Monitoring.Blocklist = []string{"api.vendor.example"}
	secret := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	e, _ := runInterceptTiming(t, cfg, &slowRT{}, t.Context(), "https://api.vendor.example/upload/"+secret+"?token="+secret)
	if e["url"] != "https://api.vendor.example:443" {
		t.Fatalf("url = %v, want destination only", e["url"])
	}
	raw, _ := json.Marshal(e)
	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("/upload")) {
		t.Fatalf("timing line carries request path or query: %s", raw)
	}
}

// failRT fails the round trip, optionally after reporting the request written.
type failRT struct{ wrote bool }

func (f failRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(r.Context()); f.wrote && trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
	return nil, errors.New("transport failure")
}

func TestInterceptTiming_UpstreamWaitFollowsRequestWrite(t *testing.T) {
	before, code := runInterceptTiming(t, timingConfig(), failRT{}, t.Context(), "https://api.vendor.example/a")
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", code)
	}
	if _, ok := before["upstream_ms"]; ok {
		t.Fatalf("upstream_ms present for a failure before the request was written: %v", before)
	}
	after, _ := runInterceptTiming(t, timingConfig(), failRT{wrote: true}, t.Context(), "https://api.vendor.example/a")
	if _, ok := after["upstream_ms"]; !ok {
		t.Fatalf("upstream_ms missing for a failure after the request was written: %v", after)
	}
}

func TestInterceptTimingWriter_Status(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &interceptTimingWriter{ResponseWriter: rec}
	if got := w.finalStatus(false); got != http.StatusOK {
		t.Fatalf("no write, client present: status %d, want implicit 200", got)
	}
	if got := w.finalStatus(true); got != 0 {
		t.Fatalf("no write, client gone: status %d, want 0", got)
	}
	w.WriteHeader(http.StatusEarlyHints)
	w.WriteHeader(http.StatusTeapot)
	if got := w.finalStatus(false); got != http.StatusTeapot {
		t.Fatalf("status %d, want final status after 1xx", got)
	}
}

// hijackRecorder is a recorder whose connection can be taken over.
type hijackRecorder struct{ *httptest.ResponseRecorder }

func (hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	client, server := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func TestInterceptTimingWriter_CommittedStatuses(t *testing.T) {
	w := &interceptTimingWriter{ResponseWriter: httptest.NewRecorder()}
	w.WriteHeader(http.StatusSwitchingProtocols)
	if got := w.finalStatus(false); got != http.StatusSwitchingProtocols {
		t.Fatalf("101 recorded as %d", got)
	}

	w = &interceptTimingWriter{ResponseWriter: httptest.NewRecorder()}
	w.Flush()
	if got := w.finalStatus(true); got != http.StatusOK {
		t.Fatalf("flush then cancel recorded as %d, want 200", got)
	}
}

func TestInterceptTimingWriter_Hijack(t *testing.T) {
	plain := &interceptTimingWriter{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := plain.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("hijack on a writer without support: err = %v", err)
	}
	w := &interceptTimingWriter{ResponseWriter: hijackRecorder{httptest.NewRecorder()}}
	var _ http.Hijacker = w
	conn, _, err := w.Hijack()
	if err != nil {
		t.Fatalf("hijack passthrough failed: %v", err)
	}
	_ = conn.Close()
	if got := w.finalStatus(false); got != http.StatusSwitchingProtocols {
		t.Fatalf("hijacked status %d, want 101", got)
	}
}

// slowHeadersRT reports the request written, then waits before answering.
type slowHeadersRT struct{ setup, wait time.Duration }

func (s slowHeadersRT) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case <-time.After(s.setup):
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	if trace := httptrace.ContextClientTrace(r.Context()); trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
	select {
	case <-time.After(s.wait):
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	rec := httptest.NewRecorder()
	_, _ = rec.WriteString("ok")
	return rec.Result(), nil
}

func TestInterceptTiming_UpstreamWaitExcludesSetup(t *testing.T) {
	e, _ := runInterceptTiming(t, timingConfig(), slowHeadersRT{setup: 300 * time.Millisecond, wait: 50 * time.Millisecond}, t.Context(), "https://api.vendor.example/a")
	up, ok := e["upstream_ms"].(float64)
	if !ok || up < 50 || up >= 300 {
		t.Fatalf("upstream_ms = %v, want the post-write wait only (50..300)", e["upstream_ms"])
	}
}

// failingHijacker supports hijacking but fails to take the connection.
type failingHijacker struct{ *httptest.ResponseRecorder }

func (failingHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("hijack failed")
}

func TestInterceptTimingWriter_FailedHijackKeepsStatus(t *testing.T) {
	w := &interceptTimingWriter{ResponseWriter: failingHijacker{httptest.NewRecorder()}}
	if _, _, err := w.Hijack(); err == nil {
		t.Fatal("hijack error was not propagated")
	}
	if got := w.finalStatus(true); got == http.StatusSwitchingProtocols {
		t.Fatalf("failed hijack recorded as %d", got)
	}
}

// retryRT reports two request writes, as a transport retry does.
type retryRT struct{ gap time.Duration }

func (rt retryRT) RoundTrip(r *http.Request) (*http.Response, error) {
	trace := httptrace.ContextClientTrace(r.Context())
	trace.WroteRequest(httptrace.WroteRequestInfo{})
	select {
	case <-time.After(rt.gap):
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	trace.WroteRequest(httptrace.WroteRequestInfo{})
	rec := httptest.NewRecorder()
	_, _ = rec.WriteString("ok")
	return rec.Result(), nil
}

func TestInterceptTiming_RetryKeepsFirstWrite(t *testing.T) {
	e, _ := runInterceptTiming(t, timingConfig(), retryRT{gap: 150 * time.Millisecond}, t.Context(), "https://api.vendor.example/a")
	up, ok := e["upstream_ms"].(float64)
	if !ok || up < 150 {
		t.Fatalf("upstream_ms = %v, want the wait from the first write (>= 150)", e["upstream_ms"])
	}
}
