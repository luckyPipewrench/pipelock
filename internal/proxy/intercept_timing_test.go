// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
