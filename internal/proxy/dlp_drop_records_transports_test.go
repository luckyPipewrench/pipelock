// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	droppedTransportPattern = "Dropped Transport Test"
	droppedTransportValue   = "dropped-transport-test-value"
)

func TestInterceptBodyLowConfidenceDLPRecordsDropped(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	cache, pool, cfg, _, _, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: droppedTransportPattern, Regex: droppedTransportValue})
	cfg.Suppress = []config.SuppressEntry{{Rule: droppedTransportPattern, Path: "*"}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, false, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()
	addr := upstream.Listener.Addr().String()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/upload", strings.NewReader(droppedTransportValue))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want allow", resp.StatusCode)
	}
	logger.Close()
	assertDroppedTransportConsumers(t, m, auditPath, "body")
}

func TestReverseBodyLowConfidenceDLPRecordsDropped(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.DefaultAgentIdentity = "deployment/reverse-test"
	cfg.BindDefaultAgentIdentity = true
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: droppedTransportPattern, Regex: droppedTransportValue})
	cfg.Suppress = []config.SuppressEntry{{Rule: droppedTransportPattern, Path: "*"}}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	proxyServer, handler := reverseTestSetupWithHandler(t, cfg, func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "ok") })
	handler.logger.Close()
	logger, err := audit.New("json", "file", auditPath, false, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	handler.logger = logger
	defer logger.Close()
	reverseReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/upload", strings.NewReader(droppedTransportValue))
	if err != nil {
		t.Fatalf("new reverse request: %v", err)
	}
	reverseReq.Header.Set("Content-Type", "text/plain")
	resp, err := proxyServer.Client().Do(reverseReq)
	if err != nil {
		t.Fatalf("reverse request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want allow", resp.StatusCode)
	}
	logger.Close()
	assertDroppedTransportConsumers(t, handler.metrics, auditPath, "body")
	auditData, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatalf("read reverse audit: %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal(auditData, &entry); err != nil {
		t.Fatalf("decode reverse audit: %v", err)
	}
	for _, field := range []string{"client_ip", "request_id", "agent"} {
		if entry[field] == nil || entry[field] == "" {
			t.Fatalf("reverse dropped-DLP audit missing %s: %+v", field, entry)
		}
	}
}

func TestWebSocketBodyLowConfidenceDLPRecordsDropped(t *testing.T) {
	cfg := config.Defaults()
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: droppedTransportPattern, Regex: droppedTransportValue})
	cfg.Suppress = []config.SuppressEntry{{Rule: droppedTransportPattern, Path: "*"}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, false, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()
	p := &Proxy{logger: logger, metrics: metrics.New()}
	relay := &wsRelay{proxy: p, cfg: cfg, scanner: sc, maxMsg: cfg.WebSocketProxy.MaxMessageBytes, hostname: "socket.vendor.example", path: "/events", targetURL: "wss://socket.vendor.example/events", clientIP: "127.0.0.1", requestID: "dropped-ws"}
	_, result := relay.scanClientMessageBody(context.Background(), []byte(droppedTransportValue))
	if !result.Clean {
		t.Fatalf("frame verdict = %+v, want allow", result)
	}
	logger.Close()
	assertDroppedTransportConsumers(t, p.metrics, auditPath, "body")
}

func TestInterceptGenericSSELowConfidenceDLPRecordsDropped(t *testing.T) {
	cache, pool, cfg, _, _, m := testInterceptSetup(t)
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.SSEStreaming.Enabled = true
	cfg.ResponseScanning.SSEStreaming.Action = config.ActionBlock
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: droppedTransportPattern, Regex: droppedTransportValue})
	cfg.Suppress = []config.SuppressEntry{{Rule: droppedTransportPattern, Path: "*"}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, false, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()
	host, port := testLoopbackIP, "9999"
	rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: " + droppedTransportValue + "\n\n"))}, nil
	})
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+host+":"+port+"/events", nil)
	resp := interceptWithRT(t, cache, pool, cfg, sc, logger, m, rt, &InterceptContext{TargetHost: host, TargetPort: port}, req)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), droppedTransportValue) {
		t.Fatalf("SSE verdict changed: status=%d body=%q", resp.StatusCode, body)
	}
	logger.Close()
	assertDroppedTransportConsumers(t, m, auditPath, "mcp_sse")
}

func assertDroppedTransportConsumers(t *testing.T, m *metrics.Metrics, auditPath, surface string) {
	const reason = "suppressed"
	pattern := droppedTransportPattern
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), fmt.Sprintf(`pipelock_dlp_dropped_matches_total{pattern=%q,reason=%q,surface=%q} `, pattern, reason, surface)) {
		t.Fatalf("dropped DLP metric missing for %q/%q/%q", pattern, surface, reason)
	}
	b, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	for _, want := range []string{fmt.Sprintf(`"pattern":%q`, pattern), fmt.Sprintf(`"transport":%q`, surface), fmt.Sprintf(`"reason":%q`, reason)} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("audit missing %q: %s", want, b)
		}
	}
}
