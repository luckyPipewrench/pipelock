// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
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
)

const (
	droppedHeaderPattern = "Dropped Header Test"
	droppedHeaderValue   = "dlp-drop-header-test-value"
	droppedSSEPattern    = "Dropped SSE Test"
	droppedSSEValue      = "dlp-drop-sse-test-value"
)

func TestForwardHeaderSuppressionRecordsDroppedDLP(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, false, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: droppedHeaderPattern, Regex: droppedHeaderValue})
		cfg.Suppress = []config.SuppressEntry{{Rule: droppedHeaderPattern, Path: "*"}}
	})
	defer cleanup()
	p.logger = logger

	resp, err := proxyClient(proxyAddr).Do(newDroppedDLPRequest(t, backend.URL, "X-Dropped-DLP", droppedHeaderValue))
	if err != nil {
		t.Fatalf("forward request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("suppressed header verdict = %d, want 200: %s", resp.StatusCode, body)
	}
	logger.Close()

	assertDroppedDLPConsumers(t, p, auditPath, droppedHeaderPattern, "header", "suppressed")
}

func TestForwardHeaderSuppressionRecordDoesNotChangeAllowOutcome(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	for _, observed := range []bool{false, true} {
		t.Run(fmt.Sprintf("observed=%t", observed), func(t *testing.T) {
			proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
				cfg.RequestBodyScanning.Action = config.ActionBlock
				cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: droppedHeaderPattern, Regex: droppedHeaderValue})
				cfg.Suppress = []config.SuppressEntry{{Rule: droppedHeaderPattern, Path: "*"}}
			})
			defer cleanup()
			if !observed {
				p.logger = audit.NewNop()
			}

			resp, err := proxyClient(proxyAddr).Do(newDroppedDLPRequest(t, backend.URL, "X-Dropped-DLP", droppedHeaderValue))
			if err != nil {
				t.Fatalf("forward request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("observed=%t status = %d, want 200: %s", observed, resp.StatusCode, body)
			}
		})
	}
}

func TestForwardGenericSSESuppressionRecordsDroppedDLP(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", droppedSSEValue)
	}))
	defer backend.Close()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, false, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.SSEStreaming.Enabled = true
		cfg.ResponseScanning.SSEStreaming.Action = config.ActionBlock
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: droppedSSEPattern, Regex: droppedSSEValue})
		cfg.Suppress = []config.SuppressEntry{{Rule: droppedSSEPattern, Path: "*"}}
	})
	defer cleanup()
	p.logger = logger

	resp, err := proxyClient(proxyAddr).Do(newDroppedDLPRequest(t, backend.URL+"/events", "", ""))
	if err != nil {
		t.Fatalf("forward SSE request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), droppedSSEValue) {
		t.Fatalf("suppressed SSE verdict changed: status=%d body=%q", resp.StatusCode, body)
	}
	logger.Close()

	assertDroppedDLPConsumers(t, p, auditPath, droppedSSEPattern, "mcp_sse", "suppressed")
}

func newDroppedDLPRequest(t *testing.T, target, header, value string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if header != "" {
		req.Header.Set(header, value)
	}
	return req
}

func assertDroppedDLPConsumers(t *testing.T, p *Proxy, auditPath, pattern, surface, reason string) {
	t.Helper()
	metricOut := httptest.NewRecorder()
	p.metrics.PrometheusHandler().ServeHTTP(metricOut, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	wantMetric := fmt.Sprintf(`pipelock_dlp_dropped_matches_total{pattern=%q,reason=%q,surface=%q} `, pattern, reason, surface)
	if !strings.Contains(metricOut.Body.String(), wantMetric) {
		t.Fatalf("dropped DLP metric missing %q: %s", wantMetric, metricOut.Body.String())
	}
	auditData, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	for _, want := range []string{fmt.Sprintf(`"pattern":%q`, pattern), fmt.Sprintf(`"transport":%q`, surface), fmt.Sprintf(`"reason":%q`, reason)} {
		if !strings.Contains(string(auditData), want) {
			t.Fatalf("dropped DLP audit record missing %q: %s", want, auditData)
		}
	}
}
