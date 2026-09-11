// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	driftCardV1 = `{"name":"Vendor Agent","description":"does things","version":"1.0","skills":[{"id":"s1","name":"search","description":"ok"}]}`
	driftCardV2 = `{"name":"Vendor Agent","description":"does useful things","version":"1.1","skills":[{"id":"s1","name":"search","description":"ok"}]}`
)

// TestForwardHTTP_AgentCardBenignDriftAdopted proves the forward-proxy surface
// adopts a description-only card change instead of blocking it: the second
// fetch of a changed card is still 200.
func TestForwardHTTP_AgentCardBenignDriftAdopted(t *testing.T) {
	var fetches atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/a2a+json")
		if fetches.Add(1) == 1 {
			_, _ = io.WriteString(w, driftCardV1)
			return
		}
		_, _ = io.WriteString(w, driftCardV2)
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.A2AScanning.Enabled = true
		cfg.A2AScanning.Action = config.ActionBlock
		cfg.A2AScanning.ScanAgentCards = false
		cfg.A2AScanning.DetectCardDrift = true
	})
	defer cleanup()

	for i := 1; i <= 2; i++ {
		resp := doGet(t, proxyClient(proxyAddr), backend.URL+agentCardPath)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("fetch %d: benign card drift must be adopted (200), got %d: %s", i, resp.StatusCode, body)
		}
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("backend fetches = %d, want 2", got)
	}
}

// TestIntercept_AgentCardBenignDriftAdoptedAndAudited proves the TLS-intercept
// surface adopts a description-only card change and writes the adoption to the
// audit log, so the silent baseline update is operator-visible.
func TestIntercept_AgentCardBenignDriftAdoptedAndAudited(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = config.ActionBlock
	cfg.A2AScanning.ScanAgentCards = false
	cfg.A2AScanning.DetectCardDrift = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", logPath, true, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	serve := func(card string) int {
		rt := roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"application/a2a+json"}},
				Body:          io.NopCloser(bytes.NewReader([]byte(card))),
				ContentLength: int64(len(card)),
			}, nil
		})
		handler := newInterceptHandler(&InterceptContext{
			TargetHost: interceptCardHost,
			TargetPort: "443",
			Config:     cfg,
			Scanner:    sc,
			Logger:     logger,
			Metrics:    m,
			ClientIP:   testLoopbackIP,
			RequestID:  "intercept-card-drift",
			Agent:      "test-agent",
			Proxy:      p,
		}, rt)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"https://"+interceptCardHost+agentCardPath, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	if code := serve(driftCardV1); code != http.StatusOK {
		t.Fatalf("first card fetch must pass (200), got %d", code)
	}
	if code := serve(driftCardV2); code != http.StatusOK {
		t.Fatalf("benign card drift over intercept must be adopted (200), got %d", code)
	}
	logger.Close()
	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(data), "descriptive drift adopted") {
		t.Fatalf("adopted drift was not audited over intercept:\n%s", data)
	}
}
