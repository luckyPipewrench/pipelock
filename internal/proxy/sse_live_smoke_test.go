// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build live

// Live-provider SSE smoke tests. Build-tagged out of the default test
// suite so CI does not require external API keys or network egress.
//
// Run manually after exporting the relevant provider credential into the
// shell environment (the variable names live in the per-provider config
// values further down this file). With the credential available:
//
//	go test -tags=live -run TestSSELiveAnthropicSmoke -v ./internal/proxy/
//	go test -tags=live -run TestSSELiveOpenAISmoke    -v ./internal/proxy/
//
// The shell-assignment form is intentionally NOT shown in this file so
// pipelock's own DLP scanner does not treat the example as a real
// secret leak in the diff.
//
// The smoke verifies three properties that a fully-mocked test cannot:
//
//  1. The reverse proxy actually streams a real provider's
//     text/event-stream response without truncation or buffering.
//  2. Token-by-token flush latency is preserved end-to-end.
//  3. The default response_scanning + sse_streaming config does NOT
//     misclassify legitimate model output as a finding.

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// liveProviderConfig describes one provider we know how to drive.
type liveProviderConfig struct {
	envVar     string
	baseURL    string
	endpoint   string
	authHeader string
	authValue  func(key string) string
	extraHdrs  map[string]string
	body       string
}

var anthropicLiveCfg = liveProviderConfig{
	envVar:     "ANTHROPIC_API_KEY",
	baseURL:    "https://api.anthropic.com",
	endpoint:   "/v1/messages",
	authHeader: "x-api-key",
	authValue:  func(key string) string { return key },
	extraHdrs: map[string]string{
		"anthropic-version": "2023-06-01",
		"content-type":      "application/json",
	},
	body: `{"model":"claude-haiku-4-5","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"Reply with exactly five distinct numbered tokens, one per line."}]}`,
}

var openaiLiveCfg = liveProviderConfig{
	envVar:     "OPENAI_API_KEY",
	baseURL:    "https://api.openai.com",
	endpoint:   "/v1/chat/completions",
	authHeader: "Authorization",
	authValue:  func(key string) string { return "Bearer " + key },
	extraHdrs: map[string]string{
		"content-type": "application/json",
	},
	body: `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"Reply with exactly five distinct numbered tokens, one per line."}]}`,
}

// runLiveSmoke spins up a pipelock reverse proxy fronting the named
// provider, opens a streaming chat completion, and asserts that
//   - response status is 200,
//   - at least three SSE events arrive,
//   - the first event arrives meaningfully earlier than the last,
//   - the default scanner config does not falsely block clean output.
//
// Skips if the provider's API key env var is not set.
func runLiveSmoke(t *testing.T, p liveProviderConfig) {
	t.Helper()

	apiKey := os.Getenv(p.envVar)
	if apiKey == "" {
		t.Skipf("%s not set, skipping live smoke", p.envVar)
	}

	upstreamURL, err := url.Parse(p.baseURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	cfg := config.Defaults()
	// cfg.Internal=nil disables SSRF blocking entirely; no allowlist needed.
	// The previous catch-all 0.0.0.0/0 / ::/0 allowlist was redundant and
	// would fail future config validation that rejects "everything-allowed"
	// shapes.
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionWarn
	cfg.ResponseScanning.SSEStreaming.Enabled = true
	cfg.ResponseScanning.SSEStreaming.Action = config.ActionWarn
	cfg.ApplyDefaults()

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	m := metrics.New()
	ks := killswitch.New(cfg)

	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, m, ks, nil, nil)
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxy.URL+p.endpoint, strings.NewReader(p.body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(p.authHeader, p.authValue(apiKey))
	req.Header.Set("accept", "text/event-stream")
	for k, v := range p.extraHdrs {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		t.Fatalf("upstream/proxy returned %d, body: %s", resp.StatusCode, body[:n])
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %q", resp.Header.Get("Content-Type"))
	}

	scannerR := bufio.NewScanner(resp.Body)
	scannerR.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		events    int
		firstSeen time.Time
		lastSeen  time.Time
		bodyDump  bytes.Buffer
	)
	for scannerR.Scan() {
		line := scannerR.Text()
		bodyDump.WriteString(line)
		bodyDump.WriteByte('\n')
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		now := time.Now()
		if events == 0 {
			firstSeen = now
		}
		lastSeen = now
		events++
	}
	if err := scannerR.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}

	if events < 3 {
		t.Fatalf("only saw %d SSE events; expected at least 3 from a streaming chat completion. body:\n%s",
			events, truncateBody(bodyDump.String(), 2000))
	}
	gap := lastSeen.Sub(firstSeen)
	if gap < 50*time.Millisecond {
		t.Errorf("first vs last event gap is %v — proxy may have buffered the response (expected ≥ 50ms for token-by-token flush)", gap)
	}
	t.Logf("live smoke OK: events=%d total_elapsed=%v first_to_last_gap=%v",
		events, time.Since(start), gap)

	if bytes.Contains(bodyDump.Bytes(), []byte(`"blocked":true`)) {
		t.Errorf("response body contains pipelock block marker; legitimate provider output was misclassified:\n%s",
			truncateBody(bodyDump.String(), 2000))
	}
}

// TestSSELiveAnthropicSmoke needs ANTHROPIC_API_KEY set and the live
// build tag enabled. Skipped otherwise.
func TestSSELiveAnthropicSmoke(t *testing.T) {
	runLiveSmoke(t, anthropicLiveCfg)
}

// TestSSELiveOpenAISmoke is the OpenAI variant. Skipped without
// OPENAI_API_KEY.
func TestSSELiveOpenAISmoke(t *testing.T) {
	runLiveSmoke(t, openaiLiveCfg)
}

func truncateBody(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
