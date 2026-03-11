// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	testCEEAWSKeyPrefix = "AKI" + "A"                               // split to avoid gosec G101
	testCEEAWSKeySuffix = "IOSFODNN7" + "EXAMPLE"                   // split to avoid gosec G101
	testCEEFakeAWSKey   = testCEEAWSKeyPrefix + testCEEAWSKeySuffix // full key for splitting
)

// testCEEProxy creates a proxy and test server with the given CEE config.
// The proxy is wired up as an httptest.Server so callers can send real HTTP
// requests through it. Returns the proxy server and a target backend server
// that the proxy can reach.
func testCEEProxy(t *testing.T, ceeCfg config.CrossRequestDetection) (*httptest.Server, *httptest.Server) {
	t.Helper()

	target := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(target.Close)

	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.CrossRequestDetection = ceeCfg
	cfg.ApplyDefaults()
	// Internal=nil disables SSRF checks for localhost test servers.
	cfg.Internal = nil
	cfg.APIAllowlist = nil

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	logger := audit.NewNop()
	m := metrics.New()

	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	ts := httptest.NewServer(p.Handler())
	t.Cleanup(ts.Close)

	return ts, target
}

// fetchThroughProxy sends a GET request to the proxy's /fetch endpoint,
// targeting the given URL. Returns the decoded FetchResponse and HTTP status.
func fetchThroughProxy(t *testing.T, proxyURL, targetURL string) (FetchResponse, int) {
	t.Helper()
	return fetchThroughProxyWithAgent(t, proxyURL, targetURL, "")
}

// fetchThroughProxyWithAgent is like fetchThroughProxy but sets the
// X-Pipelock-Agent header to simulate different agent identities.
func fetchThroughProxyWithAgent(t *testing.T, proxyURL, targetURL, agent string) (FetchResponse, int) {
	t.Helper()

	fetchURL := proxyURL + "/fetch?url=" + url.QueryEscape(targetURL)
	req, err := http.NewRequest(http.MethodGet, fetchURL, nil) //nolint:noctx // test one-shot
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if agent != "" {
		req.Header.Set("X-Pipelock-Agent", agent)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:noctx // test one-shot
	if err != nil {
		t.Fatalf("fetch request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var fr FetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	return fr, resp.StatusCode
}

// highEntropyString generates a string with approximately 1 bit of Shannon
// entropy per byte (all unique hex chars). Each byte contributes ~4 bits of
// entropy to the budget (log2(16) = 4 bits * uniform distribution).
func highEntropyString(length int) string {
	// Cycle through hex digits to create high-entropy content.
	const hexChars = "0123456789abcdef"
	var b strings.Builder
	b.Grow(length)
	for i := range length {
		_ = b.WriteByte(hexChars[i%len(hexChars)])
	}
	return b.String()
}

func TestCEEIntegration_EntropyBudgetBlock(t *testing.T) {
	// Configure a low entropy budget (256 bits) so we can exceed it quickly.
	// With high-entropy hex data, each byte contributes ~4 bits of entropy,
	// so ~64 bytes of hex data should approach the limit.
	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 256, // low budget to trigger quickly
			WindowMinutes: 5,
			Action:        config.ActionBlock,
		},
	}

	ts, target := testCEEProxy(t, ceeCfg)

	// Send requests with high-entropy query parameters until we exceed the budget.
	// Each request carries ~400 bits of entropy (100 hex chars * ~4 bits each),
	// so the second request should exceed the 256-bit budget.
	var blocked bool
	var blockReason string
	for i := range 10 {
		entropy := highEntropyString(100)
		targetURL := target.URL + fmt.Sprintf("?q=%s&i=%d", entropy, i)
		fr, status := fetchThroughProxy(t, ts.URL, targetURL)

		if fr.Blocked && status == http.StatusForbidden {
			blocked = true
			blockReason = fr.BlockReason
			break
		}
	}

	if !blocked {
		t.Fatal("expected entropy budget to be exceeded and request blocked")
	}
	if !strings.Contains(blockReason, "entropy budget exceeded") {
		t.Errorf("expected block reason to contain 'entropy budget exceeded', got %q", blockReason)
	}
}

func TestCEEIntegration_FragmentDLPDetection(t *testing.T) {
	// Enable fragment reassembly with zero debounce so scans happen immediately.
	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536, // 64KB buffer per session
			WindowMinutes:  5,
		},
	}

	ts, target := testCEEProxy(t, ceeCfg)

	// Split the fake AWS key across two requests as bare query tokens.
	// Bare tokens (no key=value) are a realistic exfiltration vector and
	// test that queryParamPayload includes valueless parameters.
	half := len(testCEEFakeAWSKey) / 2
	firstHalf := testCEEFakeAWSKey[:half]
	secondHalf := testCEEFakeAWSKey[half:]

	// Request 1: first fragment as bare query token (should pass).
	targetURL1 := target.URL + "?" + firstHalf
	fr1, status1 := fetchThroughProxy(t, ts.URL, targetURL1)
	if fr1.Blocked {
		t.Fatalf("first fragment should not be blocked, got status %d reason %q", status1, fr1.BlockReason)
	}

	// Request 2: second fragment completes the key (should be caught).
	targetURL2 := target.URL + "?" + secondHalf
	fr2, status2 := fetchThroughProxy(t, ts.URL, targetURL2)
	if !fr2.Blocked {
		t.Fatal("expected fragment reassembly to detect split AWS key")
	}
	if status2 != http.StatusForbidden {
		t.Errorf("expected 403 for fragment DLP, got %d", status2)
	}
	if !strings.Contains(fr2.BlockReason, "cross-request secret detected") {
		t.Errorf("expected block reason to contain 'cross-request secret detected', got %q", fr2.BlockReason)
	}
}

func TestCEEIntegration_FragmentDLPKeyValueSplit(t *testing.T) {
	// Regression test: secret split across key=value params (not bare tokens).
	// queryParamPayload extracts values only, so "data=AKIA" + "data=IOSF..."
	// produces contiguous "AKIA" + "IOSF..." in the fragment buffer.
	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
	}

	ts, target := testCEEProxy(t, ceeCfg)

	half := len(testCEEFakeAWSKey) / 2
	firstHalf := testCEEFakeAWSKey[:half]
	secondHalf := testCEEFakeAWSKey[half:]

	// Request 1: first fragment as key=value param (should pass).
	targetURL1 := target.URL + "?data=" + firstHalf
	fr1, status1 := fetchThroughProxy(t, ts.URL, targetURL1)
	if fr1.Blocked {
		t.Fatalf("first fragment should not be blocked, got status %d reason %q", status1, fr1.BlockReason)
	}

	// Request 2: second fragment as key=value param (should be caught).
	// Values "AKIA..." + "IOSF..." are contiguous because keys are excluded.
	targetURL2 := target.URL + "?data=" + secondHalf
	fr2, status2 := fetchThroughProxy(t, ts.URL, targetURL2)
	if !fr2.Blocked {
		t.Fatal("expected fragment reassembly to detect split AWS key in key=value params")
	}
	if status2 != http.StatusForbidden {
		t.Errorf("expected 403 for fragment DLP, got %d", status2)
	}
	if !strings.Contains(fr2.BlockReason, "cross-request secret detected") {
		t.Errorf("expected block reason to contain 'cross-request secret detected', got %q", fr2.BlockReason)
	}
}

func TestCEEIntegration_FragmentDLPKeySplit(t *testing.T) {
	// Regression: secret split across query parameter KEYS (not values).
	// ?AKIA=1 followed by ?IOSFODNN7EXAMPLE=2 must be caught by the key
	// fragment stream in ceeAdmit.
	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
	}

	ts, target := testCEEProxy(t, ceeCfg)

	half := len(testCEEFakeAWSKey) / 2
	firstHalf := testCEEFakeAWSKey[:half]
	secondHalf := testCEEFakeAWSKey[half:]

	// Request 1: first half of secret as parameter key name.
	targetURL1 := target.URL + "?" + firstHalf + "=1"
	fr1, status1 := fetchThroughProxy(t, ts.URL, targetURL1)
	if fr1.Blocked {
		t.Fatalf("first key fragment should not be blocked, got status %d reason %q", status1, fr1.BlockReason)
	}

	// Request 2: second half of secret as parameter key name.
	targetURL2 := target.URL + "?" + secondHalf + "=2"
	fr2, status2 := fetchThroughProxy(t, ts.URL, targetURL2)
	if !fr2.Blocked {
		t.Fatal("expected fragment reassembly to detect split AWS key in parameter names")
	}
	if status2 != http.StatusForbidden {
		t.Errorf("expected 403 for key-split fragment DLP, got %d", status2)
	}
	if !strings.Contains(fr2.BlockReason, "cross-request secret detected") {
		t.Errorf("expected block reason to contain 'cross-request secret detected', got %q", fr2.BlockReason)
	}
}

func TestCEEIntegration_SessionIsolation(t *testing.T) {
	// Enable fragment reassembly to verify session isolation.
	// Session key is based on clientIP, so different RemoteAddr values
	// create different sessions. We use httptest.NewRecorder to control
	// the RemoteAddr per request.
	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
	}

	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.CrossRequestDetection = ceeCfg
	cfg.ApplyDefaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	target := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(target.Close)

	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	handler := p.Handler()

	half := len(testCEEFakeAWSKey) / 2
	firstHalf := testCEEFakeAWSKey[:half]
	secondHalf := testCEEFakeAWSKey[half:]

	// Send first half from client A (10.0.0.1) as bare query token.
	targetURL1 := target.URL + "?" + firstHalf
	req1 := httptest.NewRequest(http.MethodGet, "/fetch?url="+url.QueryEscape(targetURL1), nil)
	req1.RemoteAddr = "10.0.0.1:12345"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	var fr1 FetchResponse
	if err := json.NewDecoder(w1.Body).Decode(&fr1); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	if fr1.Blocked {
		t.Fatalf("first half to session A should not be blocked: %q", fr1.BlockReason)
	}

	// Send second half from client B (10.0.0.2) as bare query token.
	// Different session, so fragment buffers are isolated.
	targetURL2 := target.URL + "?" + secondHalf
	req2 := httptest.NewRequest(http.MethodGet, "/fetch?url="+url.QueryEscape(targetURL2), nil)
	req2.RemoteAddr = "10.0.0.2:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	var fr2 FetchResponse
	if err := json.NewDecoder(w2.Body).Decode(&fr2); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if fr2.Blocked {
		t.Fatalf("second half to session B should not be blocked (sessions are isolated): %q", fr2.BlockReason)
	}
}

func TestCEEIntegration_KeyEntropyBudgetBlock(t *testing.T) {
	// High-entropy data in query parameter keys (not values) must still
	// trigger entropy budget. Covers the full HTTP path: fetch handler →
	// queryParamKeys → ceeAdmit → et.Record.
	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 256, // low budget
			WindowMinutes: 5,
			Action:        config.ActionBlock,
		},
	}

	ts, target := testCEEProxy(t, ceeCfg)

	var blocked bool
	var blockReason string
	for i := range 10 {
		entropy := highEntropyString(100)
		// Secret data in key names, trivial values.
		targetURL := target.URL + fmt.Sprintf("?%s=%d", entropy, i)
		fr, status := fetchThroughProxy(t, ts.URL, targetURL)
		if fr.Blocked && status == http.StatusForbidden {
			blocked = true
			blockReason = fr.BlockReason
			break
		}
	}

	if !blocked {
		t.Fatal("expected entropy budget to be exceeded from key-only entropy")
	}
	if !strings.Contains(blockReason, "entropy budget exceeded") {
		t.Errorf("expected block reason to contain 'entropy budget exceeded', got %q", blockReason)
	}
}

func TestCEEIntegration_FalsePositiveResilience(t *testing.T) {
	// Use the default 4096-bit budget. Legitimate traffic should stay under.
	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 4096, // default generous budget
			WindowMinutes: 5,
			Action:        config.ActionBlock,
		},
	}

	ts, target := testCEEProxy(t, ceeCfg)

	// Send 5 requests with moderate-entropy content (short random-looking
	// strings simulating normal query parameters like UUIDs or session tokens).
	// Each has ~128 bits of entropy, totaling ~640 bits, well under 4096.
	legitimateQueries := []string{
		"search=golang+http+proxy",
		"page=3&sort=name&order=asc",
		"id=abc123def456&format=json",
		"ref=session_ref_42&lang=en",
		"filter=active&limit=50&offset=100",
	}

	for _, q := range legitimateQueries {
		targetURL := target.URL + "?" + q
		fr, status := fetchThroughProxy(t, ts.URL, targetURL)
		if fr.Blocked {
			t.Errorf("legitimate query %q should not be blocked: status=%d reason=%q",
				q, status, fr.BlockReason)
		}
		if status != http.StatusOK {
			t.Errorf("legitimate query %q: expected status 200, got %d", q, status)
		}
	}
}

func TestCEEIntegration_WarnMode(t *testing.T) {
	// Configure both entropy budget and fragment DLP in warn mode.
	// Requests should be allowed (200 OK) even when thresholds are crossed.
	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionWarn, // fragment DLP in warn mode
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 256, // low budget, will be exceeded
			WindowMinutes: 5,
			Action:        config.ActionWarn, // entropy in warn mode
		},
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
	}

	ts, target := testCEEProxy(t, ceeCfg)

	// Exceed entropy budget with high-entropy payloads.
	for i := range 5 {
		entropy := highEntropyString(200)
		targetURL := target.URL + fmt.Sprintf("?q=%s&i=%d", entropy, i)
		fr, status := fetchThroughProxy(t, ts.URL, targetURL)
		if fr.Blocked {
			t.Errorf("warn mode should not block entropy exceedance: status=%d reason=%q",
				status, fr.BlockReason)
		}
		if status == http.StatusForbidden {
			t.Errorf("expected 200 in warn mode, got %d", status)
		}
	}

	// Split a fake AWS key across requests as bare tokens (should warn, not block).
	half := len(testCEEFakeAWSKey) / 2
	firstHalf := testCEEFakeAWSKey[:half]
	secondHalf := testCEEFakeAWSKey[half:]

	targetURL1 := target.URL + "?" + firstHalf
	fr1, status1 := fetchThroughProxy(t, ts.URL, targetURL1)
	if fr1.Blocked {
		t.Fatalf("warn mode: first fragment should not block: %q", fr1.BlockReason)
	}
	if status1 != http.StatusOK {
		t.Errorf("warn mode: first fragment expected status 200, got %d", status1)
	}

	targetURL2 := target.URL + "?" + secondHalf
	fr2, status2 := fetchThroughProxy(t, ts.URL, targetURL2)
	if fr2.Blocked {
		t.Fatalf("warn mode: fragment DLP match should not block: %q", fr2.BlockReason)
	}
	if status2 != http.StatusOK {
		t.Errorf("warn mode: fragment DLP expected status 200, got %d", status2)
	}
}
