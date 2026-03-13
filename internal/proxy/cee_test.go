// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"io"
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
	testCEEClientIP   = "10.0.0.1"
	testCEEAgent      = "test-agent"
	testCEERequestID  = "req-001"
	testCEESessionKey = "test-session"
	testCEEParamValue = "value"
)

func TestCeeSessionKey_WithAgent(t *testing.T) {
	got := ceeSessionKey(testCEEAgent, testCEEClientIP)
	want := testCEEAgent + "|" + testCEEClientIP
	if got != want {
		t.Errorf("ceeSessionKey(%q, %q) = %q, want %q", testCEEAgent, testCEEClientIP, got, want)
	}
}

func TestCeeSessionKey_EmptyAgent(t *testing.T) {
	got := ceeSessionKey("", testCEEClientIP)
	if got != testCEEClientIP {
		t.Errorf("ceeSessionKey(%q, %q) = %q, want %q", "", testCEEClientIP, got, testCEEClientIP)
	}
}

func TestCeeSessionKey_AnonymousAgent(t *testing.T) {
	got := ceeSessionKey(agentAnonymous, testCEEClientIP)
	if got != testCEEClientIP {
		t.Errorf("ceeSessionKey(%q, %q) = %q, want %q", agentAnonymous, testCEEClientIP, got, testCEEClientIP)
	}
}

func TestExtractOutboundPayload_QueryParams(t *testing.T) {
	// Keys are intentionally out of alphabetical order to prove wire-order extraction.
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "other=data&key=secret_value",
		},
	}
	payload := extractOutboundPayload(r)
	got := string(payload)

	// Wire order preserved, values only (keys excluded for fragment contiguity).
	want := "datasecret_value"
	if got != want {
		t.Errorf("extractOutboundPayload = %q, want %q", got, want)
	}
}

func TestExtractOutboundPayload_Body(t *testing.T) {
	body := "request body content"
	r := &http.Request{
		URL:           &url.URL{},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	payload := extractOutboundPayload(r)
	got := string(payload)
	if got != body {
		t.Errorf("extractOutboundPayload = %q, want %q", got, body)
	}

	// Body must still be readable after extraction (re-wrapping).
	remaining, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading body after extraction: %v", err)
	}
	if string(remaining) != body {
		t.Errorf("body after extraction = %q, want %q", string(remaining), body)
	}
}

func TestExtractOutboundPayload_QueryAndBody(t *testing.T) {
	body := "body-data"
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "q=query-data",
		},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	payload := extractOutboundPayload(r)
	got := string(payload)

	// Query values first, then body, concatenated without separator.
	want := "query-data" + body
	if got != want {
		t.Errorf("extractOutboundPayload = %q, want %q", got, want)
	}

	// Body must still be readable after extraction (re-wrapping).
	remaining, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading body after extraction: %v", err)
	}
	if string(remaining) != body {
		t.Errorf("body after extraction = %q, want %q", string(remaining), body)
	}
}

func TestExtractOutboundPayload_NoQueryNoBody(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{},
	}
	payload := extractOutboundPayload(r)
	if len(payload) != 0 {
		t.Errorf("expected empty payload, got %q", string(payload))
	}
}

func TestExtractOutboundPayload_NilBody(t *testing.T) {
	r := &http.Request{
		URL:  &url.URL{},
		Body: nil,
	}
	payload := extractOutboundPayload(r)
	if len(payload) != 0 {
		t.Errorf("expected empty payload for nil body, got %q", string(payload))
	}
}

func TestExtractOutboundPayload_ZeroContentLength(t *testing.T) {
	// ContentLength == 0 should skip body reading even if Body is non-nil.
	r := &http.Request{
		URL:           &url.URL{},
		Body:          io.NopCloser(strings.NewReader("should not be read")),
		ContentLength: 0,
	}
	payload := extractOutboundPayload(r)
	if len(payload) != 0 {
		t.Errorf("expected empty payload for zero content-length, got %q", string(payload))
	}
}

func TestCeeRecordSignals_BothHits(t *testing.T) {
	cfg := &config.SessionProfiling{
		Enabled:                true,
		AnomalyAction:          "warn",
		DomainBurst:            5,
		WindowMinutes:          5,
		VolumeSpikeRatio:       3.0,
		MaxSessions:            100,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 60,
	}
	m := metrics.New()
	sm := NewSessionManager(cfg, m)
	defer sm.Close()

	logger, _ := audit.New("json", "stdout", "", false, false)

	result := ceeResult{
		EntropyHit:  true,
		FragmentHit: true,
	}

	// Use a low threshold so signals trigger escalation.
	// SignalEntropyBudget = 2 points, SignalFragmentDLP = 3 points.
	// Total = 5 points, threshold = 1.0, so escalation should happen.
	threshold := 1.0
	ceeRecordSignals(result, sm, testCEESessionKey, threshold, logger, m, testCEEClientIP, testCEERequestID)

	sess := sm.GetOrCreate(testCEESessionKey)
	score := sess.ThreatScore()
	// SignalEntropyBudget (2) + SignalFragmentDLP (3) = 5 points exactly.
	if score != 5.0 {
		t.Errorf("expected threat score 5.0, got %.1f", score)
	}
}

func TestCeeRecordSignals_NoHits(t *testing.T) {
	cfg := &config.SessionProfiling{
		Enabled:                true,
		AnomalyAction:          "warn",
		DomainBurst:            5,
		WindowMinutes:          5,
		VolumeSpikeRatio:       3.0,
		MaxSessions:            100,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 60,
	}
	m := metrics.New()
	sm := NewSessionManager(cfg, m)
	defer sm.Close()

	logger, _ := audit.New("json", "stdout", "", false, false)

	result := ceeResult{
		EntropyHit:  false,
		FragmentHit: false,
	}

	ceeRecordSignals(result, sm, testCEESessionKey, 5.0, logger, m, testCEEClientIP, testCEERequestID)

	sess := sm.GetOrCreate(testCEESessionKey)
	score := sess.ThreatScore()
	if score != 0 {
		t.Errorf("expected threat score 0 for no hits, got %.1f", score)
	}
}

func TestCeeRecordSignals_NilSessionManager(t *testing.T) {
	// Nil session manager should be a no-op (no panic).
	result := ceeResult{EntropyHit: true, FragmentHit: true}
	ceeRecordSignals(result, nil, testCEESessionKey, 5.0, nil, nil, testCEEClientIP, testCEERequestID)
}

// --- ceeAdmit unit tests ---

func TestCeeAdmit_EmptyOutbound(t *testing.T) {
	// Empty outbound should return clean result immediately.
	ceeCfg := config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{Enabled: true},
	}
	result := ceeAdmit(context.Background(),
		testCEESessionKey, nil, nil, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, nil, nil, nil, nil,
	)
	if result.Blocked || result.EntropyHit || result.FragmentHit {
		t.Error("expected clean result for empty outbound")
	}

	// Also test zero-length slice.
	result = ceeAdmit(context.Background(),
		testCEESessionKey, []byte{}, nil, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, nil, nil, nil, nil,
	)
	if result.Blocked || result.EntropyHit || result.FragmentHit {
		t.Error("expected clean result for zero-length outbound")
	}
}

func TestCeeAdmit_EntropyBudgetBlock(t *testing.T) {
	// 1-bit budget: any real payload exceeds immediately.
	et := scanner.NewEntropyTracker(1.0, 300)
	defer et.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: 5,
			Action:        config.ActionBlock,
		},
	}

	payload := []byte("some outbound data with entropy")
	result := ceeAdmit(context.Background(),
		testCEESessionKey, payload, nil, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, et, nil, nil, logger, m,
	)
	if !result.Blocked {
		t.Fatal("expected block on entropy budget exceeded")
	}
	if !result.EntropyHit {
		t.Error("expected EntropyHit = true")
	}
	if result.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestCeeAdmit_EntropyBudgetWarn(t *testing.T) {
	// Warn mode: detect but don't block.
	et := scanner.NewEntropyTracker(1.0, 300)
	defer et.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: 5,
			Action:        config.ActionWarn,
		},
	}

	payload := []byte("outbound data that exceeds budget")
	result := ceeAdmit(context.Background(),
		testCEESessionKey, payload, nil, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, et, nil, nil, logger, m,
	)
	if result.Blocked {
		t.Error("expected no block in warn mode")
	}
	if !result.EntropyHit {
		t.Error("expected EntropyHit = true even in warn mode")
	}
}

func TestCeeAdmit_FragmentDLPBlock(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	defer sc.Close()

	fb := scanner.NewFragmentBuffer(65536, 1000, 300)
	defer fb.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
		Action: config.ActionBlock,
	}

	// Split fake AWS key across two ceeAdmit calls.
	part1 := "AKI" + "A"
	part2 := "IOSF" + "ODNN7EXAMPLE"

	result1 := ceeAdmit(context.Background(),
		testCEESessionKey, []byte(part1), nil, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, fb, sc, logger, m,
	)
	if result1.Blocked {
		t.Fatal("first fragment should not block")
	}

	result2 := ceeAdmit(context.Background(),
		testCEESessionKey, []byte(part2), nil, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, fb, sc, logger, m,
	)
	if !result2.Blocked {
		t.Fatal("expected block after fragment reassembly completes secret")
	}
	if !result2.FragmentHit {
		t.Error("expected FragmentHit = true")
	}
}

func TestCeeAdmit_FragmentDLPWarn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	defer sc.Close()

	fb := scanner.NewFragmentBuffer(65536, 1000, 300)
	defer fb.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
		Action: config.ActionWarn, // warn, not block
	}

	// Full fake AWS key in one shot to trigger DLP match.
	fakeKey := "AKI" + "A" + "IOSF" + "ODNN7EXAMPLE"
	result := ceeAdmit(context.Background(),
		testCEESessionKey, []byte(fakeKey), nil, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, fb, sc, logger, m,
	)
	if result.Blocked {
		t.Error("expected no block in warn mode")
	}
	if !result.FragmentHit {
		t.Error("expected FragmentHit = true even in warn mode")
	}
}

func TestCeeAdmit_BothEntropyAndFragment(t *testing.T) {
	// When entropy is warn and fragment is block, entropy fires first (warn,
	// no block), then fragment fires and blocks.
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	defer sc.Close()

	et := scanner.NewEntropyTracker(1.0, 300) // tiny budget
	defer et.Close()
	fb := scanner.NewFragmentBuffer(65536, 1000, 300)
	defer fb.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: 5,
			Action:        config.ActionWarn, // entropy warns
		},
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
		Action: config.ActionBlock, // fragment blocks
	}

	fakeKey := "AKI" + "A" + "IOSF" + "ODNN7EXAMPLE"
	result := ceeAdmit(context.Background(),
		testCEESessionKey, []byte(fakeKey), nil, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, et, fb, sc, logger, m,
	)
	// Entropy should have hit (warn, no block), then fragment should block.
	if !result.EntropyHit {
		t.Error("expected EntropyHit = true")
	}
	if !result.FragmentHit {
		t.Error("expected FragmentHit = true")
	}
	if !result.Blocked {
		t.Error("expected block from fragment DLP")
	}
	if result.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

// --- updateCEEStats tests ---

func TestUpdateCEEStats_WithTrackerAndBuffer(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	// Hit the /stats endpoint and parse CEE data from JSON.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	m.StatsHandler().ServeHTTP(rec, req)

	var resp struct {
		CEE metrics.CEEStats `json:"cross_request_detection"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if !resp.CEE.EntropyTrackerActive {
		t.Error("expected EntropyTrackerActive = true")
	}
	if !resp.CEE.FragmentBufferActive {
		t.Error("expected FragmentBufferActive = true")
	}
	if resp.CEE.FragmentBufferBytes != 0 {
		t.Errorf("expected 0 fragment bytes, got %d", resp.CEE.FragmentBufferBytes)
	}
}

func TestUpdateCEEStats_Disabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.CrossRequestDetection.Enabled = false

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	m.StatsHandler().ServeHTTP(rec, req)

	var resp struct {
		CEE metrics.CEEStats `json:"cross_request_detection"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if resp.CEE.EntropyTrackerActive {
		t.Error("expected EntropyTrackerActive = false when disabled")
	}
	if resp.CEE.FragmentBufferActive {
		t.Error("expected FragmentBufferActive = false when disabled")
	}
}

// --- queryParamPayload determinism test ---

func TestQueryParamPayload_WireOrder(t *testing.T) {
	// Keys in reverse alphabetical order to prove wire-order preservation.
	u := &url.URL{RawQuery: "z=last&a=first&m=middle"}
	payload := queryParamPayload(u)
	got := string(payload)

	// Wire order preserved, values only (keys excluded for fragment contiguity).
	want := "lastfirstmiddle"
	if got != want {
		t.Errorf("queryParamPayload = %q, want %q (wire order)", got, want)
	}
}

func TestQueryParamPayload_MultipleValues(t *testing.T) {
	u := &url.URL{RawQuery: "k=v1&k=v2&k=v3"}
	payload := queryParamPayload(u)
	got := string(payload)

	// Values only: "v1" + "v2" + "v3".
	want := "v1v2v3"
	if got != want {
		t.Errorf("queryParamPayload = %q, want %q", got, want)
	}
}

func TestQueryParamPayload_Empty(t *testing.T) {
	u := &url.URL{}
	payload := queryParamPayload(u)
	if payload != nil {
		t.Errorf("expected nil for empty query, got %q", string(payload))
	}
}

// --- queryParamKeys tests ---

func TestQueryParamKeys_WireOrder(t *testing.T) {
	u := &url.URL{RawQuery: "z=last&a=first&m=middle"}
	got := string(queryParamKeys(u))
	want := "zam"
	if got != want {
		t.Errorf("queryParamKeys = %q, want %q (wire order)", got, want)
	}
}

func TestQueryParamKeys_BareTokenExcluded(t *testing.T) {
	// Bare tokens (no '=') are handled by queryParamPayload, not keys.
	u := &url.URL{RawQuery: "baretoken&key=val"}
	got := string(queryParamKeys(u))
	want := "key"
	if got != want {
		t.Errorf("queryParamKeys = %q, want %q (bare tokens excluded)", got, want)
	}
}

func TestQueryParamKeys_SecretInKeys(t *testing.T) {
	// Secret split across parameter keys: ?AKIA=1&IOSFODNN7EXAMPLE=2
	u := &url.URL{RawQuery: "AKI" + "A" + "=1&" + "IOSF" + "ODNN7EXAMPLE" + "=2"}
	got := string(queryParamKeys(u))
	want := "AKI" + "A" + "IOSF" + "ODNN7EXAMPLE"
	if got != want {
		t.Errorf("queryParamKeys = %q, want %q (secret in keys)", got, want)
	}
}

func TestQueryParamKeys_Empty(t *testing.T) {
	u := &url.URL{}
	keys := queryParamKeys(u)
	if keys != nil {
		t.Errorf("expected nil for empty query, got %q", string(keys))
	}
}

func TestQueryParamKeys_EmptyKeyNames(t *testing.T) {
	// =val has empty key, should be skipped.
	u := &url.URL{RawQuery: "=val&k=v"}
	got := string(queryParamKeys(u))
	want := "k"
	if got != want {
		t.Errorf("queryParamKeys = %q, want %q", got, want)
	}
}

// --- ceeAdmit key-fragment reconstruction test ---

func TestCeeAdmit_KeyFragmentDLPBlock(t *testing.T) {
	// Secret split across query parameter keys, detected via key-fragment
	// stream in ceeAdmit. Simulates ?AKIA=1 then ?IOSFODNN7EXAMPLE=2.
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	defer sc.Close()

	fb := scanner.NewFragmentBuffer(65536, 1000, 300)
	defer fb.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
		Action: config.ActionBlock,
	}

	keyPart1 := []byte("AKI" + "A")
	keyPart2 := []byte("IOSF" + "ODNN7EXAMPLE")

	// Request 1: first key fragment.
	result1 := ceeAdmit(context.Background(),
		testCEESessionKey, []byte("1"), keyPart1, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, fb, sc, logger, m,
	)
	if result1.Blocked {
		t.Fatal("first key fragment should not block")
	}

	// Request 2: second key fragment completes the secret.
	result2 := ceeAdmit(context.Background(),
		testCEESessionKey, []byte("2"), keyPart2, "http://example.com", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, fb, sc, logger, m,
	)
	if !result2.Blocked {
		t.Fatal("expected block after key-fragment reassembly completes secret")
	}
	if !result2.FragmentHit {
		t.Error("expected FragmentHit = true")
	}
}

func TestCeeAdmit_KeyEntropyTracked(t *testing.T) {
	// High-entropy query keys (not matching DLP patterns) must still trigger
	// entropy budget. Without this, ?x7k9mQ2pR4wL8nJ5=1 contributes zero
	// entropy even though the key carries the exfiltrated data.
	et := scanner.NewEntropyTracker(1.0, 300) // 1-bit budget
	defer et.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: 5,
			Action:        config.ActionBlock,
		},
	}

	// keyPayload carries all the entropy; outbound value is just "1".
	keyPayload := []byte("x7k9mQ2pR4wL8nJ5vB3cT6yH0")
	result := ceeAdmit(context.Background(),
		testCEESessionKey, []byte("1"), keyPayload, "http://example.com",
		testCEEAgent, testCEEClientIP, testCEERequestID, ceeCfg, et, nil, nil, logger, m,
	)
	if !result.Blocked {
		t.Fatal("expected block: high-entropy key payload should exceed 1-bit budget")
	}
	if !result.EntropyHit {
		t.Error("expected EntropyHit = true")
	}
}

// --- urlPayload tests ---

func TestUrlPayload_PathAndQuery(t *testing.T) {
	// Path is excluded to prevent repeated paths from breaking DLP contiguity.
	u := &url.URL{Path: "/api/v1/tokens", RawQuery: "key=value"}
	got := string(urlPayload(u))
	want := testCEEParamValue
	if got != want {
		t.Errorf("urlPayload = %q, want %q", got, want)
	}
}

func TestUrlPayload_PathOnly(t *testing.T) {
	// Path-only URLs produce nil payload (path excluded from fragment buffer).
	u := &url.URL{Path: "/api/data"}
	payload := urlPayload(u)
	if payload != nil {
		t.Errorf("expected nil for path-only URL, got %q", string(payload))
	}
}

func TestUrlPayload_RootPathOnly(t *testing.T) {
	// Bare root "/" is excluded (no useful payload).
	u := &url.URL{Path: "/"}
	payload := urlPayload(u)
	if payload != nil {
		t.Errorf("expected nil for root path, got %q", string(payload))
	}
}

func TestUrlPayload_QueryOnly(t *testing.T) {
	u := &url.URL{RawQuery: "a=1&b=2"}
	got := string(urlPayload(u))
	want := "12"
	if got != want {
		t.Errorf("urlPayload = %q, want %q", got, want)
	}
}

func TestExtractOutboundPayload_ExcludesPath(t *testing.T) {
	// Path is excluded to prevent repeated paths from breaking DLP contiguity.
	r := &http.Request{
		URL: &url.URL{
			Path:     "/api/secret-data",
			RawQuery: "key=value",
		},
	}
	payload := extractOutboundPayload(r)
	got := string(payload)
	want := testCEEParamValue
	if got != want {
		t.Errorf("extractOutboundPayload = %q, want %q", got, want)
	}
}

// --- Path-split secret regression tests ---

func TestCeeAdmit_PathContributesToEntropy(t *testing.T) {
	// Tests ceeAdmit directly with path-containing payload. HTTP handlers
	// no longer include paths in the payload, but this validates ceeAdmit
	// entropy tracking works for any input data shape.
	et := scanner.NewEntropyTracker(1.0, 300) // 1-bit budget
	defer et.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: 5,
			Action:        config.ActionBlock,
		},
	}

	// Simulate path data with high entropy (passed directly, not via urlPayload).
	pathPayload := []byte("/api/tokens/x7k9mQ2pR4wL8nJ5")
	result := ceeAdmit(context.Background(),
		testCEESessionKey, pathPayload, nil, "http://example.com/api/tokens/x7k9mQ2pR4wL8nJ5",
		testCEEAgent, testCEEClientIP, testCEERequestID, ceeCfg, et, nil, nil, logger, m,
	)
	if !result.Blocked {
		t.Fatal("expected block: high-entropy path should exceed 1-bit budget")
	}
	if !result.EntropyHit {
		t.Error("expected EntropyHit = true")
	}
}

func TestCeeAdmit_PathQueryBoundarySecret(t *testing.T) {
	// Tests ceeAdmit directly with path-containing payload. HTTP handlers
	// no longer include paths, but this validates fragment reassembly DLP
	// works for any input data shape.
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	defer sc.Close()

	fb := scanner.NewFragmentBuffer(65536, 1000, 300)
	defer fb.Close()
	m := metrics.New()
	logger, _ := audit.New("json", "stdout", "", false, false)

	ceeCfg := config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
		Action: config.ActionBlock,
	}

	// First request: secret prefix spans path and query data.
	// Passed directly to ceeAdmit (not via urlPayload which excludes paths).
	payload1 := []byte("/check/" + "AKI" + "A" + "IOSF")
	result1 := ceeAdmit(context.Background(),
		testCEESessionKey, payload1, nil, "http://example.com/check", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, fb, sc, logger, m,
	)
	if result1.Blocked {
		t.Fatal("first fragment should not block")
	}

	// Second request: remaining secret suffix.
	payload2 := []byte("ODNN7EXAMPLE1234")
	result2 := ceeAdmit(context.Background(),
		testCEESessionKey, payload2, nil, "http://example.com/data", testCEEAgent,
		testCEEClientIP, testCEERequestID, ceeCfg, nil, fb, sc, logger, m,
	)
	if !result2.Blocked {
		t.Fatal("expected block after fragment reassembly completes secret across path/query boundary")
	}
	if !result2.FragmentHit {
		t.Error("expected FragmentHit = true")
	}
}

func TestQueryParamPayload_WireOrderSecretReconstruction(t *testing.T) {
	// Secret split across two query param values in wire order:
	// ?b=AKIA&a=IOSFODNN7EXAMPLE → values "AKIA" + "IOSFODNN7EXAMPLE"
	// contiguous = DLP match. Wire order (not sorted) ensures correct
	// reconstruction.
	u := &url.URL{RawQuery: "b=" + "AKI" + "A" + "&a=" + "IOSF" + "ODNN7EXAMPLE"}
	got := string(queryParamPayload(u))
	// Values only, contiguous: "AKIA" + "IOSFODNN7EXAMPLE" = full AWS key.
	want := "AKI" + "A" + "IOSF" + "ODNN7EXAMPLE"
	if got != want {
		t.Errorf("queryParamPayload = %q, want %q (wire order must preserve secret)", got, want)
	}
}

func TestQueryParamPayload_BareToken(t *testing.T) {
	// Bare tokens (no '=') must be included. An agent can exfiltrate secrets
	// as valueless query params: ?AKIA...EXAMPLE
	u := &url.URL{RawQuery: "AKI" + "A" + "IOSF" + "ODNN7EXAMPLE"}
	got := string(queryParamPayload(u))
	want := "AKI" + "A" + "IOSF" + "ODNN7EXAMPLE"
	if got != want {
		t.Errorf("queryParamPayload = %q, want %q", got, want)
	}
}

func TestQueryParamPayload_SecretInKey(t *testing.T) {
	// Secret embedded in the parameter key name: only the value "1" is
	// extracted. Key-embedded secrets are caught by per-request DLP, which
	// scans the full URL on every individual request. CEE fragment payloads
	// intentionally exclude keys to keep values contiguous across requests.
	u := &url.URL{RawQuery: "AKI" + "A" + "IOSF" + "ODNN7EXAMPLE" + "=1"}
	got := string(queryParamPayload(u))
	want := "1"
	if got != want {
		t.Errorf("queryParamPayload = %q, want %q", got, want)
	}
}

// --- Payload determinism across calls ---

func TestExtractOutboundPayload_Deterministic(t *testing.T) {
	// Run extraction 100 times to verify deterministic output.
	// Wire order is inherently stable (RawQuery is a string, not a map).
	for i := range 100 {
		r := &http.Request{
			URL: &url.URL{
				RawQuery: "z=zval&a=aval&m=mval",
			},
		}
		payload := extractOutboundPayload(r)
		got := string(payload)
		// Wire order, values only: zval, aval, mval.
		want := "zvalavalmval"
		if got != want {
			t.Errorf("iteration %d: extractOutboundPayload = %q, want %q", i, got, want)
		}
	}
}

// --- Reload CEE teardown ---

func TestReload_CEETeardownAndRebuild(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	getCEEStats := func() metrics.CEEStats {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		m.StatsHandler().ServeHTTP(rec, req)
		var resp struct {
			CEE metrics.CEEStats `json:"cross_request_detection"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode stats: %v", err)
		}
		return resp.CEE
	}

	// Verify initial state has CEE active.
	stats := getCEEStats()
	if !stats.EntropyTrackerActive || !stats.FragmentBufferActive {
		t.Fatal("expected both CEE components active after New()")
	}

	// Reload with CEE disabled.
	cfg2 := config.Defaults()
	cfg2.Internal = nil
	cfg2.CrossRequestDetection.Enabled = false
	sc2 := scanner.New(cfg2)

	p.Reload(cfg2, sc2)

	// After reload, CEE should be inactive.
	stats = getCEEStats()
	if stats.EntropyTrackerActive {
		t.Error("expected EntropyTrackerActive = false after reload with CEE disabled")
	}
	if stats.FragmentBufferActive {
		t.Error("expected FragmentBufferActive = false after reload with CEE disabled")
	}

	// Reload again with CEE re-enabled.
	cfg3 := config.Defaults()
	cfg3.Internal = nil
	cfg3.CrossRequestDetection.Enabled = true
	cfg3.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg3.CrossRequestDetection.FragmentReassembly.Enabled = true
	sc3 := scanner.New(cfg3)

	p.Reload(cfg3, sc3)

	stats = getCEEStats()
	if !stats.EntropyTrackerActive || !stats.FragmentBufferActive {
		t.Error("expected both CEE components active after re-enabling")
	}
}

// --- Fetch CEE integration ---

func TestFetchEndpoint_CEEEntropyBlock(t *testing.T) {
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello"))
	}))
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	// 1-bit budget: first request with query params exceeds it.
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 1.0
	cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionBlock

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	// Target URL has query params, which become the outbound entropy payload.
	targetURL := upstream.URL + "/text?payload=abcdefghijklmnopqrstuvwxyz0123456789"

	// First request: should be blocked because 1-bit budget is exceeded.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+url.QueryEscape(targetURL), nil)
	w := httptest.NewRecorder()
	p.handleFetch(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 from CEE entropy block on first request, got %d (body: %s)", w.Code, w.Body.String())
	}
}
