// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

const (
	testCEEClientIP   = "10.0.0.1"
	testCEEAgent      = "test-agent"
	testCEERequestID  = "req-001"
	testCEESessionKey = "test-session"
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
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "key=secret_value&other=data",
		},
	}
	payload := extractOutboundPayload(r)
	got := string(payload)

	// Query parameter iteration order is not guaranteed, so check both values
	// are present rather than exact string equality.
	if !strings.Contains(got, "secret_value") {
		t.Errorf("payload %q missing query value %q", got, "secret_value")
	}
	if !strings.Contains(got, "data") {
		t.Errorf("payload %q missing query value %q", got, "data")
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

	if !strings.Contains(got, "query-data") {
		t.Errorf("payload %q missing query value %q", got, "query-data")
	}
	if !strings.Contains(got, body) {
		t.Errorf("payload %q missing body %q", got, body)
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
	// SignalEntropyBudget (2) + SignalFragmentDLP (3) = 5 points.
	if score < 5.0 {
		t.Errorf("expected threat score >= 5.0, got %.1f", score)
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
