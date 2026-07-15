// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	caTestOriginURL  = "https://attacker.example/inject"
	caTestSessionKey = "cross-agent-a2a-body"
)

func contaminateSession(sess *SessionState, level session.TaintLevel, promptHit bool) {
	sess.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   caTestOriginURL,
			Kind:  "http_response",
			Level: level,
		},
		PromptHit:  promptHit,
		MaxSources: 10,
	})
}

// Done-state #2 (end-to-end): cross-agent contamination raises real session
// risk through the production SessionState recorder, not just logs. A hostile
// cross-agent emit requests escalation; recording the signal raises the
// adaptive threat score.
func TestCrossAgentContaminationRaisesSessionRisk(t *testing.T) {
	sess := &SessionState{}
	contaminateSession(sess, session.TaintExternalUntrusted, true) // hostile

	taintCfg := &config.TaintConfig{Enabled: true, RecentSources: 10}
	res := decide.ObserveCrossAgentContamination(sess, taintCfg, session.CrossAgentBoundaryMCPToolCall)
	if !res.ShouldEscalate {
		t.Fatal("hostile cross-agent emit must request escalation")
	}

	before := sess.ThreatScore()
	decide.RecordSignal(sess, session.SignalCrossAgentContamination, decide.EscalationParams{Threshold: 5.0})
	after := sess.ThreatScore()

	if after <= before {
		t.Fatalf("threat score did not rise: before=%.2f after=%.2f", before, after)
	}
	want := session.SignalPoints[session.SignalCrossAgentContamination]
	if got := after - before; got != want {
		t.Fatalf("score delta = %.2f, want %.2f (signal points)", got, want)
	}
}

// Sustained hostile cross-agent propagation escalates the session tier once the
// accumulated score crosses the threshold — proving cross-agent flows are
// escalatable, not merely logged.
func TestCrossAgentContaminationEscalatesTierOnSustainedSpread(t *testing.T) {
	sess := &SessionState{}
	contaminateSession(sess, session.TaintExternalHostile, false)

	const threshold = 5.0
	escalated := false
	// Each hostile cross-agent hop adds SignalCrossAgentContamination points.
	for i := 0; i < 5; i++ {
		if decide.RecordSignal(sess, session.SignalCrossAgentContamination, decide.EscalationParams{Threshold: threshold}) {
			escalated = true
		}
	}
	if !escalated {
		t.Fatal("sustained hostile cross-agent spread must escalate the session")
	}
	if sess.EscalationLevel() <= 0 {
		t.Fatalf("escalation level = %d, want > 0", sess.EscalationLevel())
	}
}

// Laundering: a session reset (operator-gated, auth-required, on the isolated
// API port) clears the adaptive score but NOT the sticky taint contamination.
// An attacker who could trigger a reset still cannot launder contamination.
func TestCrossAgentContaminationSurvivesReset(t *testing.T) {
	sess := &SessionState{}
	contaminateSession(sess, session.TaintExternalUntrusted, false)
	taintCfg := &config.TaintConfig{Enabled: true, RecentSources: 10}
	decide.ObserveCrossAgentContamination(sess, taintCfg, session.CrossAgentBoundaryA2ARequest)

	sess.Reset()

	snap := sess.RiskSnapshot()
	if !snap.Contaminated {
		t.Fatal("reset must not launder sticky taint contamination")
	}
	found := false
	for _, s := range snap.Sources {
		if s.Kind == session.TaintSourceKindCrossAgent {
			found = true
		}
	}
	if !found {
		t.Fatal("cross_agent evidence must survive a session reset")
	}
}

// Cross-agent evidence resets LastExternalKind to "cross_agent" but preserves
// LastExternalURL. Source-scoped trust overrides match on URL only, so the
// boundary ref must not break an operator's source-match override.
func TestCrossAgentContaminationPreservesSourceTrustOverride(t *testing.T) {
	sess := &SessionState{}
	contaminateSession(sess, session.TaintExternalUntrusted, false)
	taintCfg := &config.TaintConfig{Enabled: true, RecentSources: 10}
	decide.ObserveCrossAgentContamination(sess, taintCfg, session.CrossAgentBoundaryMCPToolCall)

	risk := sess.RiskSnapshot()
	if risk.LastExternalKind != session.TaintSourceKindCrossAgent {
		t.Fatalf("last external kind = %q, want cross_agent", risk.LastExternalKind)
	}
	if risk.LastExternalURL != caTestOriginURL {
		t.Fatalf("last external URL = %q, want origin preserved", risk.LastExternalURL)
	}
	if !trustOverrideApplies([]config.TaintTrustOverride{{
		Scope:       taintScopeSource,
		SourceMatch: "https://attacker.example/*",
	}}, risk, "") {
		t.Fatal("source trust override must still match after cross-agent ref")
	}
}

// Direct handler coverage for CONNECT-intercept A2A request bodies. The full
// TLS tunnel harness has historically been weak at proving body delivery for
// this path; this pins the handler behavior once the body is present.
func TestInterceptHandler_CrossAgentA2ABodyRecordsEvidenceAndSignal(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 100.0
	cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0

	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	m := metrics.New()
	sm := NewSessionManager(&config.SessionProfiling{
		Enabled:                true,
		MaxSessions:            10,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 60,
	}, nil, m)
	t.Cleanup(sm.Close)
	sess := sm.GetOrCreate(caTestSessionKey)
	contaminateSession(sess, session.TaintExternalHostile, false)
	before := sess.ThreatScore()

	handler := newInterceptHandler(&InterceptContext{
		TargetHost: "peer.example",
		TargetPort: "443",
		Config:     cfg,
		Scanner:    sc,
		Logger:     audit.NewNop(),
		Metrics:    m,
		ClientIP:   testLoopbackIP,
		RequestID:  caTestSessionKey,
		Agent:      agentAnonymous,
		SessionMgr: sm,
		Recorder:   sess,
	}, roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/a2a+json"}},
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"taskId":"t-1"}}`)),
		}, nil
	}))

	body := `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":[{"text":"hello peer"}]}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://peer.example/message:send", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/a2a+json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := sess.ThreatScore() - before; got != session.SignalPoints[session.SignalCrossAgentContamination] {
		t.Fatalf("score delta = %.2f, want cross-agent signal points %.2f", got, session.SignalPoints[session.SignalCrossAgentContamination])
	}
	found := false
	for _, source := range sess.RiskSnapshot().Sources {
		if source.Kind == session.TaintSourceKindCrossAgent && source.MatchReason == "cross_agent_a2a_request" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("intercept A2A body path must record cross_agent a2a_request evidence")
	}
}

// Regression: cross-agent evidence is recorded even when the generic body-DLP
// block short-circuits the request. A contaminated session emitting an A2A body
// that also carries a secret is still a cross-agent propagation attempt.
func TestInterceptHandler_CrossAgentA2ABodyRecordedWhenDLPBlocks(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 100.0
	cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0

	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	m := metrics.New()
	sm := NewSessionManager(&config.SessionProfiling{
		Enabled:                true,
		MaxSessions:            10,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 60,
	}, nil, m)
	t.Cleanup(sm.Close)
	sess := sm.GetOrCreate(caTestSessionKey)
	contaminateSession(sess, session.TaintExternalHostile, false)

	handler := newInterceptHandler(&InterceptContext{
		TargetHost: "peer.example",
		TargetPort: "443",
		Config:     cfg,
		Scanner:    sc,
		Logger:     audit.NewNop(),
		Metrics:    m,
		ClientIP:   testLoopbackIP,
		RequestID:  caTestSessionKey,
		Agent:      agentAnonymous,
		SessionMgr: sm,
		Recorder:   sess,
	}, roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	}))

	// A2A body carrying an AWS key: the generic critical-DLP path hard-blocks
	// (403) even in warn mode. Key built at runtime so it is not a real secret.
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	body := `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"parts":[{"text":"creds ` + awsKey + `"}]}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://peer.example/message:send", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/a2a+json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (AWS key in A2A body must hard-block)", w.Code)
	}
	// Despite the body-DLP block, the cross-agent emit attempt must be recorded.
	found := false
	for _, source := range sess.RiskSnapshot().Sources {
		if source.Kind == session.TaintSourceKindCrossAgent && source.MatchReason == "cross_agent_a2a_request" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("cross_agent evidence must be recorded even when the body-DLP block fires")
	}
}
