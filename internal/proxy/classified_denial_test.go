// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestNoteClassifiedDenial_FirstScoresDuplicateDoesNot(t *testing.T) {
	t.Parallel()
	sess := &SessionState{}
	scope := adaptiveScopeForHost("api.example.com")
	if !sess.NoteClassifiedDenial(scope, scanner.ScannerSSRF, "ssrf blocked", "hash-a") {
		t.Fatal("first denial must score")
	}
	if sess.NoteClassifiedDenial(scope, scanner.ScannerSSRF, "ssrf blocked", "hash-a") {
		t.Fatal("duplicate denial must not score")
	}
	if !sess.NoteClassifiedDenial(scope, scanner.ScannerSSRF, "ssrf blocked", "hash-b") {
		t.Fatal("policy-hash change must score as a new finding")
	}
	if !sess.NoteClassifiedDenial(adaptiveScopeForHost("other.example"), scanner.ScannerSSRF, "ssrf blocked", "hash-a") {
		t.Fatal("different destination must score")
	}
}

func TestNoteClassifiedDenial_CapStillScoresUnknownFingerprints(t *testing.T) {
	t.Parallel()
	sess := &SessionState{}
	sess.classifiedDenials = make(map[string]struct{}, maxClassifiedDenials)
	for i := 0; i < maxClassifiedDenials; i++ {
		sess.classifiedDenials[fmt.Sprintf("%d", i)] = struct{}{}
	}
	if !sess.NoteClassifiedDenial(adaptiveScopeForHost("api.example.com"), scanner.ScannerSSRF, "ssrf blocked", "hash-a") {
		t.Fatal("unknown fingerprint at cap must still score (fail closed)")
	}
}

func TestNoteClassifiedDenial_ResetClearsFingerprints(t *testing.T) {
	t.Parallel()
	sess := &SessionState{}
	scope := adaptiveScopeForHost("api.example.com")
	if !sess.NoteClassifiedDenial(scope, scanner.ScannerSSRF, "ssrf blocked", "hash-a") {
		t.Fatal("first denial must score")
	}
	sess.Reset()
	if !sess.NoteClassifiedDenial(scope, scanner.ScannerSSRF, "ssrf blocked", "hash-a") {
		t.Fatal("after reset, the same denial must score again")
	}
}

func TestRecordSessionActivity_DuplicateDeniedDestinationDoesNotPumpScore(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	host := "api.mixpanel.com"
	denied := scanner.Result{
		Allowed: false,
		Scanner: scanner.ScannerSSRF,
		Reason:  "SSRF blocked: resolves to non-overridable internal IP 0.0.0.0",
		Score:   1,
	}
	opts := func(id string) sessionActivityOptions {
		return sessionActivityOptions{
			ClientIP:   adaptiveSessionKeyLoopback,
			Agent:      agentAnonymous,
			Hostname:   host,
			RequestID:  id,
			Result:     denied,
			Config:     cfg,
			Logger:     logger,
			DeferClean: true,
		}
	}

	p.recordSessionActivityWithUserAgent(opts("req-1"))
	first := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	if first.ThreatScore() != session.SignalPoints[session.SignalBlock] {
		t.Fatalf("first denied request score=%.2f, want %.2f", first.ThreatScore(), session.SignalPoints[session.SignalBlock])
	}
	p.recordSessionActivityWithUserAgent(opts("req-2"))
	p.recordSessionActivityWithUserAgent(opts("req-3"))
	again := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	if again.ThreatScore() != session.SignalPoints[session.SignalBlock] {
		t.Fatalf("duplicate denials pumped score to %.2f, want first-denial %.2f", again.ThreatScore(), session.SignalPoints[session.SignalBlock])
	}
}

func TestRecordSessionActivity_DifferentDeniedFindingStillScores(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	base := sessionActivityOptions{
		ClientIP:   adaptiveSessionKeyLoopback,
		Agent:      agentAnonymous,
		Hostname:   "api.example.com",
		Config:     cfg,
		Logger:     logger,
		DeferClean: true,
	}
	ssrf := base
	ssrf.RequestID = "ssrf"
	ssrf.Result = scanner.Result{Allowed: false, Scanner: scanner.ScannerSSRF, Reason: "ssrf", Score: 1}
	dlp := base
	dlp.RequestID = "dlp"
	dlp.Result = scanner.Result{Allowed: false, Scanner: scanner.ScannerDLP, Reason: "secret", Score: 1}

	p.recordSessionActivityWithUserAgent(ssrf)
	p.recordSessionActivityWithUserAgent(dlp)
	rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	want := 2 * session.SignalPoints[session.SignalBlock]
	if rec.ThreatScore() != want {
		t.Fatalf("distinct findings score=%.2f, want %.2f", rec.ThreatScore(), want)
	}
}

func TestInterceptRecordFinding_DuplicateDeniedDestinationDoesNotPumpScore(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	sess := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	ic := &InterceptContext{
		TargetHost: "api.mixpanel.com",
		Config:     cfg,
		Logger:     logger,
		Recorder:   sess,
		ClientIP:   adaptiveSessionKeyLoopback,
		RequestID:  "req-1",
	}
	reason := "SSRF blocked: resolves to non-overridable internal IP 0.0.0.0"
	interceptRecordFinding(ic, session.SignalBlock, scanner.ScannerSSRF, reason)
	if sess.ThreatScore() != session.SignalPoints[session.SignalBlock] {
		t.Fatalf("first intercept denial score=%.2f, want %.2f", sess.ThreatScore(), session.SignalPoints[session.SignalBlock])
	}
	ic.RequestID = "req-2"
	interceptRecordFinding(ic, session.SignalBlock, scanner.ScannerSSRF, reason)
	interceptRecordFinding(ic, session.SignalBlock, scanner.ScannerSSRF, reason)
	if sess.ThreatScore() != session.SignalPoints[session.SignalBlock] {
		t.Fatalf("duplicate intercept denials pumped score to %.2f", sess.ThreatScore())
	}
	ic.TargetHost = "evil.example"
	ic.RequestID = "req-3"
	interceptRecordFinding(ic, session.SignalBlock, scanner.ScannerSSRF, reason)
	want := 2 * session.SignalPoints[session.SignalBlock]
	if sess.ThreatScore() != want {
		t.Fatalf("different intercept dest score=%.2f, want %.2f", sess.ThreatScore(), want)
	}
}

func TestWsRelayRecordFinding_DuplicateDeniedDestinationDoesNotPumpScore(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	sess := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	relay := &wsRelay{
		rec:      sess,
		cfg:      cfg,
		proxy:    p,
		hostname: "api.mixpanel.com",
		clientIP: adaptiveSessionKeyLoopback,
		agent:    agentAnonymous,
	}
	reason := "SSRF blocked: resolves to non-overridable internal IP 0.0.0.0"
	relay.recordFinding(session.SignalBlock, audit.NewNop(), scanner.ScannerSSRF, reason)
	if sess.ThreatScore() != session.SignalPoints[session.SignalBlock] {
		t.Fatalf("first websocket denial score=%.2f, want %.2f", sess.ThreatScore(), session.SignalPoints[session.SignalBlock])
	}
	relay.recordFinding(session.SignalBlock, audit.NewNop(), scanner.ScannerSSRF, reason)
	relay.recordFinding(session.SignalBlock, audit.NewNop(), scanner.ScannerSSRF, reason)
	if sess.ThreatScore() != session.SignalPoints[session.SignalBlock] {
		t.Fatalf("duplicate websocket denials pumped score to %.2f", sess.ThreatScore())
	}
}

func TestInterceptRecordFinding_NearMissStillAccumulates(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	sess := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	ic := &InterceptContext{
		TargetHost: "api.example.com",
		Config:     cfg,
		Logger:     audit.NewNop(),
		Recorder:   sess,
		ClientIP:   adaptiveSessionKeyLoopback,
		RequestID:  "req-1",
	}
	reason := "injection detected in response body"
	interceptRecordFinding(ic, session.SignalNearMiss, scanner.ScannerDLP, reason)
	ic.RequestID = "req-2"
	interceptRecordFinding(ic, session.SignalNearMiss, scanner.ScannerDLP, reason)
	ic.RequestID = "req-3"
	interceptRecordFinding(ic, session.SignalStrip, scanner.ScannerDLP, reason)
	want := 2*session.SignalPoints[session.SignalNearMiss] + session.SignalPoints[session.SignalStrip]
	if sess.ThreatScore() != want {
		t.Fatalf("warn/strip intercept findings score=%.2f, want %.2f", sess.ThreatScore(), want)
	}
}

func TestWsRelayRecordFinding_StripStillAccumulates(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	sess := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	relay := &wsRelay{
		rec:      sess,
		cfg:      cfg,
		proxy:    p,
		hostname: "api.example.com",
		clientIP: adaptiveSessionKeyLoopback,
		agent:    agentAnonymous,
	}
	reason := "injection detected: prompt_injection"
	relay.recordFinding(session.SignalStrip, audit.NewNop(), "response_scan", reason)
	relay.recordFinding(session.SignalStrip, audit.NewNop(), "response_scan", reason)
	want := 2 * session.SignalPoints[session.SignalStrip]
	if sess.ThreatScore() != want {
		t.Fatalf("duplicate websocket strips score=%.2f, want %.2f", sess.ThreatScore(), want)
	}
}
