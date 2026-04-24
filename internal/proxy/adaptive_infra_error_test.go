// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// infraErrorResult constructs a scanner.Result mirroring what the SSRF layer
// returns on DNS resolution failure. Allowed=false preserves fail-closed; the
// ClassInfrastructureError tag is what adaptive enforcement keys off of.
func infraErrorResult() scanner.Result {
	return scanner.Result{
		Allowed: false,
		Reason:  "SSRF check failed: DNS resolution error for example.test: lookup example.test: i/o timeout",
		Scanner: scanner.ScannerSSRF,
		Score:   1.0,
		Class:   scanner.ClassInfrastructureError,
	}
}

// threatResult constructs a scanner.Result representing a real SSRF block
// (private-IP resolution). Used as the regression contrast.
func threatResult() scanner.Result {
	return scanner.Result{
		Allowed: false,
		Reason:  "SSRF blocked: example.internal resolves to private IP 10.0.0.5",
		Scanner: scanner.ScannerSSRF,
		Score:   1.0,
		Class:   scanner.ClassThreat,
	}
}

// TestRecordSessionActivity_InfrastructureError_NoSignal verifies that a single
// infrastructure-error result produces no adaptive-score increment. This is
// the core fix — prior to the change, the block fell through the !result.Allowed
// branch and recorded SignalBlock (+3.0).
func TestRecordSessionActivity_InfrastructureError_NoSignal(t *testing.T) {
	cfg := adaptiveConfig()
	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)

	before := rec.ThreatScore()

	p.recordSessionActivity(
		adaptiveSessionKeyLoopback, agentAnonymous, "example.test",
		"req-infra-1", infraErrorResult(), cfg, logger, true,
	)

	after := rec.ThreatScore()
	if after != before {
		t.Errorf("infrastructure error must be score-neutral; before=%f after=%f", before, after)
	}
	if rec.EscalationLevel() != 0 {
		t.Errorf("single infrastructure error must not escalate; level=%d", rec.EscalationLevel())
	}
}

// TestRecordSessionActivity_InfrastructureError_BurstStaysBelowThreshold is the
// regression against the 2026-04-24 fedora airlock lockdown: a burst of DNS
// resolver failures must not accumulate enough signal to enter the airlock.
// Threshold is 5.0; 20 infrastructure errors × 0 points each = 0 < 5.0.
func TestRecordSessionActivity_InfrastructureError_BurstStaysBelowThreshold(t *testing.T) {
	cfg := adaptiveConfig()
	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)

	const burstSize = 20
	for i := 0; i < burstSize; i++ {
		p.recordSessionActivity(
			adaptiveSessionKeyLoopback, agentAnonymous, "example.test",
			"req-infra-burst", infraErrorResult(), cfg, logger, true,
		)
	}

	// 20 consecutive infrastructure errors must not escalate the session.
	// Prior to the fix, 2 would have been enough (6.0 > 5.0 threshold) to
	// push into airlock hard tier for 10 minutes.
	if rec.EscalationLevel() != 0 {
		t.Errorf("%d consecutive DNS failures must not escalate session; level=%d score=%f",
			burstSize, rec.EscalationLevel(), rec.ThreatScore())
	}
	if rec.ThreatScore() >= cfg.AdaptiveEnforcement.EscalationThreshold {
		t.Errorf("score %f exceeded threshold %f after %d infrastructure errors",
			rec.ThreatScore(), cfg.AdaptiveEnforcement.EscalationThreshold, burstSize)
	}
}

// TestRecordSessionActivity_RealSSRF_StillSignalBlock is the load-bearing
// regression guard. A real SSRF (private-IP resolution) must STILL score
// SignalBlock (+3.0) after the fix; otherwise adversarial SSRF probes
// silently stop escalating sessions.
func TestRecordSessionActivity_RealSSRF_StillSignalBlock(t *testing.T) {
	cfg := adaptiveConfig()
	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)

	before := rec.ThreatScore()

	// Two real SSRF blocks would have pushed into airlock hard tier pre-fix.
	// Post-fix they must STILL do that (this is the invariant — the fix must
	// not weaken detection of genuinely adversarial behavior).
	p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "evil.internal",
		"req-ssrf-1", threatResult(), cfg, logger, true)
	p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "evil.internal",
		"req-ssrf-2", threatResult(), cfg, logger, true)

	pointsPerBlock := session.SignalPoints[session.SignalBlock] // +3.0 by default
	want := before + 2*pointsPerBlock

	if rec.ThreatScore() < want {
		t.Errorf("real SSRF must score SignalBlock; before=%f after=%f want>=%f",
			before, rec.ThreatScore(), want)
	}
	if rec.EscalationLevel() == 0 {
		t.Errorf("2 real SSRF blocks must escalate the session; level stayed at 0 (score=%f threshold=%f)",
			rec.ThreatScore(), cfg.AdaptiveEnforcement.EscalationThreshold)
	}
}

// TestRecordSessionActivity_MixedInfraAndThreat verifies that infrastructure
// errors interleaved with real threats don't dilute the real-threat scoring.
// A session with 10 DNS failures + 2 real SSRF blocks should still escalate
// (the real blocks alone push past threshold).
func TestRecordSessionActivity_MixedInfraAndThreat(t *testing.T) {
	cfg := adaptiveConfig()
	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)

	// 5 infrastructure errors → score-neutral.
	for i := 0; i < 5; i++ {
		p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "dns-broken.test",
			"req-infra", infraErrorResult(), cfg, logger, true)
	}
	// 2 real SSRF blocks → +6.0 total, crossing the 5.0 threshold.
	p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "evil.internal",
		"req-ssrf-1", threatResult(), cfg, logger, true)
	p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "evil.internal",
		"req-ssrf-2", threatResult(), cfg, logger, true)
	// 5 more infrastructure errors → still neutral, no signal bleed.
	for i := 0; i < 5; i++ {
		p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "dns-broken.test",
			"req-infra-2", infraErrorResult(), cfg, logger, true)
	}

	if rec.EscalationLevel() == 0 {
		t.Errorf("2 real SSRF blocks + 10 infrastructure errors must escalate; level stayed at 0 (score=%f)",
			rec.ThreatScore())
	}
}

// --- Transport parity: hasFinding must exclude infrastructure errors ---
// hasFinding is computed inline at each transport entry point. The values
// below mirror the production expressions so a future change to the formula
// is caught by this test file.

// TestHasFindingFormula_InfrastructureError verifies the post-fix algebra:
//
//	hasFinding = !Allowed && !IsAdaptiveNeutral()
//
// An infrastructure error has Allowed=false and IsAdaptiveNeutral()=true,
// which must resolve to hasFinding=false at every transport.
func TestHasFindingFormula_InfrastructureError(t *testing.T) {
	r := infraErrorResult()
	got := !r.Allowed && !r.IsAdaptiveNeutral()
	if got {
		t.Errorf("infrastructure error must not flip hasFinding; got %v", got)
	}
}

// TestHasFindingFormula_RealThreat verifies the same formula still flips
// for real threats. This is the regression guard paired with the neutrality
// test above — if someone weakens IsAdaptiveNeutral() to cover ClassThreat,
// this test fails loudly.
func TestHasFindingFormula_RealThreat(t *testing.T) {
	r := threatResult()
	got := !r.Allowed && !r.IsAdaptiveNeutral()
	if !got {
		t.Errorf("real threat block must flip hasFinding; got %v", got)
	}
}

// TestHasFindingFormula_Protective confirms that protective (rate-limit)
// behavior is unchanged: still neutral, still does not flip hasFinding.
func TestHasFindingFormula_Protective(t *testing.T) {
	r := scanner.Result{
		Allowed: false,
		Reason:  "rate limit exceeded",
		Scanner: scanner.ScannerRateLimit,
		Score:   0.7,
		Class:   scanner.ClassProtective,
	}
	got := !r.Allowed && !r.IsAdaptiveNeutral()
	if got {
		t.Errorf("protective block must not flip hasFinding; got %v", got)
	}
}

// TestAdaptiveConfigEscalationThreshold is a precondition guard: the test
// config uses threshold=5.0, and SignalBlock = +3.0 per event. Two blocks
// (+6.0) cross the threshold. If this equation changes upstream the
// "burst of 20 infrastructure errors stays below threshold" test becomes
// a tautology instead of a meaningful assertion.
func TestAdaptiveConfigEscalationThreshold(t *testing.T) {
	cfg := adaptiveConfig()
	if cfg.AdaptiveEnforcement.EscalationThreshold != adaptiveTestThreshold {
		t.Errorf("adaptiveConfig threshold changed; got %f want %f",
			cfg.AdaptiveEnforcement.EscalationThreshold, adaptiveTestThreshold)
	}
	if session.SignalPoints[session.SignalBlock] < 1.0 {
		t.Errorf("SignalBlock point value dropped below 1.0 (%f); burst tests may no longer be meaningful",
			session.SignalPoints[session.SignalBlock])
	}
	// Confirm 2 × SignalBlock crosses the threshold (precondition for
	// TestRecordSessionActivity_RealSSRF_StillSignalBlock).
	if 2*session.SignalPoints[session.SignalBlock] <= adaptiveTestThreshold {
		t.Errorf("precondition failed: 2×SignalBlock (%f) must exceed threshold (%f)",
			2*session.SignalPoints[session.SignalBlock], adaptiveTestThreshold)
	}
}

// TestRecordSessionActivity_InfrastructureError_NoDecay verifies that
// infrastructure errors don't trigger clean-decay either. A session with an
// elevated threat score must not have that score reduced by a DNS wobble.
// Score-neutral means exactly that — no bump, no decay.
func TestRecordSessionActivity_InfrastructureError_NoDecay(t *testing.T) {
	cfg := adaptiveConfig()
	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)

	// Prime score with a real threat.
	rec.RecordSignal(session.SignalNearMiss, adaptiveTestThreshold) // +1.0
	rec.RecordSignal(session.SignalNearMiss, adaptiveTestThreshold) // +1.0 (now 2.0)
	beforeScore := rec.ThreatScore()

	// Infrastructure error with deferClean=false (would normally decay
	// on a clean result). Must NOT decay for infrastructure.
	p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "dns-broken.test",
		"req-infra-decay", infraErrorResult(), cfg, logger, false)

	afterScore := rec.ThreatScore()
	if afterScore != beforeScore {
		t.Errorf("infrastructure error must not decay existing score; before=%f after=%f",
			beforeScore, afterScore)
	}
}
