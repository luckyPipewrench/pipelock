// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestAirlockEdgeTrigger_NoPlateauReentry is the core regression test for the
// drain -> hard -> drain deadlock that a busy retrying client could cause.
//
// Before the fix, recordSessionActivity mapped the session's CURRENT adaptive
// level to an airlock tier on every request. After a drain session timer-
// recovered to hard, the very next allowed request would observe the session
// still sitting at "critical" adaptively and shove airlock back into drain
// — 3 seconds after leaving it — even though no new threat had appeared.
//
// After the fix, airlock activation is edge-triggered: it fires only on the
// request that actually crossed an adaptive escalation threshold.
func TestAirlockEdgeTrigger_NoPlateauReentry(t *testing.T) {
	cfg := adaptiveConfig()
	cfg.Airlock.Enabled = true
	cfg.Airlock.Triggers.OnCritical = config.AirlockTierDrain
	cfg.Airlock.Timers.DrainMinutes = 15
	cfg.Airlock.Timers.DrainTimeoutSeconds = 30

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	// Drive the session to critical through the actual adaptive→airlock
	// bridge (recordSessionActivity), not by reaching into raw signals.
	// With threshold 5.0 doubling each step and SignalBlock worth 3 points,
	// reaching level 3 (critical) takes 7 blocked-result calls.
	blocked := scanner.Result{Allowed: false}
	for i := 0; i < 12; i++ {
		p.recordSessionActivity(testClientIP, agentAnonymous, "evil.example", "req-escalate", blocked, cfg, logger, false)
		sm := p.sessionMgrPtr.Load()
		if sm == nil {
			t.Fatal("session manager not initialized")
		}
		sess := sm.GetOrCreate(testClientIP)
		if sess.EscalationLevel() >= 3 {
			break
		}
	}

	sm := p.sessionMgrPtr.Load()
	sess := sm.GetOrCreate(testClientIP)
	if got := sess.EscalationLevel(); got < 3 {
		t.Fatalf("pre-condition failed: expected session to reach critical (level >= 3), got level %d", got)
	}
	if got := sess.Airlock().Tier(); got != config.AirlockTierDrain {
		t.Fatalf("pre-condition failed: expected airlock at %q after escalation to critical, got %q",
			config.AirlockTierDrain, got)
	}

	// Simulate timer-based recovery drain -> hard. ForceSetTier bypasses the
	// upward-only SetTier rule; it exists for exactly this kind of admin /
	// timer path. The production timer path in sweepDeescalation ends up in
	// the same state, so this is a faithful proxy for it.
	if changed, _, _ := sess.Airlock().ForceSetTier(config.AirlockTierHard); !changed {
		t.Fatal("ForceSetTier(hard) unexpectedly returned changed=false")
	}
	if got := sess.Airlock().Tier(); got != config.AirlockTierHard {
		t.Fatalf("post-ForceSetTier state wrong: expected %q, got %q", config.AirlockTierHard, got)
	}
	// Adaptive level is still at critical — that's the plateau condition
	// the bug exploited. Sanity-check it explicitly.
	if got := sess.EscalationLevel(); got < 3 {
		t.Fatalf("plateau precondition failed: expected level still >= 3 (critical), got %d", got)
	}

	// The next request is CLEAN. It does not cross any escalation threshold
	// (escalated=false). Under the fix, edge-triggered airlock must NOT
	// re-arm drain even though the session is still at critical level.
	clean := scanner.Result{Allowed: true}
	p.recordSessionActivity(testClientIP, agentAnonymous, "docs.example", "req-post-recovery-clean", clean, cfg, logger, false)

	if got := sess.Airlock().Tier(); got != config.AirlockTierHard {
		t.Fatalf("edge-trigger regression: expected airlock to STAY at %q after a clean plateau request, got %q (drain->hard->drain loop returned)",
			config.AirlockTierHard, got)
	}

	// Control: a NEW blocked result that fires a fresh escalation (level
	// will tick past the doubled threshold at this point) must still be
	// able to re-arm drain. Edge-triggering narrows the trigger, it does
	// not disable it.
	for i := 0; i < 20; i++ {
		p.recordSessionActivity(testClientIP, agentAnonymous, "evil2.example", "req-post-recovery-bad", blocked, cfg, logger, false)
		if sess.Airlock().Tier() == config.AirlockTierDrain {
			return
		}
	}
	t.Fatalf("control case failed: blocked-result retries should eventually escalate and re-arm drain, ended at tier %q level %d",
		sess.Airlock().Tier(), sess.EscalationLevel())
}

// TestSessionManager_SweepDeescalation_DrainToHardAfterTimeout verifies that
// sweepDeescalation drops a drained session back to hard once wall clock has
// advanced past the drain timeout, with adaptive enforcement enabled and
// without any external touches to the airlock timer.
//
// This is the fix-direction assertion for Bug #2. Before the fix, every deny
// path called AirlockState.ExtendTimer(), which reset enteredAt on every
// blocked retry. The deny paths no longer reference ExtendTimer (the
// function itself has been deleted), so a session's drain enteredAt is only
// ever set once — at drain entry — and sweepDeescalation can observe a
// real elapsed interval. This test locks that invariant in place.
//
// Regression guard: if a future refactor reintroduces a timer-extension
// mechanism that fires on denies, this test by itself will not catch it
// (it does not drive the HTTP handler). That surface is guarded by the
// absence of any ExtendTimer-equivalent public method on AirlockState and
// by the source-level fact that the four deny paths touch only the logger,
// metrics, and response writer — see forward.go, intercept.go, websocket.go.
func TestSessionManager_SweepDeescalation_DrainToHardAfterTimeout(t *testing.T) {
	sessCfg := testSessionConfig()
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:              true,
		EscalationThreshold:  adaptiveTestThreshold,
		DecayPerCleanRequest: 0.5,
	}
	airlockCfg := &config.Airlock{
		Enabled: true,
		Timers: config.AirlockTimers{
			// DrainTimeoutSeconds is the shorter ceiling TryDeescalate checks
			// (it takes min(DrainMinutes*60, DrainTimeoutSeconds) as the
			// drain duration). Keep DrainMinutes realistic and use a 1s
			// timeout that the test crosses via enteredAt manipulation.
			DrainMinutes:        15,
			DrainTimeoutSeconds: 1,
		},
	}

	sm := NewSessionManager(sessCfg, adaptiveCfg, nil, SessionManagerOptions{
		AirlockCfg: airlockCfg,
		Logger:     audit.NewNop(),
	})
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Match the real-world bug state: session has reached critical on the
	// adaptive ladder before being shoved into airlock drain.
	escalateRec(sess, 3)

	if changed, _, _ := sess.Airlock().SetTier(config.AirlockTierDrain); !changed {
		t.Fatal("SetTier(drain) unexpectedly returned changed=false")
	}

	// Age enteredAt past the 1s drain timeout so TryDeescalate fires. This
	// is the same technique used by TestAirlockState_TryDeescalate elsewhere
	// in the file — avoids wall-clock sleeps and keeps the test fast and
	// deterministic.
	sess.Airlock().mu.Lock()
	sess.Airlock().enteredAt = time.Now().Add(-2 * time.Second)
	sess.Airlock().mu.Unlock()

	// sweepDeescalation short-circuits when adaptive is nil/disabled, which
	// is why airlockCfg alone is not enough — adaptiveCfg MUST be enabled
	// for the sweep to reach the airlock-recovery block. This wiring is
	// exercised explicitly so a future refactor cannot silently bypass it.
	sm.sweepDeescalation()

	if got := sess.Airlock().Tier(); got != config.AirlockTierHard {
		t.Fatalf("expected sweepDeescalation to drop drain -> hard after timeout; got tier %q", got)
	}
}
