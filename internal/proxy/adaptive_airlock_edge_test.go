// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type airlockEdgeWriter func()

func (f airlockEdgeWriter) Write(p []byte) (int, error) {
	f()
	return len(p), nil
}

func TestScopedAirlockUsesRecordedEscalationEdge(t *testing.T) {
	for _, scope := range []string{"", adaptiveScopeForHost(adaptiveScopePollHost)} {
		for _, recoverFirst := range []bool{false, true} {
			name := scope + "/escalation"
			if recoverFirst {
				name = scope + "/recovery"
			}
			t.Run(name, func(t *testing.T) {
				cfg := adaptiveScopedAirlockConfig()
				cfg.Airlock.Triggers.OnElevated = config.AirlockTierSoft
				cfg.Airlock.Triggers.OnHigh = config.AirlockTierHard
				p, _ := newAdaptiveScopeProxy(t, cfg)
				sess := scopedSession(t, p)
				writes := 0
				// The real console callback runs after the atomic score update.
				// Change the state there to schedule the competing operation
				// deterministically, without adding a production test seam.
				writer := airlockEdgeWriter(func() {
					writes++
					if recoverFirst {
						changed, _, _ := sess.RecordScopedCleanWithRecovery(scope, 0, 1, nil)
						if !changed {
							t.Fatal("control did not recover the recorded escalation")
						}
					} else {
						changed, _, _ := sess.RecordScopedSignal(scope, session.SignalBlock, 3)
						if !changed {
							t.Fatal("control did not cross the next escalation edge")
						}
					}
				})
				recordAdaptiveSignalForScope(sess, scope, session.SignalBlock, &cfg.AdaptiveEnforcement, &cfg.Airlock, decide.EscalationParams{
					Threshold: 3, ConsoleWriter: writer,
				})
				if writes != 1 {
					t.Fatalf("console callback ran %d times, want 1", writes)
				}
				if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierSoft {
					t.Fatalf("recorded elevated edge selected tier %q, want soft", got)
				}
				trigger, source := sess.AirlockForScope(scope).EntryProvenance()
				if trigger != airlockTriggerOnElevated || source != airlockSourceTriggers {
					t.Fatalf("edge provenance = %q/%q, want elevated trigger", trigger, source)
				}
			})
		}
	}
}
