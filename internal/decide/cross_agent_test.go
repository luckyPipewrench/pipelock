// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide_test

import (
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// riskRecorder is a session.Recorder that also implements session.RiskState,
// backed by a real session.SessionRisk so the taint folding semantics under
// test match production exactly.
type riskRecorder struct {
	mu   sync.Mutex
	risk session.SessionRisk
}

func (r *riskRecorder) RecordSignal(_ session.SignalType, _ float64) (bool, string, string) {
	return false, "", ""
}
func (r *riskRecorder) RecordClean(_ float64) {}
func (r *riskRecorder) EscalationLevel() int  { return 0 }
func (r *riskRecorder) ThreatScore() float64  { return 0 }

func (r *riskRecorder) RiskSnapshot() session.SessionRisk {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.risk.Snapshot()
}

func (r *riskRecorder) ObserveRisk(obs session.RiskObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.risk.Observe(obs)
}

// contaminate marks the session externally untrusted. promptHit escalates the
// folded level to hostile, matching how a prompt-injection ingest contaminates.
func (r *riskRecorder) contaminate(promptHit bool) {
	r.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://attacker.example/x",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
		PromptHit:  promptHit,
		MaxSources: 10,
	})
}

// plainRecorder implements session.Recorder but NOT session.RiskState, used to
// exercise the fail-closed indeterminate path.
type plainRecorder struct{}

func (r *plainRecorder) RecordSignal(_ session.SignalType, _ float64) (bool, string, string) {
	return false, "", ""
}
func (r *plainRecorder) RecordClean(_ float64) {}
func (r *plainRecorder) EscalationLevel() int  { return 0 }
func (r *plainRecorder) ThreatScore() float64  { return 0 }

func enabledTaintCfg() *config.TaintConfig {
	return &config.TaintConfig{Enabled: true, RecentSources: 10}
}

func TestObserveCrossAgentContamination(t *testing.T) {
	t.Run("nil config no-op", func(t *testing.T) {
		rec := &riskRecorder{}
		rec.contaminate(false)
		got := decide.ObserveCrossAgentContamination(rec, nil, session.CrossAgentBoundaryMCPToolCall)
		if got != (decide.CrossAgentResult{}) {
			t.Fatalf("nil cfg should be no-op, got %+v", got)
		}
	})

	t.Run("disabled config no-op", func(t *testing.T) {
		rec := &riskRecorder{}
		rec.contaminate(false)
		got := decide.ObserveCrossAgentContamination(rec, &config.TaintConfig{Enabled: false}, session.CrossAgentBoundaryMCPToolCall)
		if got != (decide.CrossAgentResult{}) {
			t.Fatalf("disabled cfg should be no-op, got %+v", got)
		}
	})

	t.Run("nil recorder no-op", func(t *testing.T) {
		got := decide.ObserveCrossAgentContamination(nil, enabledTaintCfg(), session.CrossAgentBoundaryMCPToolCall)
		if got != (decide.CrossAgentResult{}) {
			t.Fatalf("nil rec should be no-op, got %+v", got)
		}
	})

	t.Run("clean session no-op", func(t *testing.T) {
		rec := &riskRecorder{}
		got := decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), session.CrossAgentBoundaryMCPToolCall)
		if got.Contaminated || got.SourceRecorded || got.ShouldEscalate {
			t.Fatalf("clean session must not record cross-agent, got %+v", got)
		}
		if len(rec.RiskSnapshot().Sources) != 0 {
			t.Fatal("clean session must not append a source")
		}
	})

	t.Run("untrusted contamination records source, no escalate", func(t *testing.T) {
		rec := &riskRecorder{}
		rec.contaminate(false)
		got := decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), session.CrossAgentBoundaryMCPToolCall)
		if !got.Contaminated || !got.SourceRecorded {
			t.Fatalf("want contaminated+recorded, got %+v", got)
		}
		if got.ShouldEscalate {
			t.Fatal("untrusted (non-hostile) contamination must not escalate the adaptive score")
		}
		srcs := rec.RiskSnapshot().Sources
		last := srcs[len(srcs)-1]
		if last.Kind != session.TaintSourceKindCrossAgent {
			t.Fatalf("last source kind = %q, want cross_agent", last.Kind)
		}
	})

	t.Run("hostile contamination escalates", func(t *testing.T) {
		rec := &riskRecorder{}
		rec.contaminate(true) // promptHit -> hostile
		got := decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), session.CrossAgentBoundaryA2ARequest)
		if !got.Contaminated || !got.SourceRecorded || !got.ShouldEscalate {
			t.Fatalf("hostile contamination must escalate, got %+v", got)
		}
	})

	t.Run("fail-closed when risk state unreadable", func(t *testing.T) {
		// plainRecorder implements session.Recorder but NOT RiskState.
		rec := &plainRecorder{}
		got := decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), session.CrossAgentBoundaryMCPToolCall)
		if !got.Contaminated || !got.Indeterminate || !got.ShouldEscalate {
			t.Fatalf("indeterminate state must fail closed (contaminated+escalate), got %+v", got)
		}
		if got.SourceRecorded {
			t.Fatal("cannot record a source without RiskState")
		}
	})

	t.Run("dedupes consecutive same-boundary refs to bound dilution", func(t *testing.T) {
		rec := &riskRecorder{}
		rec.contaminate(false)
		for i := 0; i < 25; i++ {
			decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), session.CrossAgentBoundaryMCPToolCall)
		}
		crossCount := 0
		for _, s := range rec.RiskSnapshot().Sources {
			if s.Kind == session.TaintSourceKindCrossAgent {
				crossCount++
			}
		}
		if crossCount != 1 {
			t.Fatalf("consecutive same-boundary cross-agent emits must dedupe to 1 ref, got %d", crossCount)
		}
	})

	t.Run("distinct boundaries are not deduped", func(t *testing.T) {
		rec := &riskRecorder{}
		rec.contaminate(false)
		decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), session.CrossAgentBoundaryMCPToolCall)
		decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), session.CrossAgentBoundaryA2ARequest)
		crossCount := 0
		for _, s := range rec.RiskSnapshot().Sources {
			if s.Kind == session.TaintSourceKindCrossAgent {
				crossCount++
			}
		}
		if crossCount != 2 {
			t.Fatalf("distinct boundaries must each record, got %d", crossCount)
		}
	})
}
