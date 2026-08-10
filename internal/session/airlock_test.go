// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session

import "testing"

type basicAirlockRecorder struct{}

func (*basicAirlockRecorder) RecordSignal(SignalType, float64) (bool, string, string) {
	return false, "", ""
}
func (*basicAirlockRecorder) RecordClean(float64)  {}
func (*basicAirlockRecorder) EscalationLevel() int { return 0 }
func (*basicAirlockRecorder) ThreatScore() float64 { return 0 }

type providerAirlockRecorder struct {
	basicAirlockRecorder
	tier string
}

func (r *providerAirlockRecorder) AirlockTier() string { return r.tier }
func (r *providerAirlockRecorder) EscalateAirlock(tier, _ string) (bool, string, string) {
	from := r.tier
	r.tier = tier
	return from != tier, from, tier
}

func TestAirlockAccessorsAreNilSafe(t *testing.T) {
	t.Parallel()

	if got, ok := AirlockTier(nil); got != "" || ok {
		t.Fatalf("AirlockTier(nil) = (%q, %v), want empty, false", got, ok)
	}
	if changed, _, _ := EscalateAirlock(nil, "hard", "test"); changed {
		t.Fatal("EscalateAirlock(nil) changed state")
	}

	basic := &basicAirlockRecorder{}
	if got, ok := AirlockTier(basic); got != "" || ok {
		t.Fatalf("AirlockTier(basic) = (%q, %v), want empty, false", got, ok)
	}
	if changed, _, _ := EscalateAirlock(basic, "hard", "test"); changed {
		t.Fatal("EscalateAirlock(basic) changed state")
	}

	provider := &providerAirlockRecorder{tier: "none"}
	if changed, from, to := EscalateAirlock(provider, "hard", "test"); !changed || from != "none" || to != "hard" {
		t.Fatalf("EscalateAirlock(provider) = (%v, %q, %q), want (true, none, hard)", changed, from, to)
	}
	if got, ok := AirlockTier(provider); got != "hard" || !ok {
		t.Fatalf("AirlockTier(provider) = (%q, %v), want hard, true", got, ok)
	}
}
