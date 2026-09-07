// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

func TestEvidenceHealthZeroAnchorLagDisablesOnlyAgeRequirement(t *testing.T) {
	h, _, emitter, _ := newEvidenceHealthTestMonitor(t, nil)
	t.Cleanup(func() {
		if err := h.recorder.Close(); err != nil {
			t.Errorf("recorder.Close: %v", err)
		}
	})
	emitEvidenceHealthTestReceipt(t, emitter, "https://api.vendor.example/baseline")
	emitEvidenceHealthTestReceipt(t, emitter, "https://api.vendor.example/current-head")
	h.currentConfig().FlightRecorder.EvidenceHealth.MaxAnchorLag = "0s"
	withoutAnchor, ok := h.stats()
	if !ok || withoutAnchor.Anchor != nil || withoutAnchor.Requirements[metrics.EvidenceRequirementAnchoringFresh] {
		t.Fatalf("zero age limit accepted missing anchor evidence: ok=%v stats=%+v", ok, withoutAnchor)
	}
	state := validEvidenceHealthAnchorState()
	state.FinalSeq = 1
	state.SignerKey = emitter.SignerKeyHex()
	state.AnchoredAt = time.Now().UTC().Add(-2 * config.DefaultEvidenceHealthMaxAnchorLag)
	writeEvidenceHealthAnchorState(t, h.recorder.Dir(), state)
	h.runPass()

	for _, tt := range []struct {
		name      string
		lag       string
		wantFresh bool
	}{
		{name: "default rejects stale anchor"},
		{name: "zero accepts valid stale anchor", lag: "0s", wantFresh: true},
		{name: "restored limit rejects stale anchor", lag: "1h"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h.currentConfig().FlightRecorder.EvidenceHealth.MaxAnchorLag = tt.lag
			stats, ok := h.stats()
			if !ok || stats.Anchor == nil {
				t.Fatalf("valid anchor stats unavailable: ok=%v anchor=%+v", ok, stats.Anchor)
			}
			if got := stats.Requirements[metrics.EvidenceRequirementAnchoringFresh]; got != tt.wantFresh {
				t.Errorf("anchoring_fresh = %v, want %v", got, tt.wantFresh)
			}
			if stats.CurrentAEL != metrics.EvidenceCurrentAELUnavailable {
				t.Errorf("age setting raised current AEL to %q", stats.CurrentAEL)
			}
			if !stats.LocalRecorderOperational {
				t.Error("age setting degraded local recorder operation")
			}
		})
	}
}
