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
	if _, present := withoutAnchor.Requirements[metrics.EvidenceRequirementAnchoringFresh]; !present {
		t.Fatal("missing anchoring_fresh requirement without anchor")
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
			checkStats := func() {
				t.Helper()
				stats, ok := h.stats()
				if !ok || stats.Anchor == nil {
					t.Fatalf("valid anchor stats unavailable: ok=%v anchor=%+v", ok, stats.Anchor)
				}
				if stats.Anchor.AnchoredAt != state.AnchoredAt.Format(time.RFC3339Nano) || stats.Anchor.FinalSeq != state.FinalSeq || stats.Anchor.RootHash != state.RootHash {
					t.Fatalf("loaded anchor does not match stale fixture: %+v", stats.Anchor)
				}
				if want := float64(state.AnchoredAt.UnixNano()) / 1e9; stats.Anchor.LastTimestampSeconds != want {
					t.Fatalf("anchor age timestamp = %v, want %v", stats.Anchor.LastTimestampSeconds, want)
				}
				if time.Since(state.AnchoredAt) <= config.DefaultEvidenceHealthMaxAnchorLag {
					t.Fatal("anchor fixture is not stale")
				}
				if got, present := stats.Requirements[metrics.EvidenceRequirementAnchoringFresh]; !present {
					t.Error("missing anchoring_fresh requirement with stale anchor")
				} else if got != tt.wantFresh {
					t.Errorf("anchoring_fresh = %v, want %v", got, tt.wantFresh)
				}
				if stats.CurrentAEL != metrics.EvidenceCurrentAELUnavailable {
					t.Errorf("age setting raised current AEL to %q", stats.CurrentAEL)
				}
				if !stats.LocalRecorderOperational {
					t.Error("age setting degraded local recorder operation")
				}
			}
			checkStats()
			h.runPass()
			checkStats()
		})
	}
}
