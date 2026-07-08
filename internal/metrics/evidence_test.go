// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestEvidenceCurrentAELTable(t *testing.T) {
	base := EvidenceAELInput{
		RecorderEnabled: true,
		EmitterHealthy:  true,
		SelfAuditOK:     true,
	}
	tests := []struct {
		name string
		in   EvidenceAELInput
		want int
	}{
		{name: "recorder_disabled", in: EvidenceAELInput{}, want: 0},
		{name: "recorder_only", in: EvidenceAELInput{RecorderEnabled: true}, want: 0},
		{name: "selfaudit_latched_bad", in: EvidenceAELInput{RecorderEnabled: true, EmitterHealthy: true}, want: 0},
		{name: "best_effort", in: base, want: 1},
		{name: "durable_heartbeat", in: withEvidenceAEL(base, func(in *EvidenceAELInput) {
			in.DurabilityGate = true
			in.Heartbeats = true
		}), want: 2},
		{name: "anchor_fresh", in: withEvidenceAEL(base, func(in *EvidenceAELInput) {
			in.DurabilityGate = true
			in.Heartbeats = true
			in.AnchoringFresh = true
		}), want: 3},
		{name: "cpc_active", in: withEvidenceAEL(base, func(in *EvidenceAELInput) {
			in.DurabilityGate = true
			in.Heartbeats = true
			in.AnchoringFresh = true
			in.CPCActive = true
		}), want: 4},
		{name: "ungated_fsync_failure_degrades_to_zero", in: withEvidenceAEL(base, func(in *EvidenceAELInput) {
			in.UngatedFsyncFail = true
		}), want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvidenceCurrentAEL(tt.in); got != tt.want {
				t.Fatalf("EvidenceCurrentAEL = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEvidenceAELRungZeroIsNarrowerThanRungOne(t *testing.T) {
	recorderOnly := EvidenceAELInput{RecorderEnabled: true}
	if !evidenceAELRules[0].ok(recorderOnly) {
		t.Fatal("rung 0 rejected recorder-only evidence")
	}
	if evidenceAELRules[1].ok(recorderOnly) {
		t.Fatal("rung 1 accepted recorder-only evidence")
	}
}

func withEvidenceAEL(base EvidenceAELInput, mutate func(*EvidenceAELInput)) EvidenceAELInput {
	mutate(&base)
	return base
}

func TestEvidenceMetricsUseClosedLabelFallbacks(t *testing.T) {
	m := New()

	m.RecordEvidenceSequenceGap("attacker-controlled-source")
	if got := testutil.ToFloat64(m.evidenceSequenceGaps.WithLabelValues("unknown")); got != 1 {
		t.Fatalf("sequence_gaps_total{source=unknown} = %v, want 1", got)
	}
	m.RecordSelfAuditFailure("attacker-controlled-check")
	if got := testutil.ToFloat64(m.evidenceSelfAuditFailures.WithLabelValues("sampler_error")); got != 1 {
		t.Fatalf("selfaudit_failures_total{check=sampler_error} = %v, want 1", got)
	}
	m.SetEvidenceRequirement("attacker-controlled-requirement", true)
	if got := testutil.ToFloat64(m.evidenceAELRequirements.WithLabelValues("unknown")); got != 1 {
		t.Fatalf("ael_requirement_ok{requirement=unknown} = %v, want 1", got)
	}
}

func TestEvidenceMetricsSettersSnapshotsAndDynamicCollector(t *testing.T) {
	m := New()

	m.RecordFsyncError(true, 2)
	m.RecordFsyncError(false, 3)
	m.RecordFsyncError(true, 0)
	m.RecordRequiredReceiptBlock("durability", "fetch")
	m.RecordRequiredReceiptBlock("durability", "connect")
	gated, blocks := m.EvidenceCountersSnapshot()
	if gated != 2 || blocks != 2 {
		t.Fatalf("EvidenceCountersSnapshot = (%d, %d), want (2, 2)", gated, blocks)
	}
	gaps, fsync := m.EvidenceStatsCountersSnapshot()
	if gaps != (EvidenceGapStats{}) {
		t.Fatalf("initial gaps = %+v, want zero", gaps)
	}
	if fsync.Gated != 2 || fsync.Ungated != 3 {
		t.Fatalf("fsync stats = %+v, want gated=2 ungated=3", fsync)
	}

	m.RecordEvidenceSequenceGap("resume")
	m.RecordEvidenceSequenceGap("self_audit")
	gaps, _ = m.EvidenceStatsCountersSnapshot()
	if gaps.Resume != 1 || gaps.SelfAudit != 1 {
		t.Fatalf("gap stats = %+v, want resume=1 self_audit=1", gaps)
	}

	m.SetEvidenceSelfAuditOK(false)
	if got := testutil.ToFloat64(m.evidenceSelfAuditOK); got != 0 {
		t.Fatalf("selfaudit_ok gauge = %v, want 0", got)
	}
	m.SetEvidenceSelfAuditOK(true)
	if got := testutil.ToFloat64(m.evidenceSelfAuditOK); got != 1 {
		t.Fatalf("selfaudit_ok gauge = %v, want 1", got)
	}

	m.SetEvidenceHeartbeatInterval(15, true)
	if got := testutil.ToFloat64(m.evidenceHeartbeatInterval); got != 15 {
		t.Fatalf("heartbeat interval gauge = %v, want 15", got)
	}
	m.SetEvidenceHeartbeatInterval(15, false)
	if got := testutil.ToFloat64(m.evidenceHeartbeatInterval); !math.IsNaN(got) {
		t.Fatalf("disabled heartbeat interval gauge = %v, want NaN", got)
	}

	m.SetEvidenceAnchor(1234.5, 42)
	if got := testutil.ToFloat64(m.evidenceLastAnchorTimestamp); got != 1234.5 {
		t.Fatalf("last anchor timestamp gauge = %v, want 1234.5", got)
	}
	if got := testutil.ToFloat64(m.evidenceAnchoredFinalSeq); got != 42 {
		t.Fatalf("anchored final seq gauge = %v, want 42", got)
	}

	m.SetEvidenceRequirements(map[string]bool{
		EvidenceRequirementRecorderEnabled: true,
		EvidenceRequirementHeartbeats:      true,
		EvidenceRequirementSelfAuditOK:     true,
	})
	for req, want := range map[string]bool{
		EvidenceRequirementRecorderEnabled: true,
		EvidenceRequirementEmitterHealthy:  false,
		EvidenceRequirementDurabilityGate:  false,
		EvidenceRequirementHeartbeats:      true,
		EvidenceRequirementAnchoringFresh:  false,
		EvidenceRequirementCPCActive:       false,
		EvidenceRequirementSelfAuditOK:     true,
	} {
		if got := m.evidenceRequirementValues[req]; got != want {
			t.Fatalf("requirement %s = %v, want %v", req, got, want)
		}
		wantGauge := 0.0
		if want {
			wantGauge = 1
		}
		if got := testutil.ToFloat64(m.evidenceAELRequirements.WithLabelValues(req)); got != wantGauge {
			t.Fatalf("ael_requirement_ok{%s} = %v, want %v", req, got, wantGauge)
		}
	}

	age := 7.5
	stats := EvidenceHealthStats{
		Schema:                   "pipelock.evidencehealth.v1",
		CurrentAEL:               3,
		ChainHeadSeq:             9,
		ChainHeadAgeSeconds:      &age,
		AnchorLagReceipts:        4,
		HeartbeatIntervalSeconds: &age,
	}
	m.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
		return stats, true
	})
	gotStats, ok := m.EvidenceHealthStatsSnapshot()
	if !ok || gotStats.CurrentAEL != 3 || gotStats.ChainHeadSeq != 9 {
		t.Fatalf("EvidenceHealthStatsSnapshot = (%+v, %v), want stats ok", gotStats, ok)
	}
	if got := testutil.CollectAndCount(m.evidenceCollector); got != 4 {
		t.Fatalf("dynamic evidence collector emitted %d metrics, want 4", got)
	}

	rec := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
	var body struct {
		EvidenceHealth *EvidenceHealthStats `json:"evidence_health"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal stats: %v", err)
	}
	if body.EvidenceHealth == nil || body.EvidenceHealth.CurrentAEL != 3 || body.EvidenceHealth.ChainHeadSeq != 9 {
		t.Fatalf("stats evidence_health = %+v, want current_ael=3 chain_head_seq=9", body.EvidenceHealth)
	}

	m.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
		stats.ChainHeadAgeSeconds = nil
		return stats, true
	})
	if got := testutil.CollectAndCount(m.evidenceCollector); got != 3 {
		t.Fatalf("dynamic evidence collector emitted %d metrics without age, want 3", got)
	}
}

func TestEvidenceMetricsNilAndZeroValueFailClosed(t *testing.T) {
	var nilMetrics *Metrics
	nilMetrics.RecordFsyncError(true, 1)
	nilMetrics.SetEvidenceSelfAuditOK(false)
	nilMetrics.SetEvidenceHeartbeatInterval(1, true)
	nilMetrics.SetEvidenceAnchor(1, 1)
	nilMetrics.SetEvidenceRequirement(EvidenceRequirementRecorderEnabled, true)
	nilMetrics.SetEvidenceRequirements(map[string]bool{EvidenceRequirementRecorderEnabled: true})
	nilMetrics.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) { return EvidenceHealthStats{}, true })
	if got, blocks := nilMetrics.EvidenceCountersSnapshot(); got != 0 || blocks != 0 {
		t.Fatalf("nil EvidenceCountersSnapshot = (%d, %d), want zero", got, blocks)
	}
	if gaps, fsync := nilMetrics.EvidenceStatsCountersSnapshot(); gaps != (EvidenceGapStats{}) || fsync != (EvidenceFsyncStats{}) {
		t.Fatalf("nil EvidenceStatsCountersSnapshot = (%+v, %+v), want zero", gaps, fsync)
	}
	if stats, ok := nilMetrics.EvidenceHealthStatsSnapshot(); ok || stats.CurrentAEL != 0 || stats.Requirements != nil {
		t.Fatalf("nil EvidenceHealthStatsSnapshot = (%+v, %v), want zero false", stats, ok)
	}

	zero := &Metrics{}
	zero.RecordFsyncError(true, 2)
	zero.SetEvidenceSelfAuditOK(false)
	zero.SetEvidenceHeartbeatInterval(1, true)
	zero.SetEvidenceAnchor(1, 1)
	zero.SetEvidenceRequirement(EvidenceRequirementRecorderEnabled, true)
	zero.SetEvidenceRequirements(nil)
	zero.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
		return EvidenceHealthStats{CurrentAEL: 1}, true
	})
	if stats, ok := zero.EvidenceHealthStatsSnapshot(); !ok || stats.CurrentAEL != 1 {
		t.Fatalf("zero-value health snapshot = (%+v, %v), want current_ael=1 ok", stats, ok)
	}
}

func TestNonNegativeInt64ToUint64(t *testing.T) {
	if got := nonNegativeInt64ToUint64(-7); got != 0 {
		t.Fatalf("negative conversion = %d, want 0", got)
	}
	if got := nonNegativeInt64ToUint64(0); got != 0 {
		t.Fatalf("zero conversion = %d, want 0", got)
	}
	if got := nonNegativeInt64ToUint64(12); got != 12 {
		t.Fatalf("positive conversion = %d, want 12", got)
	}
}

func TestEvidenceHealthUnmeasuredStatsNullAndDynamicGaugesAbsent(t *testing.T) {
	m := New()

	rec := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
	var body struct {
		EvidenceHealth *EvidenceHealthStats `json:"evidence_health"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal stats: %v", err)
	}
	if body.EvidenceHealth != nil {
		t.Fatalf("evidence_health = %+v, want null", body.EvidenceHealth)
	}

	if got := testutil.CollectAndCount(m.evidenceCollector); got != 0 {
		t.Fatalf("dynamic evidence collector emitted %d metrics, want 0 when unmeasured", got)
	}
	if strings.Contains(rec.Body.String(), `"current_ael":`) {
		t.Fatalf("stats included current_ael while evidence health is unmeasured: %s", rec.Body.String())
	}
}
