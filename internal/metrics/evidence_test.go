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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestEvidenceLocalRecorderOperationalTable(t *testing.T) {
	base := EvidenceOperationalInput{
		RecorderEnabled: true,
		EmitterHealthy:  true,
		SelfAuditOK:     true,
	}
	tests := []struct {
		name string
		in   EvidenceOperationalInput
		want bool
	}{
		{name: "recorder_disabled", in: EvidenceOperationalInput{}, want: false},
		{name: "recorder_only", in: EvidenceOperationalInput{RecorderEnabled: true}, want: false},
		{name: "selfaudit_latched_bad", in: EvidenceOperationalInput{RecorderEnabled: true, EmitterHealthy: true}, want: false},
		{name: "local_process_healthy", in: base, want: true},
		{name: "unresolved_gap", in: withEvidenceOperational(base, func(in *EvidenceOperationalInput) {
			in.UnresolvedGaps = true
		}), want: false},
		{name: "ungated_fsync_failure", in: withEvidenceOperational(base, func(in *EvidenceOperationalInput) {
			in.UngatedFsyncFail = true
		}), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvidenceLocalRecorderOperational(tt.in); got != tt.want {
				t.Fatalf("EvidenceLocalRecorderOperational = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvidenceHealthStatsSnapshotRejectsAlternateAELProducer(t *testing.T) {
	m := New()
	producerRunID := "producer-chosen-run"
	m.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
		return EvidenceHealthStats{
			Schema:     "pipelock.evidencehealth.v1",
			CurrentAEL: "AEL-4",
			RunState:   "VERIFIED",
			RunID:      &producerRunID,
			AELArtifactCapability: EvidenceArtifactCapability{
				AELFormatVersions:        []int{4},
				BoundedRuns:              true,
				ClosedRunExport:          true,
				VerificationResultImport: true,
			},
		}, true
	})
	stats, ok := m.EvidenceHealthStatsSnapshot()
	if !ok {
		t.Fatal("EvidenceHealthStatsSnapshot unavailable")
	}
	if stats.Schema != EvidenceHealthSchemaV2 {
		t.Fatalf("Schema = %q, want %q: a preserved legacy schema points a schema-selecting decoder at the wrong contract", stats.Schema, EvidenceHealthSchemaV2)
	}
	if stats.CurrentAEL != EvidenceCurrentAELUnavailable {
		t.Fatalf("CurrentAEL = %q, want %q", stats.CurrentAEL, EvidenceCurrentAELUnavailable)
	}
	if stats.RunState != EvidenceRunStateOpen || stats.RunID != nil {
		t.Fatalf("run lifecycle = %q/%v, want OPEN with no bounded run id", stats.RunState, stats.RunID)
	}
	if stats.AELArtifactCapability.BoundedRuns || stats.AELArtifactCapability.ClosedRunExport || stats.AELArtifactCapability.VerificationResultImport || len(stats.AELArtifactCapability.AELFormatVersions) != 0 {
		t.Fatalf("capability callback restored unsupported claim: %+v", stats.AELArtifactCapability)
	}
}

func TestCurrentEvidenceArtifactCapabilityDoesNotDeclareGrade(t *testing.T) {
	capability := CurrentEvidenceArtifactCapability()
	raw, err := json.Marshal(capability)
	if err != nil {
		t.Fatalf("Marshal capability: %v", err)
	}
	for _, forbidden := range []string{"current_ael", "maximum_ael", "target_ael", "verified"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("capability declaration contains forbidden grade/status field %q: %s", forbidden, raw)
		}
	}
	if capability.Schema == "" || capability.AELFormatVersions == nil {
		t.Fatalf("capability declaration is not explicit: %+v", capability)
	}
	if capability.BoundedRuns || capability.ClosedRunExport || capability.VerificationResultImport || len(capability.AELFormatVersions) != 0 {
		t.Fatalf("capability overstates current implementation: %+v", capability)
	}
}

func withEvidenceOperational(base EvidenceOperationalInput, mutate func(*EvidenceOperationalInput)) EvidenceOperationalInput {
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
	m.RecordEvidenceAnchorStateSkipped(2)
	m.RecordEvidenceAnchorStateSkipped(0)
	if got := testutil.ToFloat64(m.evidenceAnchorStateSkipped); got != 2 {
		t.Fatalf("anchor_state_skipped_total = %v, want 2", got)
	}
	m.RecordEvidenceAutoAnchorAttempt()
	m.RecordEvidenceAutoAnchorSuccess()
	m.RecordEvidenceAutoAnchorAttempt()
	m.RecordEvidenceAutoAnchorFailure(" test failure ")
	autoAnchor := m.EvidenceAutoAnchorStatsSnapshot()
	if autoAnchor.Attempts != 2 || autoAnchor.Successes != 1 || autoAnchor.Failures != 1 || autoAnchor.LastError != "test failure" {
		t.Fatalf("auto-anchor stats = %+v, want 2/1/1 and last error", autoAnchor)
	}
	for name, metric := range map[string]prometheus.Counter{
		"attempts":  m.evidenceAutoAnchorAttempts,
		"successes": m.evidenceAutoAnchorSuccesses,
		"failures":  m.evidenceAutoAnchorFailures,
	} {
		want := 1.0
		if name == "attempts" {
			want = 2
		}
		if got := testutil.ToFloat64(metric); got != want {
			t.Fatalf("auto-anchor %s counter = %v, want %v", name, got, want)
		}
	}
	// An oversized last-error string is truncated to the rune bound so a hostile
	// failure message cannot grow the stats snapshot without limit.
	m.RecordEvidenceAutoAnchorFailure(strings.Repeat("x", 5000))
	if truncated := m.EvidenceAutoAnchorStatsSnapshot().LastError; len([]rune(truncated)) != 1024 {
		t.Fatalf("oversized last error rune length = %d, want 1024", len([]rune(truncated)))
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
		Schema:                   "pipelock.evidencehealth.v2",
		LocalRecorderOperational: true,
		RunState:                 EvidenceRunStateOpen,
		AELArtifactCapability:    CurrentEvidenceArtifactCapability(),
		ChainHeadSeq:             9,
		ChainHeadAgeSeconds:      &age,
		AnchorLagReceipts:        4,
		HeartbeatIntervalSeconds: &age,
	}
	m.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
		return stats, true
	})
	gotStats, ok := m.EvidenceHealthStatsSnapshot()
	if !ok || gotStats.CurrentAEL != EvidenceCurrentAELUnavailable || !gotStats.LocalRecorderOperational || gotStats.ChainHeadSeq != 9 {
		t.Fatalf("EvidenceHealthStatsSnapshot = (%+v, %v), want stats ok", gotStats, ok)
	}
	if got := testutil.CollectAndCount(m.evidenceCollector); got != 5 {
		t.Fatalf("dynamic evidence collector emitted %d metrics, want 5", got)
	}

	rec := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
	var body struct {
		EvidenceHealth *EvidenceHealthStats `json:"evidence_health"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal stats: %v", err)
	}
	if !strings.Contains(rec.Body.String(), `"current_ael":"UNAVAILABLE"`) {
		t.Fatalf("stats did not retain deprecated current_ael as UNAVAILABLE: %s", rec.Body.String())
	}
	if body.EvidenceHealth == nil || body.EvidenceHealth.CurrentAEL != EvidenceCurrentAELUnavailable || !body.EvidenceHealth.LocalRecorderOperational || body.EvidenceHealth.RunState != EvidenceRunStateOpen || body.EvidenceHealth.RunID != nil || body.EvidenceHealth.ChainHeadSeq != 9 {
		t.Fatalf("stats evidence_health = %+v, want current_ael=UNAVAILABLE local_recorder_operational=true OPEN unbounded run and chain_head_seq=9", body.EvidenceHealth)
	}
	if body.EvidenceHealth.AELArtifactCapability.Schema == "" || body.EvidenceHealth.AELArtifactCapability.AELFormatVersions == nil {
		t.Fatalf("stats capability declaration is not explicit: %+v", body.EvidenceHealth.AELArtifactCapability)
	}

	m.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
		stats.ChainHeadAgeSeconds = nil
		return stats, true
	})
	if got := testutil.CollectAndCount(m.evidenceCollector); got != 4 {
		t.Fatalf("dynamic evidence collector emitted %d metrics without age, want 4", got)
	}
}

func TestEvidenceMetricsNilAndZeroValueFailClosed(t *testing.T) {
	var nilMetrics *Metrics
	nilMetrics.RecordFsyncError(true, 1)
	nilMetrics.SetEvidenceSelfAuditOK(false)
	nilMetrics.SetEvidenceHeartbeatInterval(1, true)
	nilMetrics.SetEvidenceAnchor(1, 1)
	nilMetrics.RecordEvidenceAnchorStateSkipped(1)
	nilMetrics.RecordEvidenceAutoAnchorAttempt()
	nilMetrics.RecordEvidenceAutoAnchorSuccess()
	nilMetrics.RecordEvidenceAutoAnchorFailure("failure")
	nilMetrics.SetEvidenceRequirement(EvidenceRequirementRecorderEnabled, true)
	nilMetrics.SetEvidenceRequirements(map[string]bool{EvidenceRequirementRecorderEnabled: true})
	nilMetrics.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) { return EvidenceHealthStats{}, true })
	if got, blocks := nilMetrics.EvidenceCountersSnapshot(); got != 0 || blocks != 0 {
		t.Fatalf("nil EvidenceCountersSnapshot = (%d, %d), want zero", got, blocks)
	}
	if gaps, fsync := nilMetrics.EvidenceStatsCountersSnapshot(); gaps != (EvidenceGapStats{}) || fsync != (EvidenceFsyncStats{}) {
		t.Fatalf("nil EvidenceStatsCountersSnapshot = (%+v, %+v), want zero", gaps, fsync)
	}
	if got := nilMetrics.EvidenceAutoAnchorStatsSnapshot(); got != (EvidenceAutoAnchorStats{}) {
		t.Fatalf("nil auto-anchor stats = %+v, want zero", got)
	}
	if stats, ok := nilMetrics.EvidenceHealthStatsSnapshot(); ok || stats.CurrentAEL != "" || stats.Requirements != nil {
		t.Fatalf("nil EvidenceHealthStatsSnapshot = (%+v, %v), want zero false", stats, ok)
	}

	zero := &Metrics{}
	zero.RecordFsyncError(true, 2)
	zero.SetEvidenceSelfAuditOK(false)
	zero.SetEvidenceHeartbeatInterval(1, true)
	zero.SetEvidenceAnchor(1, 1)
	zero.RecordEvidenceAnchorStateSkipped(1)
	zero.SetEvidenceRequirement(EvidenceRequirementRecorderEnabled, true)
	zero.SetEvidenceRequirements(nil)
	zero.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
		return EvidenceHealthStats{CurrentAEL: "AEL-1"}, true
	})
	if stats, ok := zero.EvidenceHealthStatsSnapshot(); !ok || stats.CurrentAEL != EvidenceCurrentAELUnavailable {
		t.Fatalf("zero-value health snapshot = (%+v, %v), want current_ael=UNAVAILABLE ok", stats, ok)
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

func TestEvidenceCollectorSeparatesLocalOperationFromDeprecatedAEL(t *testing.T) {
	tests := []struct {
		name        string
		operational bool
		wantGauge   float64
	}{
		{name: "operational", operational: true, wantGauge: 1},
		{name: "not operational", operational: false, wantGauge: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
				return EvidenceHealthStats{CurrentAEL: "AEL-4", LocalRecorderOperational: tc.operational, ChainHeadSeq: 9}, true
			})
			reg := prometheus.NewPedanticRegistry()
			if err := reg.Register(m.evidenceCollector); err != nil {
				t.Fatalf("register evidence collector: %v", err)
			}
			fams, err := reg.Gather()
			if err != nil {
				t.Fatalf("gather: %v", err)
			}
			foundCurrent := false
			foundOperational := false
			for _, fam := range fams {
				switch fam.GetName() {
				case "pipelock_evidence_current_ael":
					foundCurrent = true
					if v := fam.GetMetric()[0].GetGauge().GetValue(); !math.IsNaN(v) {
						t.Fatalf("exported pipelock_evidence_current_ael = %v, want NaN", v)
					}
				case "pipelock_evidence_local_recorder_operational":
					foundOperational = true
					if v := fam.GetMetric()[0].GetGauge().GetValue(); v != tc.wantGauge {
						t.Fatalf("exported pipelock_evidence_local_recorder_operational = %v, want %v", v, tc.wantGauge)
					}
				}
			}
			if !foundCurrent || !foundOperational {
				t.Fatalf("metric presence current_ael=%v local_recorder_operational=%v, want both", foundCurrent, foundOperational)
			}
		})
	}
}

func TestStatsHandlerUnavailableEvidenceHealthIsNull(t *testing.T) {
	m := New()
	m.SetEvidenceHealthFunc(func() (EvidenceHealthStats, bool) {
		return EvidenceHealthStats{}, false
	})
	rec := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
	var body struct {
		EvidenceHealth json.RawMessage `json:"evidence_health"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal stats: %v", err)
	}
	if got := strings.TrimSpace(string(body.EvidenceHealth)); got != "null" {
		t.Fatalf("evidence_health = %q, want JSON null when the snapshot is unavailable", got)
	}
}
