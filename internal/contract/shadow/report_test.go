// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testRuleIDA = "rule-a"
	testRuleIDB = "rule-b"
)

func TestAnalyze_BuildsBatchesAndQuarantineCandidate(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	records := shadowRecords(base, 4)

	report, err := Analyze(records, AnalyzeOptions{
		ContractHash: "sha256:contract",
		GeneratedAt:  base.Add(time.Hour),
		Aggregation:  AggregateConfig{WindowDuration: time.Hour, SampleCount: 3},
		Quarantine:   DefaultQuarantineConfig(),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.TotalRecords != 60 || report.Replayed != 60 || report.Changed != 4 || report.NewBlocks != 4 {
		t.Fatalf("report counts = %+v", report)
	}
	if len(report.Batches) != 1 {
		t.Fatalf("batches = %d, want 1", len(report.Batches))
	}
	if report.Batches[0].LosslessCount != 4 || len(report.Batches[0].ExemplarIDs) != 3 {
		t.Fatalf("batch = %+v, want four lossless and three exemplars", report.Batches[0])
	}
	if len(report.Quarantines) != 1 || report.Quarantines[0].RuleID != testRuleIDA {
		t.Fatalf("quarantines = %+v, want rule-a", report.Quarantines)
	}
	if got := report.Rules[0].State; got != quarantineStateCandidate {
		t.Fatalf("rule state = %q, want %q", got, quarantineStateCandidate)
	}
}

func TestAnalyze_QuarantineCooldownAndHysteresis(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	now := base.Add(2 * time.Hour)

	cooldownCfg := DefaultQuarantineConfig()
	cooldownCfg.LastQuarantinedAt = map[string]time.Time{testRuleIDA: now.Add(-30 * time.Minute)}
	report, err := Analyze(shadowRecords(base, 4), AnalyzeOptions{
		ContractHash: "sha256:contract",
		GeneratedAt:  now,
		Aggregation:  AggregateConfig{WindowDuration: time.Hour, SampleCount: 1},
		Quarantine:   cooldownCfg,
	})
	if err != nil {
		t.Fatalf("Analyze cooldown: %v", err)
	}
	if len(report.Quarantines) != 0 || report.Rules[0].Reason != quarantineReasonCooldown {
		t.Fatalf("cooldown report = %+v", report)
	}

	heldCfg := DefaultQuarantineConfig()
	heldCfg.ActiveRules = map[string]bool{testRuleIDA: true}
	held, err := Analyze(shadowRecords(base, 2), AnalyzeOptions{
		ContractHash: "sha256:contract",
		GeneratedAt:  now,
		Aggregation:  AggregateConfig{WindowDuration: time.Hour, SampleCount: 1},
		Quarantine:   heldCfg,
	})
	if err != nil {
		t.Fatalf("Analyze held: %v", err)
	}
	if held.Rules[0].State != quarantineStateHeld || held.Rules[0].Reason != quarantineReasonHeld {
		t.Fatalf("held rule = %+v", held.Rules[0])
	}

	released, err := Analyze(shadowRecords(base, 0), AnalyzeOptions{
		ContractHash: "sha256:contract",
		GeneratedAt:  now,
		Aggregation:  AggregateConfig{WindowDuration: time.Hour, SampleCount: 1},
		Quarantine:   heldCfg,
	})
	if err != nil {
		t.Fatalf("Analyze released: %v", err)
	}
	if released.Rules[0].State != quarantineStateReleased || released.Rules[0].Reason != quarantineReasonReleased {
		t.Fatalf("released rule = %+v", released.Rules[0])
	}
}

func TestAnalyze_DefaultQuarantineThresholdsPreserveState(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	cfg := QuarantineConfig{
		LastQuarantinedAt: map[string]time.Time{testRuleIDA: base.Add(-30 * time.Minute)},
		RecentPageTimes:   []time.Time{base.Add(-time.Minute)},
	}
	report, err := Analyze(shadowRecords(base, 4), AnalyzeOptions{
		ContractHash: "sha256:contract",
		GeneratedAt:  base,
		Aggregation:  AggregateConfig{WindowDuration: time.Hour, SampleCount: 1},
		Quarantine:   cfg,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if report.Rules[0].Reason != quarantineReasonCooldown {
		t.Fatalf("rule reason = %q, want preserved cooldown state", report.Rules[0].Reason)
	}
}

func TestRenderJSONMarkdownAndDiffReports(t *testing.T) {
	t.Parallel()
	report := Report{
		ReportVersion: reportVersion,
		GeneratedAt:   time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		ContractHash:  "sha256:contract",
		TotalRecords:  10,
		NewBlocks:     1,
		Rules: []RuleStats{{
			RuleID:          testRuleIDA,
			Evaluations:     10,
			NewBlocks:       1,
			NewBlockRatePct: 10,
			State:           quarantineStateCandidate,
		}},
	}
	var jsonBuf bytes.Buffer
	if err := RenderJSON(&jsonBuf, report); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal rendered JSON: %v", err)
	}
	var md bytes.Buffer
	if err := RenderMarkdown(&md, report); err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !bytes.Contains(md.Bytes(), []byte("Shadow Report")) {
		t.Fatalf("markdown missing title:\n%s", md.String())
	}

	next := report
	next.Rules = append([]RuleStats(nil), report.Rules...)
	next.TotalRecords = 12
	next.Rules[0].NewBlocks = 3
	diff := DiffReports(report, next)
	if len(diff) != 1 || diff[0].NewBlocks != 2 {
		t.Fatalf("DiffReports = %+v, want +2 new blocks", diff)
	}
}

func TestQuarantineConfigValidateRejectsInvalidValues(t *testing.T) {
	t.Parallel()
	for _, cfg := range []QuarantineConfig{
		{CeilingPct: 0, ReleaseFloorPct: 0, MinEvaluations: 50, Cooldown: time.Hour, PageLimitPerHour: 5},
		{CeilingPct: 5, ReleaseFloorPct: 5, MinEvaluations: 50, Cooldown: time.Hour, PageLimitPerHour: 5},
		{CeilingPct: 5, ReleaseFloorPct: 1, MinEvaluations: 0, Cooldown: time.Hour, PageLimitPerHour: 5},
		{CeilingPct: 5, ReleaseFloorPct: 1, MinEvaluations: 50, Cooldown: 0, PageLimitPerHour: 5},
		{CeilingPct: 5, ReleaseFloorPct: 1, MinEvaluations: 50, Cooldown: time.Hour, PageLimitPerHour: 0},
	} {
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidQuarantineConfig) {
			t.Fatalf("Validate(%+v) error = %v, want ErrInvalidQuarantineConfig", cfg, err)
		}
	}
}

func TestAnalyze_DefaultsSkipsAndValidation(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	if _, err := Analyze(nil, AnalyzeOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Analyze empty hash error = %v, want ErrInvalidConfig", err)
	}
	if _, err := Analyze(nil, AnalyzeOptions{
		ContractHash: "sha256:contract",
		Aggregation:  AggregateConfig{WindowDuration: -time.Minute, SampleCount: 1},
		Quarantine:   DefaultQuarantineConfig(),
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Analyze invalid aggregation error = %v, want ErrInvalidConfig", err)
	}
	if _, err := Analyze(nil, AnalyzeOptions{
		ContractHash: "sha256:contract",
		Aggregation:  AggregateConfig{WindowDuration: time.Minute, SampleCount: 1},
		Quarantine: QuarantineConfig{
			CeilingPct:       -1,
			ReleaseFloorPct:  0,
			MinEvaluations:   1,
			Cooldown:         time.Hour,
			PageLimitPerHour: 1,
		},
	}); !errors.Is(err, ErrInvalidQuarantineConfig) {
		t.Fatalf("Analyze invalid quarantine error = %v, want ErrInvalidQuarantineConfig", err)
	}

	records := []capture.ReplayedRecord{
		{
			Summary: capture.CaptureSummary{Surface: capture.SurfaceCEE},
			Result:  capture.ReplayResult{EvidenceOnly: true, CaptureGrade: capture.CaptureGradeNone},
		},
		{
			Summary: capture.CaptureSummary{Surface: capture.SurfaceResponse},
			Result:  capture.ReplayResult{SummaryOnly: true, CaptureGrade: capture.CaptureGradeSummary},
		},
		{
			Summary: capture.CaptureSummary{Surface: capture.SurfaceDLP},
			Result: capture.ReplayResult{
				OriginalAction:  config.ActionAllow,
				CandidateAction: config.ActionAllow,
				CaptureGrade:    capture.CaptureGradePartial,
			},
		},
		{
			Timestamp: base,
			Summary:   capture.CaptureSummary{Surface: capture.SurfaceURL, Request: capture.CaptureRequest{URL: "https://api.example.com"}},
			Result: capture.ReplayResult{
				OriginalAction:  config.ActionBlock,
				CandidateAction: config.ActionAllow,
				Changed:         true,
				CaptureGrade:    capture.CaptureGradeFull,
				CandidateFindings: []capture.Finding{
					{Kind: capture.KindContract, PolicyRule: testRuleIDB},
					{Kind: capture.KindContract, PolicyRule: testRuleIDB},
					{Kind: capture.KindDLP, PolicyRule: "ignored"},
				},
			},
		},
	}
	report, err := Analyze(records, AnalyzeOptions{ContractHash: "sha256:contract", GeneratedAt: base})
	if err != nil {
		t.Fatalf("Analyze defaults: %v", err)
	}
	if report.EvidenceOnly != 1 || report.SummaryOnly != 1 || report.Replayed != 2 || report.NewAllows != 1 {
		t.Fatalf("report skip counts = %+v", report)
	}
	if len(report.Rules) != 1 || report.Rules[0].RuleID != testRuleIDB || report.Rules[0].NewAllows != 1 {
		t.Fatalf("rule stats = %+v", report.Rules)
	}
	if got := report.CaptureSurfaces[capture.SurfaceDLP].Grade; got != capture.CaptureGradePartial {
		t.Fatalf("surface grade = %q, want partial", got)
	}

	empty, err := Analyze(nil, AnalyzeOptions{ContractHash: "sha256:contract"})
	if err != nil {
		t.Fatalf("Analyze empty defaults: %v", err)
	}
	if empty.CaptureSurfaces != nil || empty.GeneratedAt.IsZero() {
		t.Fatalf("empty report surfaces/time = %#v/%s, want nil surfaces and generated time", empty.CaptureSurfaces, empty.GeneratedAt)
	}
	if _, err := Analyze([]capture.ReplayedRecord{{
		Result: capture.ReplayResult{
			Changed: true,
			CandidateFindings: []capture.Finding{{
				Kind:       capture.KindContract,
				PolicyRule: testRuleIDB,
			}},
		},
	}}, AnalyzeOptions{
		ContractHash: "sha256:contract",
		GeneratedAt:  base,
		Aggregation:  AggregateConfig{WindowDuration: time.Minute, SampleCount: 1},
		Quarantine:   DefaultQuarantineConfig(),
	}); !errors.Is(err, ErrInvalidDelta) {
		t.Fatalf("Analyze invalid delta error = %v, want ErrInvalidDelta", err)
	}
}

func TestQuarantineDecisionPageLimitThinSampleAndClear(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	cfg := DefaultQuarantineConfig()
	cfg.MinEvaluations = 10
	cfg.ActiveRules = map[string]bool{"thin": true}
	state, reason, event := quarantineDecision(RuleStats{RuleID: "thin", Evaluations: 9}, cfg, now)
	if state != quarantineStateHeld || reason != quarantineReasonThinSample || event != nil {
		t.Fatalf("thin decision = %s/%s/%+v", state, reason, event)
	}
	cfg.ActiveRules = nil
	state, reason, event = quarantineDecision(RuleStats{RuleID: "clear", Evaluations: 10, NewBlocks: 0}, cfg, now)
	if state != quarantineStateClear || reason != "" || event != nil {
		t.Fatalf("clear decision = %s/%s/%+v", state, reason, event)
	}
	cfg.RecentPageTimes = []time.Time{now.Add(-time.Minute)}
	cfg.PageLimitPerHour = 1
	state, reason, event = quarantineDecision(RuleStats{
		RuleID:          "limited",
		Evaluations:     10,
		NewBlocks:       2,
		NewBlockRatePct: 20,
	}, cfg, now)
	if state != quarantineStateClear || reason != quarantineReasonPageLimit || event != nil {
		t.Fatalf("page limited decision = %s/%s/%+v", state, reason, event)
	}
	if recentPages(now, []time.Time{now.Add(-2 * time.Hour), now.Add(-30 * time.Minute), now.Add(time.Minute)}) != 1 {
		t.Fatal("recentPages did not count only timestamps in the last hour and not in the future")
	}
	ids := contractRuleIDs([]capture.Finding{{
		Kind:       capture.KindContract,
		PolicyRule: " rule-a, ,rule-b,rule-a ",
	}})
	if len(ids) != 2 || ids[0] != testRuleIDA || ids[1] != testRuleIDB {
		t.Fatalf("contractRuleIDs = %#v, want trimmed unique ids", ids)
	}
}

func TestRenderMarkdownNoRulesAndRankFallbacks(t *testing.T) {
	t.Parallel()
	var md bytes.Buffer
	if err := RenderMarkdown(&md, Report{GeneratedAt: time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !bytes.Contains(md.Bytes(), []byte("No contract rule evaluations.")) {
		t.Fatalf("markdown =\n%s", md.String())
	}
	md.Reset()
	if err := RenderMarkdown(&md, Report{
		GeneratedAt: time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		Quarantines: []QuarantineEvent{{
			RuleID:          testRuleIDA,
			Evaluations:     60,
			NewBlocks:       4,
			NewBlockRatePct: 6.67,
			CooldownUntil:   time.Date(2026, 4, 30, 13, 0, 0, 0, time.UTC),
		}},
	}); err != nil {
		t.Fatalf("RenderMarkdown quarantine: %v", err)
	}
	if !bytes.Contains(md.Bytes(), []byte("cooldown until")) {
		t.Fatalf("markdown missing quarantine entry:\n%s", md.String())
	}
	for _, grade := range []string{
		capture.CaptureGradeNone,
		capture.CaptureGradeSummary,
		capture.CaptureGradePartial,
		capture.CaptureGradeFull,
		"bogus",
	} {
		_ = captureGradeRank(grade)
	}
}

func shadowRecords(base time.Time, newBlocks int) []capture.ReplayedRecord {
	const total = 60
	records := make([]capture.ReplayedRecord, 0, total)
	for i := 0; i < total; i++ {
		changed := i < newBlocks
		candidate := config.ActionAllow
		if changed {
			candidate = config.ActionBlock
		}
		records = append(records, capture.ReplayedRecord{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Summary: capture.CaptureSummary{
				Surface: capture.SurfaceURL,
				Request: capture.CaptureRequest{
					Method: "GET",
					URL:    "https://api.example.com/repos/foo",
				},
			},
			Result: capture.ReplayResult{
				OriginalAction:  config.ActionAllow,
				CandidateAction: candidate,
				Changed:         changed,
				CaptureGrade:    capture.CaptureGradeFull,
				CandidateFindings: []capture.Finding{{
					Kind:       capture.KindContract,
					Action:     candidate,
					PolicyRule: testRuleIDA,
				}},
			},
		})
	}
	return records
}
