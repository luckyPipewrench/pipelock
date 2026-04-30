// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	reportVersion = 1

	defaultQuarantineCeilingPct = 5.0
	defaultQuarantineReleasePct = 1.0
	defaultQuarantineMinEval    = 50
	defaultQuarantineCooldown   = time.Hour
	defaultQuarantinePageLimit  = 5
	defaultShadowReportTitle    = "Shadow Report"
	quarantineStateClear        = "clear"
	quarantineStateCandidate    = "candidate"
	quarantineStateHeld         = "held"
	quarantineStateReleased     = "released"
	quarantineReasonRate        = "new_block_rate_above_ceiling"
	quarantineReasonCooldown    = "cooldown_active"
	quarantineReasonPageLimit   = "page_rate_limited"
	quarantineReasonHeld        = "above_release_floor"
	quarantineReasonReleased    = "below_release_floor"
	quarantineReasonThinSample  = "below_denominator_floor"
)

// ErrInvalidQuarantineConfig rejects unusable quarantine thresholds.
var ErrInvalidQuarantineConfig = errors.New("shadow: invalid quarantine config")

// QuarantineConfig controls flap-resistant quarantine decisions.
type QuarantineConfig struct {
	CeilingPct        float64
	ReleaseFloorPct   float64
	MinEvaluations    int
	Cooldown          time.Duration
	PageLimitPerHour  int
	ActiveRules       map[string]bool
	LastQuarantinedAt map[string]time.Time
	RecentPageTimes   []time.Time
}

// DefaultQuarantineConfig returns the standard shadow quarantine thresholds.
func DefaultQuarantineConfig() QuarantineConfig {
	return QuarantineConfig{
		CeilingPct:       defaultQuarantineCeilingPct,
		ReleaseFloorPct:  defaultQuarantineReleasePct,
		MinEvaluations:   defaultQuarantineMinEval,
		Cooldown:         defaultQuarantineCooldown,
		PageLimitPerHour: defaultQuarantinePageLimit,
	}
}

// Validate reports invalid quarantine settings.
func (cfg QuarantineConfig) Validate() error {
	if cfg.CeilingPct <= 0 || cfg.CeilingPct > 100 {
		return fmt.Errorf("%w: ceiling_pct=%v", ErrInvalidQuarantineConfig, cfg.CeilingPct)
	}
	if cfg.ReleaseFloorPct < 0 || cfg.ReleaseFloorPct >= cfg.CeilingPct {
		return fmt.Errorf("%w: release_floor_pct=%v ceiling_pct=%v", ErrInvalidQuarantineConfig, cfg.ReleaseFloorPct, cfg.CeilingPct)
	}
	if cfg.MinEvaluations <= 0 {
		return fmt.Errorf("%w: min_evaluations=%d", ErrInvalidQuarantineConfig, cfg.MinEvaluations)
	}
	if cfg.Cooldown <= 0 {
		return fmt.Errorf("%w: cooldown=%s", ErrInvalidQuarantineConfig, cfg.Cooldown)
	}
	if cfg.PageLimitPerHour <= 0 {
		return fmt.Errorf("%w: page_limit_per_hour=%d", ErrInvalidQuarantineConfig, cfg.PageLimitPerHour)
	}
	return nil
}

// AnalyzeOptions controls conversion of replayed records into shadow output.
type AnalyzeOptions struct {
	ContractHash string
	GeneratedAt  time.Time
	Aggregation  AggregateConfig
	Quarantine   QuarantineConfig
}

// RuleStats summarizes one contract rule in a shadow run.
type RuleStats struct {
	RuleID          string  `json:"rule_id"`
	Evaluations     int     `json:"evaluations"`
	NewBlocks       int     `json:"new_blocks"`
	NewAllows       int     `json:"new_allows"`
	Unchanged       int     `json:"unchanged"`
	NewBlockRatePct float64 `json:"new_block_rate_pct"`
	State           string  `json:"state"`
	Reason          string  `json:"reason,omitempty"`
}

// QuarantineEvent records one rule quarantine recommendation.
type QuarantineEvent struct {
	RuleID          string    `json:"rule_id"`
	Reason          string    `json:"reason"`
	Evaluations     int       `json:"evaluations"`
	NewBlocks       int       `json:"new_blocks"`
	NewBlockRatePct float64   `json:"new_block_rate_pct"`
	CooldownUntil   time.Time `json:"cooldown_until"`
}

// Report is the JSON and markdown surface for a shadow run.
type Report struct {
	ReportVersion   int                              `json:"report_version"`
	GeneratedAt     time.Time                        `json:"generated_at"`
	ContractHash    string                           `json:"contract_hash"`
	TotalRecords    int                              `json:"total_records"`
	Replayed        int                              `json:"replayed"`
	Changed         int                              `json:"changed"`
	NewBlocks       int                              `json:"new_blocks"`
	NewAllows       int                              `json:"new_allows"`
	EvidenceOnly    int                              `json:"evidence_only"`
	SummaryOnly     int                              `json:"summary_only"`
	Rules           []RuleStats                      `json:"rules"`
	Quarantines     []QuarantineEvent                `json:"quarantines,omitempty"`
	Batches         []Batch                          `json:"batches,omitempty"`
	CaptureSurfaces map[string]capture.SurfaceStatus `json:"capture_surfaces,omitempty"`
}

type mutableRuleStats struct {
	RuleStats
}

// Analyze converts replay output into shadow deltas, aggregate batches, and
// quarantine recommendations.
func Analyze(records []capture.ReplayedRecord, opts AnalyzeOptions) (Report, error) {
	if opts.ContractHash == "" {
		return Report{}, fmt.Errorf("%w: contract_hash", ErrInvalidConfig)
	}
	if opts.Aggregation.WindowDuration == 0 && opts.Aggregation.SampleCount == 0 {
		opts.Aggregation = DefaultAggregateConfig()
	}
	if err := opts.Aggregation.Validate(); err != nil {
		return Report{}, err
	}
	if opts.Quarantine.CeilingPct == 0 && opts.Quarantine.ReleaseFloorPct == 0 &&
		opts.Quarantine.MinEvaluations == 0 && opts.Quarantine.Cooldown == 0 &&
		opts.Quarantine.PageLimitPerHour == 0 {
		defaults := DefaultQuarantineConfig()
		opts.Quarantine.CeilingPct = defaults.CeilingPct
		opts.Quarantine.ReleaseFloorPct = defaults.ReleaseFloorPct
		opts.Quarantine.MinEvaluations = defaults.MinEvaluations
		opts.Quarantine.Cooldown = defaults.Cooldown
		opts.Quarantine.PageLimitPerHour = defaults.PageLimitPerHour
	}
	if err := opts.Quarantine.Validate(); err != nil {
		return Report{}, err
	}
	now := opts.GeneratedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	report := Report{
		ReportVersion:   reportVersion,
		GeneratedAt:     now.UTC(),
		ContractHash:    opts.ContractHash,
		TotalRecords:    len(records),
		CaptureSurfaces: map[string]capture.SurfaceStatus{},
	}
	stats := map[string]*mutableRuleStats{}
	var deltas []Delta
	for _, record := range records {
		report.recordSurface(record)
		if record.Result.EvidenceOnly {
			report.EvidenceOnly++
			continue
		}
		if record.Result.SummaryOnly {
			report.SummaryOnly++
			continue
		}
		report.Replayed++
		if record.Result.Changed {
			report.Changed++
		}
		if isNewBlock(record.Result.OriginalAction, record.Result.CandidateAction) {
			report.NewBlocks++
		} else if record.Result.Changed {
			report.NewAllows++
		}
		ruleIDs := contractRuleIDs(record.Result.CandidateFindings)
		if len(ruleIDs) == 0 {
			continue
		}
		for _, ruleID := range ruleIDs {
			s := statsForRule(stats, ruleID)
			s.Evaluations++
			switch {
			case isNewBlock(record.Result.OriginalAction, record.Result.CandidateAction):
				s.NewBlocks++
			case record.Result.Changed:
				s.NewAllows++
			default:
				s.Unchanged++
			}
			if record.Result.Changed {
				observedAt := record.Timestamp
				if observedAt.IsZero() {
					observedAt = now
				}
				deltas = append(deltas, Delta{
					ContractHash:     opts.ContractHash,
					RuleID:           ruleID,
					OriginalVerdict:  record.Result.OriginalAction,
					CandidateVerdict: record.Result.CandidateAction,
					ExemplarID:       exemplarID(record),
					ObservedAt:       observedAt,
				})
			}
		}
	}
	if len(report.CaptureSurfaces) == 0 {
		report.CaptureSurfaces = nil
	}

	batches, err := Aggregate(deltas, opts.Aggregation)
	if err != nil {
		return Report{}, err
	}
	report.Batches = batches
	report.Rules, report.Quarantines = finalizeRuleStats(stats, opts.Quarantine, now)
	return report, nil
}

func (r *Report) recordSurface(record capture.ReplayedRecord) {
	if record.Summary.Surface == "" || record.Result.CaptureGrade == "" {
		return
	}
	current := r.CaptureSurfaces[record.Summary.Surface]
	if captureGradeRank(record.Result.CaptureGrade) > captureGradeRank(current.Grade) {
		current.Grade = record.Result.CaptureGrade
	}
	current.Sidecar = current.Sidecar || record.Result.SidecarDecrypted
	r.CaptureSurfaces[record.Summary.Surface] = current
}

func statsForRule(stats map[string]*mutableRuleStats, ruleID string) *mutableRuleStats {
	s := stats[ruleID]
	if s == nil {
		s = &mutableRuleStats{RuleStats: RuleStats{RuleID: ruleID}}
		stats[ruleID] = s
	}
	return s
}

func finalizeRuleStats(stats map[string]*mutableRuleStats, cfg QuarantineConfig, now time.Time) ([]RuleStats, []QuarantineEvent) {
	rules := make([]RuleStats, 0, len(stats))
	for _, s := range stats {
		if s.Evaluations > 0 {
			s.NewBlockRatePct = float64(s.NewBlocks) * 100 / float64(s.Evaluations)
		}
		rules = append(rules, s.RuleStats)
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })

	events := make([]QuarantineEvent, 0)
	recent := append([]time.Time(nil), cfg.RecentPageTimes...)
	for i, rule := range rules {
		effectiveCfg := cfg
		effectiveCfg.RecentPageTimes = recent
		state, reason, event := quarantineDecision(rule, effectiveCfg, now)
		rules[i].State = state
		rules[i].Reason = reason
		if event != nil {
			events = append(events, *event)
			recent = append(recent, now)
		}
	}
	return rules, events
}

func quarantineDecision(s RuleStats, cfg QuarantineConfig, now time.Time) (string, string, *QuarantineEvent) {
	active := cfg.ActiveRules != nil && cfg.ActiveRules[s.RuleID]
	if s.Evaluations < cfg.MinEvaluations {
		if active {
			return quarantineStateHeld, quarantineReasonThinSample, nil
		}
		return quarantineStateClear, quarantineReasonThinSample, nil
	}
	if active {
		if s.NewBlockRatePct > cfg.ReleaseFloorPct {
			return quarantineStateHeld, quarantineReasonHeld, nil
		}
		return quarantineStateReleased, quarantineReasonReleased, nil
	}
	if s.NewBlockRatePct <= cfg.CeilingPct {
		return quarantineStateClear, "", nil
	}
	if last, ok := cfg.LastQuarantinedAt[s.RuleID]; ok && now.Sub(last) < cfg.Cooldown {
		return quarantineStateClear, quarantineReasonCooldown, nil
	}
	if recentPages(now, cfg.RecentPageTimes) >= cfg.PageLimitPerHour {
		return quarantineStateClear, quarantineReasonPageLimit, nil
	}
	return quarantineStateCandidate, quarantineReasonRate, &QuarantineEvent{
		RuleID:          s.RuleID,
		Reason:          quarantineReasonRate,
		Evaluations:     s.Evaluations,
		NewBlocks:       s.NewBlocks,
		NewBlockRatePct: s.NewBlockRatePct,
		CooldownUntil:   now.Add(cfg.Cooldown).UTC(),
	}
}

func recentPages(now time.Time, pages []time.Time) int {
	cutoff := now.Add(-time.Hour)
	count := 0
	for _, ts := range pages {
		if !ts.Before(cutoff) && !ts.After(now) {
			count++
		}
	}
	return count
}

func contractRuleIDs(findings []capture.Finding) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, finding := range findings {
		if finding.Kind != capture.KindContract || finding.PolicyRule == "" {
			continue
		}
		for _, ruleID := range strings.Split(finding.PolicyRule, ",") {
			ruleID = strings.TrimSpace(ruleID)
			if ruleID == "" {
				continue
			}
			if _, ok := seen[ruleID]; ok {
				continue
			}
			seen[ruleID] = struct{}{}
			out = append(out, ruleID)
		}
	}
	sort.Strings(out)
	return out
}

func isNewBlock(original, candidate string) bool {
	return !isBlockAction(original) && isBlockAction(candidate)
}

func isBlockAction(action string) bool {
	return action == config.ActionBlock || action == "fail_closed"
}

func captureGradeRank(grade string) int {
	switch grade {
	case capture.CaptureGradeNone:
		return 0
	case capture.CaptureGradeSummary:
		return 1
	case capture.CaptureGradePartial:
		return 2
	case capture.CaptureGradeFull:
		return 3
	default:
		return -1
	}
}

func exemplarID(record capture.ReplayedRecord) string {
	h := sha256.New()
	_, _ = io.WriteString(h, record.Summary.Surface)
	_, _ = io.WriteString(h, "\x00")
	_, _ = io.WriteString(h, record.Summary.Request.Method)
	_, _ = io.WriteString(h, "\x00")
	_, _ = io.WriteString(h, record.Summary.Request.URL)
	_, _ = io.WriteString(h, "\x00")
	_, _ = io.WriteString(h, record.Summary.Request.ToolName)
	_, _ = io.WriteString(h, "\x00")
	_, _ = io.WriteString(h, record.Summary.Request.MCPMethod)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// RenderJSON writes a deterministic JSON report.
func RenderJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// RenderMarkdown writes a deterministic human-readable shadow report.
func RenderMarkdown(w io.Writer, report Report) error {
	_, _ = fmt.Fprintf(w, "# %s\n\n", defaultShadowReportTitle)
	_, _ = fmt.Fprintf(w, "- contract_hash: `%s`\n", report.ContractHash)
	_, _ = fmt.Fprintf(w, "- generated_at: `%s`\n", report.GeneratedAt.UTC().Format(time.RFC3339Nano))
	_, _ = fmt.Fprintf(w, "- records: %d total, %d replayed, %d changed\n", report.TotalRecords, report.Replayed, report.Changed)
	_, _ = fmt.Fprintf(w, "- deltas: %d new blocks, %d new allows, %d batches\n\n", report.NewBlocks, report.NewAllows, len(report.Batches))

	_, _ = fmt.Fprintln(w, "## Quarantine")
	if len(report.Quarantines) == 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "No quarantine candidates.")
		_, _ = fmt.Fprintln(w)
	} else {
		_, _ = fmt.Fprintln(w)
		for _, q := range report.Quarantines {
			_, _ = fmt.Fprintf(w, "- `%s`: %.2f%% new-block rate (%d/%d), cooldown until `%s`\n",
				q.RuleID, q.NewBlockRatePct, q.NewBlocks, q.Evaluations, q.CooldownUntil.UTC().Format(time.RFC3339Nano))
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintln(w, "## Rules")
	if len(report.Rules) == 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "No contract rule evaluations.")
		_, _ = fmt.Fprintln(w)
		return nil
	}
	_, _ = fmt.Fprintln(w, "\n| rule | evals | new_blocks | new_allows | rate | state | reason |")
	_, _ = fmt.Fprintln(w, "|---|---:|---:|---:|---:|---|---|")
	for _, rule := range report.Rules {
		_, _ = fmt.Fprintf(w, "| `%s` | %d | %d | %d | %.2f%% | %s | %s |\n",
			rule.RuleID, rule.Evaluations, rule.NewBlocks, rule.NewAllows, rule.NewBlockRatePct, rule.State, rule.Reason)
	}
	return nil
}

// DiffReports returns a deterministic summary comparing two shadow reports.
func DiffReports(a, b Report) []RuleStats {
	byRule := map[string]RuleStats{}
	for _, rule := range a.Rules {
		byRule[rule.RuleID] = RuleStats{
			RuleID:          rule.RuleID,
			Evaluations:     -rule.Evaluations,
			NewBlocks:       -rule.NewBlocks,
			NewAllows:       -rule.NewAllows,
			Unchanged:       -rule.Unchanged,
			NewBlockRatePct: -rule.NewBlockRatePct,
		}
	}
	for _, rule := range b.Rules {
		prev := byRule[rule.RuleID]
		prev.RuleID = rule.RuleID
		prev.Evaluations += rule.Evaluations
		prev.NewBlocks += rule.NewBlocks
		prev.NewAllows += rule.NewAllows
		prev.Unchanged += rule.Unchanged
		prev.NewBlockRatePct += rule.NewBlockRatePct
		byRule[rule.RuleID] = prev
	}
	out := make([]RuleStats, 0, len(byRule))
	for _, rule := range byRule {
		out = append(out, rule)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}
