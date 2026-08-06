// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"math"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	EvidenceRequirementRecorderEnabled = "recorder_enabled"
	EvidenceRequirementEmitterHealthy  = "emitter_healthy"
	EvidenceRequirementDurabilityGate  = "durability_gate"
	EvidenceRequirementHeartbeats      = "heartbeats"
	EvidenceRequirementAnchoringFresh  = "anchoring_fresh"
	EvidenceRequirementCPCActive       = "cpc_active"
	EvidenceRequirementSelfAuditOK     = "selfaudit_ok"

	// EvidenceRunStateOpen identifies a live recorder process. It is a lifecycle
	// fact, not an AEL verification state.
	EvidenceRunStateOpen = "OPEN"
	// EvidenceCurrentAELUnavailable is the only value emitted on the deprecated
	// JSON field. A string makes legacy numeric decoders fail visibly instead of
	// silently coercing JSON null into the valid-looking AEL-0 value.
	EvidenceCurrentAELUnavailable = "UNAVAILABLE"
	// EvidenceHealthSchemaV2 is the canonical evidence-health schema for this
	// release. The sanitized snapshot forces it so an alternate callback cannot
	// declare the v1 contract while emitting v2 field shapes, which would let a
	// consumer that selects its decoder from the schema pick the wrong one.
	EvidenceHealthSchemaV2 = "pipelock.evidencehealth.v2"

	evidenceArtifactCapabilitySchema = "pipelock.ael-artifact-capability.v1"
)

var evidenceSequenceGapSources = map[string]bool{
	"resume":     true,
	"self_audit": true,
	"unknown":    true,
}

var evidenceFsyncGatedValues = map[string]bool{
	"true":  true,
	"false": true,
}

var evidenceSelfAuditChecks = map[string]bool{
	"durability_invariant": true,
	"tail_divergence":      true,
	"sampler_error":        true,
}

var evidenceAELRequirements = map[string]bool{
	EvidenceRequirementRecorderEnabled: true,
	EvidenceRequirementEmitterHealthy:  true,
	EvidenceRequirementDurabilityGate:  true,
	EvidenceRequirementHeartbeats:      true,
	EvidenceRequirementAnchoringFresh:  true,
	EvidenceRequirementCPCActive:       true,
	EvidenceRequirementSelfAuditOK:     true,
	"unknown":                          true,
}

var evidenceAELRequirementOrder = []string{
	EvidenceRequirementRecorderEnabled,
	EvidenceRequirementEmitterHealthy,
	EvidenceRequirementDurabilityGate,
	EvidenceRequirementHeartbeats,
	EvidenceRequirementAnchoringFresh,
	EvidenceRequirementCPCActive,
	EvidenceRequirementSelfAuditOK,
}

// EvidenceHealthStats is the live observability snapshot used by conditional
// Prometheus collectors and the JSON /stats endpoint. Nil/false callback
// results mean evidence health is not measured and should render UNKNOWN.
type EvidenceHealthStats struct {
	Schema string `json:"schema"`
	// CurrentAEL is retained as UNAVAILABLE for one compatibility window. A live
	// process cannot independently verify and award an AEL grade to itself.
	// Deprecated: use LocalRecorderOperational, RunState, and
	// AELArtifactCapability.
	CurrentAEL                 string                     `json:"current_ael"`
	LocalRecorderOperational   bool                       `json:"local_recorder_operational"`
	RunState                   string                     `json:"run_state"`
	RunID                      *string                    `json:"run_id"`
	AELArtifactCapability      EvidenceArtifactCapability `json:"ael_artifact_capability"`
	Requirements               map[string]bool            `json:"requirements"`
	ChainHeadSeq               uint64                     `json:"chain_head_seq"`
	ChainHeadAgeSeconds        *float64                   `json:"chain_head_age_seconds"`
	HeartbeatIntervalSeconds   *float64                   `json:"heartbeat_interval_seconds"`
	SequenceGaps               EvidenceGapStats           `json:"sequence_gaps"`
	FsyncErrors                EvidenceFsyncStats         `json:"fsync_errors"`
	Files                      EvidenceFileStats          `json:"files"`
	DurabilityBlocks           uint64                     `json:"durability_blocks"`
	DurabilityInvariantOK      bool                       `json:"durability_invariant_ok"`
	Anchor                     *EvidenceAnchorStats       `json:"anchor"`
	AutoAnchor                 EvidenceAutoAnchorStats    `json:"auto_anchor"`
	CPC                        any                        `json:"cpc"`
	AnchoredFinalSeq           uint64                     `json:"-"`
	AnchorLagReceipts          uint64                     `json:"-"`
	LastAnchorTimestampSeconds float64                    `json:"-"`
}

// EvidenceArtifactCapability is a producer declaration, not an AEL grade or
// verification result. It deliberately contains no target, maximum, or current
// AEL rung.
type EvidenceArtifactCapability struct {
	Schema                   string   `json:"schema"`
	AELFormatVersions        []int    `json:"ael_format_versions"`
	BoundedRuns              bool     `json:"bounded_runs"`
	ClosedRunExport          bool     `json:"closed_run_export"`
	VerificationResultImport bool     `json:"verification_result_import"`
	KnownLimitations         []string `json:"known_limitations"`
}

// CurrentEvidenceArtifactCapability returns Pipelock's current producer
// declaration. Empty format versions and false operation flags are explicit
// unsupported states, not unknown values.
func CurrentEvidenceArtifactCapability() EvidenceArtifactCapability {
	return EvidenceArtifactCapability{
		Schema:                   evidenceArtifactCapabilitySchema,
		AELFormatVersions:        []int{},
		BoundedRuns:              false,
		ClosedRunExport:          false,
		VerificationResultImport: false,
		KnownLimitations: []string{
			"ael_artifact_export_not_implemented",
			"concurrent_writer_isolation_not_enforced",
			"verification_result_import_not_implemented",
		},
	}
}

type EvidenceGapStats struct {
	Resume    int64 `json:"resume"`
	SelfAudit int64 `json:"self_audit"`
}

type EvidenceFsyncStats struct {
	Gated   int64 `json:"gated"`
	Ungated int64 `json:"ungated"`
}

type EvidenceFileStats struct {
	TotalEvidenceFiles     int    `json:"total_evidence_files"`
	MaxSessionFiles        int    `json:"max_session_files"`
	MaxSessionID           string `json:"max_session_id,omitempty"`
	WarningThreshold       int    `json:"warning_threshold"`
	MaxFilesPerSession     int    `json:"max_files_per_session"`
	NearSessionFileLimit   bool   `json:"near_session_file_limit"`
	OverSessionFileLimit   bool   `json:"over_session_file_limit"`
	RetentionDays          int    `json:"retention_days"`
	RetentionEnabled       bool   `json:"retention_enabled"`
	RetentionEligibleFiles int    `json:"retention_eligible_files"`
}

type EvidenceAnchorStats struct {
	SessionID            string  `json:"session_id"`
	FinalSeq             uint64  `json:"final_seq"`
	RootHash             string  `json:"root_hash"`
	Backend              string  `json:"backend"`
	LogIndex             uint64  `json:"log_index"`
	AnchoredAt           string  `json:"anchored_at"`
	BundleSHA256         string  `json:"bundle_sha256"`
	BundlePath           string  `json:"bundle_path"`
	LagReceipts          uint64  `json:"lag_receipts"`
	LastTimestampSeconds float64 `json:"last_timestamp_seconds"`
}

type EvidenceAutoAnchorStats struct {
	Attempts  uint64 `json:"attempts"`
	Successes uint64 `json:"successes"`
	Failures  uint64 `json:"failures"`
	LastError string `json:"last_error"`
}

type EvidenceOperationalInput struct {
	RecorderEnabled  bool
	EmitterHealthy   bool
	SelfAuditOK      bool
	UnresolvedGaps   bool
	UngatedFsyncFail bool
}

func EvidenceLocalRecorderOperational(in EvidenceOperationalInput) bool {
	return in.RecorderEnabled && in.EmitterHealthy && in.SelfAuditOK &&
		!in.UnresolvedGaps && !in.UngatedFsyncFail
}

func (m *Metrics) registerEvidenceMetrics(reg *prometheus.Registry) {
	m.evidenceSequenceGaps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "sequence_gaps_total",
		Help:      "Total observed evidence sequence gaps by bounded source.",
	}, []string{"source"})
	m.evidenceHeartbeatInterval = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "heartbeat_interval_seconds",
		Help:      "Configured receipt heartbeat interval in seconds; absent from JSON stats until heartbeats are enabled.",
	})
	m.evidenceLastAnchorTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "last_anchor_timestamp_seconds",
		Help:      "Unix timestamp of the latest accepted local anchor-state marker, or zero when never anchored.",
	})
	m.evidenceAnchoredFinalSeq = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "anchored_final_seq",
		Help:      "Final receipt sequence covered by the latest accepted local anchor-state marker.",
	})
	m.evidenceFsyncErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "fsync_errors_total",
		Help:      "Per-action durability confirmation failures, labeled by whether fail-closed receipt gating was active.",
	}, []string{"gated"})
	m.evidenceAELRequirements = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "ael_requirement_ok",
		Help:      "Deprecated diagnostic inputs from the former live AEL estimate; these 1/0 values do not award an AEL grade.",
	}, []string{"requirement"})
	m.evidenceSelfAuditOK = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "selfaudit_ok",
		Help:      "One while evidence self-audit checks pass; latched to zero after any failure in this process.",
	})
	m.evidenceSelfAuditFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "selfaudit_failures_total",
		Help:      "Total evidence self-audit failures by bounded check label.",
	}, []string{"check"})
	m.evidenceAnchorStateSkipped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "anchor_state_skipped_total",
		Help:      "Total malformed or conflicting local anchor-state entries skipped during recovery.",
	})
	m.evidenceAutoAnchorAttempts = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "auto_anchor_attempts_total",
		Help:      "Total runtime receipt-chain auto-anchor attempts.",
	})
	m.evidenceAutoAnchorSuccesses = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "auto_anchor_successes_total",
		Help:      "Total successful runtime receipt-chain auto-anchor attempts.",
	})
	m.evidenceAutoAnchorFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Subsystem: "evidence",
		Name:      "auto_anchor_failures_total",
		Help:      "Total failed runtime receipt-chain auto-anchor attempts.",
	})
	m.evidenceSelfAuditOK.Set(1)
	for _, req := range evidenceAELRequirementOrder {
		m.evidenceAELRequirements.WithLabelValues(req).Set(0)
	}
	m.evidenceCollector = newEvidenceCollector(m)

	reg.MustRegister(
		m.evidenceSequenceGaps,
		m.evidenceHeartbeatInterval,
		m.evidenceLastAnchorTimestamp,
		m.evidenceAnchoredFinalSeq,
		m.evidenceFsyncErrors,
		m.evidenceAELRequirements,
		m.evidenceSelfAuditOK,
		m.evidenceSelfAuditFailures,
		m.evidenceAnchorStateSkipped,
		m.evidenceAutoAnchorAttempts,
		m.evidenceAutoAnchorSuccesses,
		m.evidenceAutoAnchorFailures,
		m.evidenceCollector,
	)
}

func (m *Metrics) RecordEvidenceSequenceGap(source string) {
	if m == nil {
		return
	}
	if !evidenceSequenceGapSources[source] {
		source = "unknown"
	}
	m.mu.Lock()
	if m.evidenceSequenceGapCounts != nil {
		m.evidenceSequenceGapCounts[source]++
	}
	m.mu.Unlock()
	if m.evidenceSequenceGaps != nil {
		m.evidenceSequenceGaps.WithLabelValues(source).Inc()
	}
}

func (m *Metrics) RecordFsyncError(gated bool, n int) {
	if m == nil || n <= 0 {
		return
	}
	label := "false"
	if gated {
		label = "true"
	}
	if !evidenceFsyncGatedValues[label] {
		label = "false"
	}
	m.mu.Lock()
	if m.evidenceFsyncErrorCounts != nil {
		m.evidenceFsyncErrorCounts[label] += int64(n)
	}
	m.mu.Unlock()
	if m.evidenceFsyncErrors != nil {
		m.evidenceFsyncErrors.WithLabelValues(label).Add(float64(n))
	}
}

func (m *Metrics) RecordSelfAuditFailure(check string) {
	if m == nil {
		return
	}
	if !evidenceSelfAuditChecks[check] {
		check = "sampler_error"
	}
	m.mu.Lock()
	if m.evidenceSelfAuditFailCounts != nil {
		m.evidenceSelfAuditFailCounts[check]++
	}
	m.mu.Unlock()
	if m.evidenceSelfAuditFailures != nil {
		m.evidenceSelfAuditFailures.WithLabelValues(check).Inc()
	}
}

func (m *Metrics) RecordEvidenceAnchorStateSkipped(n int) {
	if m == nil || n <= 0 || m.evidenceAnchorStateSkipped == nil {
		return
	}
	m.evidenceAnchorStateSkipped.Add(float64(n))
}

func (m *Metrics) RecordEvidenceAutoAnchorAttempt() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.evidenceAutoAnchorStats.Attempts++
	m.mu.Unlock()
	if m.evidenceAutoAnchorAttempts != nil {
		m.evidenceAutoAnchorAttempts.Inc()
	}
}

func (m *Metrics) RecordEvidenceAutoAnchorSuccess() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.evidenceAutoAnchorStats.Successes++
	m.evidenceAutoAnchorStats.LastError = ""
	m.mu.Unlock()
	if m.evidenceAutoAnchorSuccesses != nil {
		m.evidenceAutoAnchorSuccesses.Inc()
	}
}

func (m *Metrics) RecordEvidenceAutoAnchorFailure(err string) {
	if m == nil {
		return
	}
	const maxLastErrorRunes = 1024
	trimmed := []rune(strings.ToValidUTF8(strings.TrimSpace(err), "�"))
	if len(trimmed) > maxLastErrorRunes {
		trimmed = trimmed[:maxLastErrorRunes]
	}
	m.mu.Lock()
	m.evidenceAutoAnchorStats.Failures++
	m.evidenceAutoAnchorStats.LastError = string(trimmed)
	m.mu.Unlock()
	if m.evidenceAutoAnchorFailures != nil {
		m.evidenceAutoAnchorFailures.Inc()
	}
}

func (m *Metrics) EvidenceAutoAnchorStatsSnapshot() EvidenceAutoAnchorStats {
	if m == nil {
		return EvidenceAutoAnchorStats{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evidenceAutoAnchorStats
}

func (m *Metrics) SetEvidenceSelfAuditOK(ok bool) {
	if m == nil || m.evidenceSelfAuditOK == nil {
		return
	}
	if ok {
		m.evidenceSelfAuditOK.Set(1)
		return
	}
	m.evidenceSelfAuditOK.Set(0)
}

func (m *Metrics) SetEvidenceHeartbeatInterval(intervalSeconds float64, enabled bool) {
	if m == nil || m.evidenceHeartbeatInterval == nil {
		return
	}
	if !enabled {
		m.evidenceHeartbeatInterval.Set(math.NaN())
		return
	}
	m.evidenceHeartbeatInterval.Set(intervalSeconds)
}

func (m *Metrics) SetEvidenceAnchor(timestampSeconds float64, finalSeq uint64) {
	if m == nil {
		return
	}
	if m.evidenceLastAnchorTimestamp != nil {
		m.evidenceLastAnchorTimestamp.Set(timestampSeconds)
	}
	if m.evidenceAnchoredFinalSeq != nil {
		m.evidenceAnchoredFinalSeq.Set(float64(finalSeq))
	}
}

func (m *Metrics) SetEvidenceRequirement(requirement string, ok bool) {
	if m == nil {
		return
	}
	if !evidenceAELRequirements[requirement] {
		requirement = "unknown"
	}
	m.mu.Lock()
	if m.evidenceRequirementValues != nil {
		m.evidenceRequirementValues[requirement] = ok
	}
	m.mu.Unlock()
	if m.evidenceAELRequirements != nil {
		value := 0.0
		if ok {
			value = 1
		}
		m.evidenceAELRequirements.WithLabelValues(requirement).Set(value)
	}
}

func (m *Metrics) SetEvidenceRequirements(values map[string]bool) {
	for _, req := range evidenceAELRequirementOrder {
		ok := false
		if values != nil {
			ok = values[req]
		}
		m.SetEvidenceRequirement(req, ok)
	}
}

func (m *Metrics) EvidenceCountersSnapshot() (gatedFsync, durabilityBlocks uint64) {
	if m == nil {
		return 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.evidenceFsyncErrorCounts != nil {
		gatedFsync = nonNegativeInt64ToUint64(m.evidenceFsyncErrorCounts["true"])
	}
	if m.requiredReceiptBlocks != nil {
		for key, count := range m.requiredReceiptBlocks {
			reason, _ := splitRequiredReceiptBlockKey(key)
			if reason == "durability" {
				durabilityBlocks += nonNegativeInt64ToUint64(count)
			}
		}
	}
	return gatedFsync, durabilityBlocks
}

func nonNegativeInt64ToUint64(v int64) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}

func (m *Metrics) EvidenceStatsCountersSnapshot() (EvidenceGapStats, EvidenceFsyncStats) {
	if m == nil {
		return EvidenceGapStats{}, EvidenceFsyncStats{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var gaps EvidenceGapStats
	var fsync EvidenceFsyncStats
	if m.evidenceSequenceGapCounts != nil {
		gaps.Resume = m.evidenceSequenceGapCounts["resume"]
		gaps.SelfAudit = m.evidenceSequenceGapCounts["self_audit"]
	}
	if m.evidenceFsyncErrorCounts != nil {
		fsync.Gated = m.evidenceFsyncErrorCounts["true"]
		fsync.Ungated = m.evidenceFsyncErrorCounts["false"]
	}
	return gaps, fsync
}

func (m *Metrics) EvidenceHealthStatsSnapshot() (EvidenceHealthStats, bool) {
	if m == nil {
		return EvidenceHealthStats{}, false
	}
	m.mu.Lock()
	fn := m.evidenceHealthFunc
	m.mu.Unlock()
	if fn == nil {
		return EvidenceHealthStats{}, false
	}
	stats, ok := fn()
	if !ok {
		return stats, false
	}
	// The callback backs both /stats and the Prometheus collector. Force the
	// deprecated producer-computed grade and producer-set verification lifecycle
	// to honest current-release values so an alternate callback cannot restore a
	// self-awarded AEL number or label an open legacy run as verified. The schema
	// is forced with them: a preserved v1 schema alongside v2 field shapes would
	// point a schema-selecting decoder at the wrong contract.
	stats.Schema = EvidenceHealthSchemaV2
	stats.CurrentAEL = EvidenceCurrentAELUnavailable
	stats.RunState = EvidenceRunStateOpen
	stats.RunID = nil
	stats.AELArtifactCapability = CurrentEvidenceArtifactCapability()
	return stats, true
}

func (m *Metrics) SetEvidenceHealthFunc(fn func() (EvidenceHealthStats, bool)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.evidenceHealthFunc = fn
	m.mu.Unlock()
}

type evidenceCollector struct {
	m                *Metrics
	age              *prometheus.Desc
	seq              *prometheus.Desc
	lag              *prometheus.Desc
	current          *prometheus.Desc
	localOperational *prometheus.Desc
}

func newEvidenceCollector(m *Metrics) *evidenceCollector {
	labels := prometheus.Labels{}
	return &evidenceCollector{
		m: m,
		age: prometheus.NewDesc(
			"pipelock_evidence_chain_head_age_seconds",
			"Seconds since the last durable chain entry; omitted when evidence health is not measured.",
			nil, labels,
		),
		seq: prometheus.NewDesc(
			"pipelock_evidence_chain_head_seq",
			"In-memory last emitted receipt sequence; omitted when evidence health is not measured.",
			nil, labels,
		),
		lag: prometheus.NewDesc(
			"pipelock_evidence_anchor_lag_receipts",
			"Receipts between the live chain head and the latest accepted local anchor-state marker.",
			nil, labels,
		),
		current: prometheus.NewDesc(
			"pipelock_evidence_current_ael",
			"Deprecated self-reported AEL gauge; always NaN because a live process cannot award AEL and grades require a separately verified exported artifact.",
			nil, labels,
		),
		localOperational: prometheus.NewDesc(
			"pipelock_evidence_local_recorder_operational",
			"One when this process's recorder and emitter are operational with no locally observed gap, self-audit, or ungated fsync failure; does not establish corpus-wide integrity or an AEL grade.",
			nil, labels,
		),
	}
}

func (c *evidenceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.age
	ch <- c.seq
	ch <- c.lag
	ch <- c.current
	ch <- c.localOperational
}

func (c *evidenceCollector) Collect(ch chan<- prometheus.Metric) {
	stats, ok := c.m.EvidenceHealthStatsSnapshot()
	if !ok {
		return
	}
	if stats.ChainHeadAgeSeconds != nil {
		ch <- prometheus.MustNewConstMetric(c.age, prometheus.GaugeValue, *stats.ChainHeadAgeSeconds)
	}
	ch <- prometheus.MustNewConstMetric(c.seq, prometheus.GaugeValue, float64(stats.ChainHeadSeq))
	ch <- prometheus.MustNewConstMetric(c.lag, prometheus.GaugeValue, float64(stats.AnchorLagReceipts))
	ch <- prometheus.MustNewConstMetric(c.current, prometheus.GaugeValue, math.NaN())
	operational := 0.0
	if stats.LocalRecorderOperational {
		operational = 1
	}
	ch <- prometheus.MustNewConstMetric(c.localOperational, prometheus.GaugeValue, operational)
}
