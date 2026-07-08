// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"math"

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
	Schema                     string               `json:"schema"`
	CurrentAEL                 int                  `json:"current_ael"`
	Requirements               map[string]bool      `json:"requirements"`
	ChainHeadSeq               uint64               `json:"chain_head_seq"`
	ChainHeadAgeSeconds        *float64             `json:"chain_head_age_seconds"`
	HeartbeatIntervalSeconds   *float64             `json:"heartbeat_interval_seconds"`
	SequenceGaps               EvidenceGapStats     `json:"sequence_gaps"`
	FsyncErrors                EvidenceFsyncStats   `json:"fsync_errors"`
	DurabilityBlocks           uint64               `json:"durability_blocks"`
	DurabilityInvariantOK      bool                 `json:"durability_invariant_ok"`
	Anchor                     *EvidenceAnchorStats `json:"anchor"`
	CPC                        any                  `json:"cpc"`
	AnchoredFinalSeq           uint64               `json:"-"`
	AnchorLagReceipts          uint64               `json:"-"`
	LastAnchorTimestampSeconds float64              `json:"-"`
}

type EvidenceGapStats struct {
	Resume    int64 `json:"resume"`
	SelfAudit int64 `json:"self_audit"`
}

type EvidenceFsyncStats struct {
	Gated   int64 `json:"gated"`
	Ungated int64 `json:"ungated"`
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

type EvidenceAELInput struct {
	RecorderEnabled  bool
	EmitterHealthy   bool
	DurabilityGate   bool
	Heartbeats       bool
	AnchoringFresh   bool
	CPCActive        bool
	SelfAuditOK      bool
	UnresolvedGaps   bool
	UngatedFsyncFail bool
}

type evidenceAELRule struct {
	rung int
	ok   func(EvidenceAELInput) bool
}

var evidenceAELRules = []evidenceAELRule{
	{rung: 0, ok: func(in EvidenceAELInput) bool {
		return in.RecorderEnabled
	}},
	{rung: 1, ok: func(in EvidenceAELInput) bool {
		return in.RecorderEnabled && in.EmitterHealthy && in.SelfAuditOK && !in.UngatedFsyncFail
	}},
	{rung: 2, ok: func(in EvidenceAELInput) bool {
		return in.DurabilityGate && in.Heartbeats && !in.UnresolvedGaps
	}},
	{rung: 3, ok: func(in EvidenceAELInput) bool {
		return in.AnchoringFresh
	}},
	{rung: 4, ok: func(in EvidenceAELInput) bool {
		return in.CPCActive
	}},
}

func EvidenceCurrentAEL(in EvidenceAELInput) int {
	level := 0
	for _, rule := range evidenceAELRules {
		if !rule.ok(in) {
			return level
		}
		level = rule.rung
	}
	return level
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
		Help:      "Evidence assurance requirement state as 1/0 by closed requirement label.",
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
	return fn()
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
	m       *Metrics
	age     *prometheus.Desc
	seq     *prometheus.Desc
	lag     *prometheus.Desc
	current *prometheus.Desc
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
			"Current evidence assurance level, 0 through 4.",
			nil, labels,
		),
	}
}

func (c *evidenceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.age
	ch <- c.seq
	ch <- c.lag
	ch <- c.current
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
	ch <- prometheus.MustNewConstMetric(c.current, prometheus.GaugeValue, float64(stats.CurrentAEL))
}
