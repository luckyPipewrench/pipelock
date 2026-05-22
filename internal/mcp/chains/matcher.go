// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package chains

import (
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Verdict describes the result of checking a tool call against chain patterns.
type Verdict struct {
	Matched     bool
	PatternName string
	Severity    string // medium, high, critical
	Action      string // warn, block
}

// MetricsRecorder is an optional interface for recording chain detection metrics.
type MetricsRecorder interface {
	RecordChainDetection(pattern, severity, action string)
}

// Matcher tracks tool call history per session and matches against patterns.
type Matcher struct {
	cfg      *config.ToolChainDetection
	patterns []pattern
	sessions sync.Map // sessionKey -> *sessionHistory
	metrics  MetricsRecorder
}

// pattern is an internal compiled representation of a chain pattern.
type pattern struct {
	name     string
	sequence []string
	severity string
	action   string
}

// toolCallRecord stores a classified tool call in the session history.
type toolCallRecord struct {
	category    string
	name        string
	sensitivity string
	timestamp   time.Time
}

// sessionHistory holds the tool call history for a single session.
type sessionHistory struct {
	mu      sync.Mutex
	records []toolCallRecord
}

// builtInPatterns defines the default attack chain patterns (category axis).
var builtInPatterns = []pattern{
	{name: "read-then-exec", sequence: []string{"read", "exec"}, severity: "high", action: "warn"},
	{name: "read-write-send", sequence: []string{"read", "write", "network"}, severity: "critical", action: "warn"},
	{name: "env-then-network", sequence: []string{"env", "network"}, severity: "critical", action: "warn"},
	{name: "directory-scan", sequence: []string{"list", "list", "read"}, severity: "medium", action: "warn"},
	{name: "write-execute", sequence: []string{"write", "exec"}, severity: "high", action: "warn"},
	{name: "write-chmod-execute", sequence: []string{"write", "exec", "exec"}, severity: "critical", action: "warn"},
	{name: "read-sensitive-write", sequence: []string{"read", "write"}, severity: "medium", action: "warn"},
	{name: "shell-burst", sequence: []string{"exec", "exec", "exec", "exec"}, severity: "high", action: "warn"},
	{name: "write-persist", sequence: []string{"write", "persist"}, severity: "critical", action: "warn"},
	{name: "persist-callback", sequence: []string{"persist", "network"}, severity: "critical", action: "warn"},
}

// lethalTrifectaPattern is the sensitivity-axis pattern: untrusted-source
// then sensitive-source then external-sink within the chain window.
// Three independent research sources cite this shape (Invariantlabs GitHub
// MCP, parasitic toolchain arXiv 2509.06572, Toxic Flow Analysis).
//
// Run separately from category-axis patterns because the data is orthogonal.
// Operators can override the action via PatternOverrides[lethalTrifectaName].
const lethalTrifectaName = "lethal-trifecta"

var lethalTrifectaSequence = []string{
	SensitivityUntrustedSource,
	SensitivitySensitiveSource,
	SensitivityExternalSink,
}

// severityRank maps severity strings to numeric rank for comparison.
var severityRank = map[string]int{
	"medium":   1,
	"high":     2,
	"critical": 3,
}

// actionRank maps action strings to numeric rank for comparison.
var actionRank = map[string]int{
	"warn":  1,
	"block": 2,
}

// New creates a Matcher from the tool chain detection config.
// Returns a no-op matcher if the config is nil or disabled.
func New(cfg *config.ToolChainDetection) *Matcher {
	if cfg == nil {
		cfg = &config.ToolChainDetection{}
	}
	m := &Matcher{cfg: cfg}

	if !cfg.Enabled {
		return m
	}

	// Load built-in patterns with config overrides.
	for _, bp := range builtInPatterns {
		p := pattern{
			name:     bp.name,
			sequence: bp.sequence,
			severity: bp.severity,
			action:   bp.action,
		}
		// Apply pattern-specific action override from config.
		if override, ok := cfg.PatternOverrides[p.name]; ok {
			p.action = override
		}
		m.patterns = append(m.patterns, p)
	}

	// Load custom patterns from config.
	for _, cp := range cfg.CustomPatterns {
		p := pattern{
			name:     cp.Name,
			sequence: cp.Sequence,
			severity: cp.Severity,
			action:   cp.Action,
		}
		if p.action == "" {
			p.action = cfg.Action
		}
		// Apply pattern-specific override if exists.
		if override, ok := cfg.PatternOverrides[p.name]; ok {
			p.action = override
		}
		m.patterns = append(m.patterns, p)
	}

	return m
}

// WithMetrics attaches a metrics recorder to the matcher.
func (m *Matcher) WithMetrics(mr MetricsRecorder) *Matcher {
	m.metrics = mr
	return m
}

// Record classifies a tool call, adds it to the session history, and checks
// all patterns against the updated history. Returns the highest-severity match.
//
// If the tool classifies as "unknown", it is not recorded and no match is returned.
//
// The optional argHint parameter provides the raw tool arguments (e.g., the
// JSON-RPC message body) for argument-aware reclassification. When a tool
// name classifies as "exec" but the arguments contain persistence commands
// (crontab, systemctl enable, etc.), the category is upgraded to "persist".
func (m *Matcher) Record(sessionKey, toolName string, argHint ...string) Verdict {
	if !m.cfg.Enabled || len(m.patterns) == 0 {
		return Verdict{}
	}

	// Classify tool by name, then refine by arguments if provided.
	category := classifyTool(toolName, m.cfg)
	argHintStr := ""
	if len(argHint) > 0 {
		argHintStr = argHint[0]
		category = reclassifyByArgs(category, argHintStr)
	}
	sensitivity := ClassifySensitivity(toolName, argHintStr, m.cfg)
	// Skip recording only if BOTH axes are uninformative. A tool that's
	// "unknown" by category but carries a real sensitivity label
	// (e.g., an unrecognized tool name with "external_sink" keywords)
	// still belongs in the trifecta history.
	if category == "unknown" && sensitivity == SensitivityNeutral {
		return Verdict{}
	}

	// Get or create session history.
	val, _ := m.sessions.LoadOrStore(sessionKey, &sessionHistory{})
	sess := val.(*sessionHistory)

	sess.mu.Lock()
	defer sess.mu.Unlock()

	// Add record.
	now := time.Now()
	sess.records = append(sess.records, toolCallRecord{
		category:    category,
		name:        toolName,
		sensitivity: sensitivity,
		timestamp:   now,
	})

	// Evict old entries: time-based first, then count-based.
	m.evict(sess, now)

	// Check all patterns and return highest-severity match.
	v := m.matchPatterns(sess)
	if v.Matched && m.metrics != nil {
		m.metrics.RecordChainDetection(v.PatternName, v.Severity, v.Action)
	}
	return v
}

// ClearSession removes all tool call history for the given session key.
// Safe to call with a non-existent key (no-op).
func (m *Matcher) ClearSession(sessionKey string) {
	m.sessions.Delete(sessionKey)
}

// evict removes stale entries from the session history.
// Time-based eviction runs first, then count-based.
func (m *Matcher) evict(sess *sessionHistory, now time.Time) {
	// Time-based eviction.
	cutoff := now.Add(-time.Duration(m.cfg.WindowSeconds) * time.Second)
	firstValid := len(sess.records) // default: all expired
	for i, r := range sess.records {
		if !r.timestamp.Before(cutoff) {
			firstValid = i
			break
		}
	}
	if firstValid > 0 {
		sess.records = sess.records[firstValid:]
	}

	// Count-based eviction.
	if len(sess.records) > m.cfg.WindowSize {
		excess := len(sess.records) - m.cfg.WindowSize
		sess.records = sess.records[excess:]
	}
}

// matchPatterns checks all patterns against the session history.
// Returns the highest-severity match (critical > high > medium),
// breaking ties by strictest action (block > warn).
//
// Both axes are evaluated independently: category-axis built-ins/customs,
// plus the sensitivity-axis lethal-trifecta pattern. The highest-severity
// match across both wins.
func (m *Matcher) matchPatterns(sess *sessionHistory) Verdict {
	var best Verdict

	maxGap := config.DefaultMaxGap
	if m.cfg.MaxGap != nil {
		maxGap = *m.cfg.MaxGap
	}
	for _, p := range m.patterns {
		if subsequenceMatch(sess.records, p.sequence, maxGap) {
			if !best.Matched || isBetterMatch(p, best) {
				best = Verdict{
					Matched:     true,
					PatternName: p.name,
					Severity:    p.severity,
					Action:      p.action,
				}
			}
		}
	}

	// Sensitivity-axis: lethal-trifecta detection.
	if sensitivitySubsequenceMatch(sess.records, lethalTrifectaSequence, maxGap) {
		action := m.cfg.Action
		if action == "" {
			action = "warn"
		}
		if override, ok := m.cfg.PatternOverrides[lethalTrifectaName]; ok {
			action = override
		}
		p := pattern{
			name:     lethalTrifectaName,
			sequence: lethalTrifectaSequence,
			severity: "critical",
			action:   action,
		}
		if !best.Matched || isBetterMatch(p, best) {
			best = Verdict{
				Matched:     true,
				PatternName: p.name,
				Severity:    p.severity,
				Action:      p.action,
			}
		}
	}

	return best
}

// isBetterMatch returns true if pattern p has higher severity or stricter
// action than the current best verdict.
func isBetterMatch(p pattern, best Verdict) bool {
	ps := severityRank[p.severity]
	bs := severityRank[best.Severity]
	if ps != bs {
		return ps > bs
	}
	return actionRank[p.action] > actionRank[best.Action]
}

// subsequenceMatch checks if the pattern sequence appears as a subsequence
// in the history records on the CATEGORY axis, with at most maxGap
// non-matching entries between consecutive matched steps.
//
// If a match attempt fails due to gap constraint, the algorithm retries
// starting from the next occurrence of the first step.
func subsequenceMatch(records []toolCallRecord, sequence []string, maxGap int) bool {
	return subsequenceMatchOnAxis(records, sequence, maxGap, axisCategory)
}

// sensitivitySubsequenceMatch checks for the sequence on the SENSITIVITY axis.
// Separate function so the axis is explicit at call sites and the trifecta
// detector reads naturally.
func sensitivitySubsequenceMatch(records []toolCallRecord, sequence []string, maxGap int) bool {
	return subsequenceMatchOnAxis(records, sequence, maxGap, axisSensitivity)
}

// axis identifies which field of toolCallRecord drives the match.
type axis int

const (
	axisCategory axis = iota
	axisSensitivity
)

// recordField extracts the value of the axis field from a record.
func recordField(r toolCallRecord, a axis) string {
	switch a {
	case axisSensitivity:
		return r.sensitivity
	default:
		return r.category
	}
}

// subsequenceMatchOnAxis is the generic subsequence walker used by both
// the category-axis and sensitivity-axis matchers.
func subsequenceMatchOnAxis(records []toolCallRecord, sequence []string, maxGap int, a axis) bool {
	if len(sequence) == 0 || len(records) == 0 {
		return false
	}

	// Try each possible starting position for the first step.
	for startIdx := 0; startIdx < len(records); startIdx++ {
		if recordField(records[startIdx], a) != sequence[0] {
			continue
		}

		if matchFromPositionOnAxis(records, sequence, startIdx, maxGap, a) {
			return true
		}
	}

	return false
}

// matchFromPositionOnAxis attempts to match the sequence starting from a
// given position on the specified axis.
func matchFromPositionOnAxis(records []toolCallRecord, sequence []string, startIdx, maxGap int, a axis) bool {
	seqIdx := 1 // Already matched step 0 at startIdx.
	gap := 0

	for i := startIdx + 1; i < len(records) && seqIdx < len(sequence); i++ {
		if recordField(records[i], a) == sequence[seqIdx] {
			seqIdx++
			gap = 0
		} else {
			gap++
			if gap > maxGap {
				return false
			}
		}
	}

	return seqIdx == len(sequence)
}
