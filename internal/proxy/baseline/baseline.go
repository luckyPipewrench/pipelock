// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package baseline implements Profile-then-Lock behavioral baselines for
// agent sessions. It learns normal behavior, builds statistical models,
// requires operator ratification, and then enforces deviations.
package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// safeAgentKeyRe restricts agent keys to alphanumeric, hyphens, underscores,
// and dots. Prevents path traversal via crafted agent keys.
var safeAgentKeyRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validateAgentKey ensures an agent key cannot escape the profile directory.
func validateAgentKey(key string) error {
	if key == "" {
		return errors.New("empty agent key")
	}
	if !safeAgentKeyRe.MatchString(key) {
		return fmt.Errorf("invalid agent key %q: must match [a-zA-Z0-9._-]+", key)
	}
	if strings.Contains(key, "..") {
		return fmt.Errorf("invalid agent key %q: contains path traversal", key)
	}
	return nil
}

// ProfileState is the explicit state machine for baseline lifecycle.
// Transitions: Observe->Learn (auto), Learn->Ratify (auto),
// Ratify->Locked (operator only), Locked->Observe (operator only).
type ProfileState string

const (
	// StateObserve collects data, no enforcement, no learning.
	StateObserve ProfileState = "observe"
	// StateLearn builds a statistical model from observations.
	StateLearn ProfileState = "learn"
	// StateRatify awaits operator approval of the learned profile.
	StateRatify ProfileState = "ratify"
	// StateLocked enforces the baseline.
	StateLocked ProfileState = "locked"
)

// Deviation severity thresholds (in standard deviations from mean).
const (
	severityLowMax    = 2.0 // Up to 2 sigma = low.
	severityMediumMax = 3.0 // 2-3 sigma = medium.
	// Above 3 sigma = high.
)

// Deviation severity labels.
const (
	severityLow    = "low"
	severityMedium = "medium"
	severityHigh   = "high"
)

// poisonTrimSigma is the standard deviation multiplier for outlier trimming.
// Sessions beyond this threshold are discarded during learning.
const poisonTrimSigma = 3.0

// profileFileExt is the file extension for persisted profiles.
const profileFileExt = ".json"

// Profile is a learned behavioral baseline for an agent.
type Profile struct {
	AgentKey     string         `json:"agent_key"`
	State        ProfileState   `json:"state"`
	LearnedAt    time.Time      `json:"learned_at"`
	SessionCount int            `json:"session_count"`
	Ratified     bool           `json:"ratified"`
	RatifiedAt   *time.Time     `json:"ratified_at,omitempty"`
	Metrics      ProfileMetrics `json:"metrics"`
}

// ProfileMetrics are the learned behavioral ranges.
type ProfileMetrics struct {
	ToolCallsPerSession   Range `json:"tool_calls_per_session"`
	UniqueToolsPerSession Range `json:"unique_tools_per_session"`
	DomainsPerSession     Range `json:"domains_per_session"`
	BytesPerSession       Range `json:"bytes_per_session"`
	SessionDurationSec    Range `json:"session_duration_sec"`
	RequestsPerSession    Range `json:"requests_per_session"`
}

// Range is a min-max-mean-stddev learned from observation.
type Range struct {
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"stddev"`
}

// Deviation is an explainable violation of the baseline.
type Deviation struct {
	Metric   string  `json:"metric"`
	Baseline Range   `json:"baseline"`
	Observed float64 `json:"observed"`
	Delta    float64 `json:"delta"`
	Severity string  `json:"severity"`
}

// SessionMetrics is what we collect per session for baseline learning.
type SessionMetrics struct {
	ToolCalls   int     `json:"tool_calls"`
	UniqueTools int     `json:"unique_tools"`
	Domains     int     `json:"domains"`
	BytesTotal  int64   `json:"bytes_total"`
	DurationSec float64 `json:"duration_sec"`
	Requests    int     `json:"requests"`
}

// Config for behavioral baseline.
type Config struct {
	Enabled          bool     `yaml:"enabled"`
	LearningWindow   int      `yaml:"learning_window"`
	DeviationAction  string   `yaml:"deviation_action"`
	ProfileDir       string   `yaml:"profile_dir"`
	AutoRatify       bool     `yaml:"auto_ratify"`
	SensitivitySigma float64  `yaml:"sensitivity_sigma"`
	LockDimensions   []string `yaml:"lock_dimensions"`
	PoisonResistance bool     `yaml:"poison_resistance"`
	SeasonalityMode  string   `yaml:"seasonality_mode"`
}

// seasonalityNone is the only supported seasonality mode.
const seasonalityNone = "none"

// allDimensions is the complete list of enforceable metrics.
var allDimensions = []string{
	"tool_calls", "unique_tools", "domains", "bytes", "duration", "requests",
}

// agentState holds the in-memory state for a single agent.
type agentState struct {
	profile  *Profile
	learning []SessionMetrics
	state    ProfileState
}

// Manager handles learning, storage, and enforcement.
type Manager struct {
	cfg    Config
	agents map[string]*agentState
	mu     sync.RWMutex
}

// NewManager creates a new baseline manager. If ProfileDir is set and exists,
// persisted profiles are loaded.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.LearningWindow <= 0 {
		cfg.LearningWindow = 10 // Default: 10 sessions.
	}
	if cfg.SensitivitySigma <= 0 {
		cfg.SensitivitySigma = 2.0 // Default: 2 sigma.
	}
	if cfg.DeviationAction == "" {
		cfg.DeviationAction = "warn"
	}
	if cfg.SeasonalityMode == "" {
		cfg.SeasonalityMode = seasonalityNone
	}

	// Validate SeasonalityMode. Only "none" is implemented.
	// Reject unknown values rather than silently accepting them.
	if cfg.SeasonalityMode != seasonalityNone {
		return nil, fmt.Errorf("unsupported seasonality_mode %q: only \"none\" is supported", cfg.SeasonalityMode)
	}

	// Validate LockDimensions against known metric names.
	validDims := make(map[string]bool, len(allDimensions))
	for _, d := range allDimensions {
		validDims[d] = true
	}
	for _, d := range cfg.LockDimensions {
		if !validDims[d] {
			return nil, fmt.Errorf("unsupported lock_dimension %q: valid values are %v", d, allDimensions)
		}
	}

	m := &Manager{
		cfg:    cfg,
		agents: make(map[string]*agentState),
	}

	// Load persisted profiles if directory exists.
	if cfg.ProfileDir != "" {
		if err := m.loadProfiles(); err != nil {
			return nil, fmt.Errorf("loading profiles: %w", err)
		}
	}

	return m, nil
}

// RecordSession adds a completed session's metrics to the learning set.
// Handles state transitions: Observe->Learn->Ratify automatically.
func (m *Manager) RecordSession(agentKey string, metrics SessionMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()

	as, exists := m.agents[agentKey]
	if !exists {
		as = &agentState{state: StateObserve}
		m.agents[agentKey] = as
	}

	// Only collect data in Observe and Learn states.
	if as.state == StateLocked || as.state == StateRatify {
		return
	}

	as.learning = append(as.learning, metrics)

	// Auto-transition: Observe -> Learn after collecting enough sessions.
	if as.state == StateObserve && len(as.learning) >= m.cfg.LearningWindow {
		as.state = StateLearn
	}

	// Auto-transition: Learn -> Ratify when we have enough data to build a model.
	if as.state == StateLearn {
		profile := m.buildProfile(agentKey, as.learning)
		as.profile = profile
		as.state = StateRatify

		// Auto-ratify if configured (labeled DANGEROUS).
		if m.cfg.AutoRatify {
			now := time.Now()
			as.profile.Ratified = true
			as.profile.RatifiedAt = &now
			as.profile.State = StateLocked
			as.state = StateLocked

			// Persistence is mandatory for auto-ratify: a profile that
			// appears locked in memory but never reaches disk gives a
			// false sense of security (lost on restart). Roll back to
			// StateRatify if the write fails so the operator notices.
			if err := m.persistProfile(agentKey); err != nil {
				as.profile.Ratified = false
				as.profile.RatifiedAt = nil
				as.profile.State = StateRatify
				as.state = StateRatify
			}
		} else {
			as.profile.State = StateRatify
			_ = m.persistProfile(agentKey) // Best-effort for unratified profile.
		}
	}
}

// Check evaluates current session metrics against the locked profile.
// Returns nil if no profile, not locked, or within bounds.
func (m *Manager) Check(agentKey string, current SessionMetrics) []Deviation {
	m.mu.RLock()
	defer m.mu.RUnlock()

	as, exists := m.agents[agentKey]
	if !exists || as.profile == nil || as.state != StateLocked {
		return nil
	}

	dims := m.activeDimensions()
	var deviations []Deviation

	type metricCheck struct {
		name     string
		baseline Range
		observed float64
	}

	checks := []metricCheck{
		{"tool_calls", as.profile.Metrics.ToolCallsPerSession, float64(current.ToolCalls)},
		{"unique_tools", as.profile.Metrics.UniqueToolsPerSession, float64(current.UniqueTools)},
		{"domains", as.profile.Metrics.DomainsPerSession, float64(current.Domains)},
		{"bytes", as.profile.Metrics.BytesPerSession, float64(current.BytesTotal)},
		{"duration", as.profile.Metrics.SessionDurationSec, current.DurationSec},
		{"requests", as.profile.Metrics.RequestsPerSession, float64(current.Requests)},
	}

	for _, c := range checks {
		if !contains(dims, c.name) {
			continue
		}
		if dev := checkDeviation(c.name, c.baseline, c.observed, m.cfg.SensitivitySigma); dev != nil {
			deviations = append(deviations, *dev)
		}
	}

	return deviations
}

// GetProfile returns the current profile for an agent. Returns nil if
// no profile has been built yet.
func (m *Manager) GetProfile(agentKey string) *Profile {
	m.mu.RLock()
	defer m.mu.RUnlock()

	as, exists := m.agents[agentKey]
	if !exists || as.profile == nil {
		return nil
	}

	// Return a copy to prevent external mutation.
	cp := *as.profile
	return &cp
}

// GetState returns the current state for an agent.
func (m *Manager) GetState(agentKey string) ProfileState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	as, exists := m.agents[agentKey]
	if !exists {
		return StateObserve
	}
	return as.state
}

// Ratify locks a learned profile for enforcement. Only valid in StateRatify.
func (m *Manager) Ratify(agentKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	as, exists := m.agents[agentKey]
	if !exists {
		return fmt.Errorf("agent %q not found", agentKey)
	}
	if as.state != StateRatify {
		return fmt.Errorf("agent %q is in state %q, not %q", agentKey, as.state, StateRatify)
	}
	if as.profile == nil {
		return fmt.Errorf("agent %q has no profile to ratify", agentKey)
	}

	now := time.Now()
	as.profile.Ratified = true
	as.profile.RatifiedAt = &now
	as.profile.State = StateLocked

	// Persist BEFORE committing state in memory. If the write fails,
	// we revert the profile fields so Check() doesn't enforce an
	// unperisted ratification.
	if err := m.persistProfile(agentKey); err != nil {
		as.profile.Ratified = false
		as.profile.RatifiedAt = nil
		as.profile.State = StateRatify
		return fmt.Errorf("ratification failed: %w", err)
	}

	as.state = StateLocked
	return nil
}

// Reset moves an agent back to Observe state for relearning.
// Clears the existing profile and learning data.
func (m *Manager) Reset(agentKey string) error {
	if err := validateAgentKey(agentKey); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	as, exists := m.agents[agentKey]
	if !exists {
		return fmt.Errorf("agent %q not found", agentKey)
	}

	as.profile = nil
	as.learning = nil
	as.state = StateObserve

	// Remove persisted profile.
	if m.cfg.ProfileDir != "" {
		path := filepath.Join(m.cfg.ProfileDir, agentKey+profileFileExt)
		_ = os.Remove(filepath.Clean(path))
	}

	return nil
}

// ListAgents returns all tracked agent keys.
func (m *Manager) ListAgents() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.agents))
	for k := range m.agents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// buildProfile computes a statistical profile from session metrics.
func (m *Manager) buildProfile(agentKey string, sessions []SessionMetrics) *Profile {
	data := sessions
	if m.cfg.PoisonResistance {
		data = trimOutliers(sessions)
	}

	if len(data) == 0 {
		// All sessions were outliers. Use original data to avoid empty profile.
		data = sessions
	}

	return &Profile{
		AgentKey:     agentKey,
		State:        StateRatify,
		LearnedAt:    time.Now(),
		SessionCount: len(data),
		Metrics: ProfileMetrics{
			ToolCallsPerSession:   computeRange(extractFloat64s(data, func(s SessionMetrics) float64 { return float64(s.ToolCalls) })),
			UniqueToolsPerSession: computeRange(extractFloat64s(data, func(s SessionMetrics) float64 { return float64(s.UniqueTools) })),
			DomainsPerSession:     computeRange(extractFloat64s(data, func(s SessionMetrics) float64 { return float64(s.Domains) })),
			BytesPerSession:       computeRange(extractFloat64s(data, func(s SessionMetrics) float64 { return float64(s.BytesTotal) })),
			SessionDurationSec:    computeRange(extractFloat64s(data, func(s SessionMetrics) float64 { return s.DurationSec })),
			RequestsPerSession:    computeRange(extractFloat64s(data, func(s SessionMetrics) float64 { return float64(s.Requests) })),
		},
	}
}

// trimOutliers removes sessions that are >3 sigma from the mean on any metric.
// This provides poison resistance: an attacker who injects anomalous sessions
// during learning gets those sessions discarded.
func trimOutliers(sessions []SessionMetrics) []SessionMetrics {
	if len(sessions) < 3 {
		// Too few sessions for meaningful outlier detection.
		return sessions
	}

	// Compute mean and stddev for each metric.
	extractors := []func(SessionMetrics) float64{
		func(s SessionMetrics) float64 { return float64(s.ToolCalls) },
		func(s SessionMetrics) float64 { return float64(s.UniqueTools) },
		func(s SessionMetrics) float64 { return float64(s.Domains) },
		func(s SessionMetrics) float64 { return float64(s.BytesTotal) },
		func(s SessionMetrics) float64 { return s.DurationSec },
		func(s SessionMetrics) float64 { return float64(s.Requests) },
	}

	means := make([]float64, len(extractors))
	stddevs := make([]float64, len(extractors))

	for i, ext := range extractors {
		vals := extractFloat64s(sessions, ext)
		means[i] = mean(vals)
		stddevs[i] = stddev(vals, means[i])
	}

	var kept []SessionMetrics
	for _, s := range sessions {
		outlier := false
		for i, ext := range extractors {
			val := ext(s)
			if stddevs[i] > 0 && math.Abs(val-means[i])/stddevs[i] > poisonTrimSigma {
				outlier = true
				break
			}
		}
		if !outlier {
			kept = append(kept, s)
		}
	}

	return kept
}

// checkDeviation checks if an observed value deviates from the baseline
// beyond the sensitivity threshold.
func checkDeviation(metric string, baseline Range, observed, sigma float64) *Deviation {
	if baseline.StdDev == 0 {
		// Zero stddev means all training data was identical.
		// Any difference is a deviation.
		if observed == baseline.Mean {
			return nil
		}
		return &Deviation{
			Metric:   metric,
			Baseline: baseline,
			Observed: observed,
			Delta:    math.Abs(observed - baseline.Mean),
			Severity: severityHigh,
		}
	}

	distance := math.Abs(observed-baseline.Mean) / baseline.StdDev
	if distance <= sigma {
		return nil
	}

	delta := math.Abs(observed-baseline.Mean) - sigma*baseline.StdDev
	severity := severityLow
	if distance > severityMediumMax {
		severity = severityHigh
	} else if distance > severityLowMax {
		severity = severityMedium
	}

	return &Deviation{
		Metric:   metric,
		Baseline: baseline,
		Observed: observed,
		Delta:    delta,
		Severity: severity,
	}
}

// activeDimensions returns the set of metrics to enforce.
func (m *Manager) activeDimensions() []string {
	if len(m.cfg.LockDimensions) > 0 {
		return m.cfg.LockDimensions
	}
	return allDimensions
}

// persistProfile saves a profile to disk as JSON.
func (m *Manager) persistProfile(agentKey string) error {
	if m.cfg.ProfileDir == "" {
		return nil
	}

	if err := validateAgentKey(agentKey); err != nil {
		return fmt.Errorf("refusing to persist: %w", err)
	}

	as, exists := m.agents[agentKey]
	if !exists || as.profile == nil {
		return nil
	}

	data, err := json.MarshalIndent(as.profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling profile: %w", err)
	}

	path := filepath.Join(m.cfg.ProfileDir, agentKey+profileFileExt)
	return os.WriteFile(filepath.Clean(path), data, 0o600)
}

// loadProfiles reads all persisted profiles from ProfileDir.
func (m *Manager) loadProfiles() error {
	entries, err := os.ReadDir(filepath.Clean(m.cfg.ProfileDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading profile directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != profileFileExt {
			continue
		}

		path := filepath.Join(m.cfg.ProfileDir, entry.Name())
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			continue
		}

		var profile Profile
		if err := json.Unmarshal(data, &profile); err != nil {
			continue
		}

		agentKey := profile.AgentKey
		if agentKey == "" {
			// Derive from filename.
			agentKey = entry.Name()[:len(entry.Name())-len(profileFileExt)]
		}

		m.agents[agentKey] = &agentState{
			profile: &profile,
			state:   profile.State,
		}
	}

	return nil
}

// Helper functions.

func extractFloat64s(sessions []SessionMetrics, fn func(SessionMetrics) float64) []float64 {
	vals := make([]float64, len(sessions))
	for i, s := range sessions {
		vals[i] = fn(s)
	}
	return vals
}

func computeRange(vals []float64) Range {
	if len(vals) == 0 {
		return Range{}
	}

	m := mean(vals)
	sd := stddev(vals, m)

	minVal := vals[0]
	maxVal := vals[0]
	for _, v := range vals[1:] {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	return Range{
		Min:    minVal,
		Max:    maxVal,
		Mean:   m,
		StdDev: sd,
	}
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stddev(vals []float64, m float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	sumSq := 0.0
	for _, v := range vals {
		d := v - m
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(vals)))
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
