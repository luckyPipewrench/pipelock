// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package baseline implements Profile-then-Lock behavioral baselines for
// agent sessions. It learns normal behavior, builds statistical models,
// requires operator ratification, and then enforces deviations.
package baseline

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	appconfig "github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
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

// ValidateAgentKey reports whether key is safe for identity-keyed baseline
// storage and lookup.
func ValidateAgentKey(key string) error {
	return validateAgentKey(key)
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

const (
	integrityManifestDirName  = ".integrity"
	integrityManifestFileName = "manifest.json"
	integrityManifestVersion  = 1
	integrityManifestAlg      = "HMAC-SHA256"
	integrityKeyBytes         = 32
	integrityStateMaxSize     = 4 * 1024
	baselineProfileMaxSize    = 1024 * 1024
)

// Profile is a learned behavioral baseline for an agent.
type Profile struct {
	AgentKey             string         `json:"agent_key"`
	State                ProfileState   `json:"state"`
	LearnedAt            time.Time      `json:"learned_at"`
	SessionCount         int            `json:"session_count"`
	ObservedSessionCount int            `json:"observed_session_count,omitempty"`
	TrimmedSessionCount  int            `json:"trimmed_session_count,omitempty"`
	ToolIdentities       []string       `json:"tool_identities,omitempty"`
	Ratified             bool           `json:"ratified"`
	RatifiedAt           *time.Time     `json:"ratified_at,omitempty"`
	Metrics              ProfileMetrics `json:"metrics"`
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
	ToolCalls      int      `json:"tool_calls"`
	UniqueTools    int      `json:"unique_tools"`
	ToolIdentities []string `json:"tool_identities,omitempty"`
	Domains        int      `json:"domains"`
	BytesTotal     int64    `json:"bytes_total"`
	DurationSec    float64  `json:"duration_sec"`
	Requests       int      `json:"requests"`
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
	IntegrityKeyPath string   `yaml:"-"`
}

type integrityManifestFile struct {
	Manifest integrityManifest `json:"manifest"`
	HMAC     string            `json:"hmac_sha256"`
}

type integrityManifest struct {
	SchemaVersion int                      `json:"schema_version"`
	Algorithm     string                   `json:"algorithm"`
	Generation    uint64                   `json:"generation"`
	Profiles      []integrityManifestEntry `json:"profiles"`
}

type integrityManifestEntry struct {
	AgentKey string       `json:"agent_key"`
	SHA256   string       `json:"sha256"`
	State    ProfileState `json:"state"`
}

type integrityHighWaterState struct {
	Generation   uint64 `json:"generation"`
	Context      string `json:"context"`
	ManifestHMAC string `json:"manifest_hmac"`
	Digest       string `json:"digest"`
}

// seasonalityNone is the only supported seasonality mode.
const seasonalityNone = "none"

// a2aToolIdentityPrefix identifies A2A method entries in the shared
// tool-identity baseline dimension. The MCP layer synthesizes these as
// "a2a:<method>" so A2A methods reuse the tool-call machinery without
// colliding with ordinary tool names.
const a2aToolIdentityPrefix = "a2a:"

// supportedDimensions is the complete list of accepted metric names.
var supportedDimensions = []string{
	"tool_calls", "unique_tools", "domains", "bytes", "duration", "requests",
}

// defaultDimensions are enforced when lock_dimensions is omitted. Bytes are
// accepted for existing profiles/configs but excluded from the PR1 default
// because production traffic does not yet record bytes into SessionState.
var defaultDimensions = []string{
	"tool_calls", "unique_tools", "domains", "duration", "requests",
}

// agentState holds the in-memory state for a single agent.
type agentState struct {
	profile  *Profile
	learning []SessionMetrics
	state    ProfileState
}

// Manager handles learning, storage, and enforcement.
type Manager struct {
	cfg       Config
	agents    map[string]*agentState
	mu        sync.RWMutex
	persistMu sync.Mutex
}

var integrityHighWaterMu sync.Mutex

// Deviation actions. "warn" is observational; "ask" (HITL) and "block" both
// take a consequential action on a deviation, so they are enforcing.
const (
	deviationActionWarn  = appconfig.ActionWarn
	deviationActionAsk   = appconfig.ActionAsk
	deviationActionBlock = appconfig.ActionBlock
)

// enforces reports whether a deviation from a locked profile takes a
// consequential action (ask=HITL, block=deny) rather than only observing
// (warn). Under enforcement, a persisted profile that exists but cannot be
// read or parsed must fail closed at load: silently skipping it would erase
// active enforcement for that agent on the next restart (fail-open).
func (c Config) enforces() bool {
	return c.DeviationAction == deviationActionAsk || c.DeviationAction == deviationActionBlock
}

func validateDeviationAction(action string) error {
	switch action {
	case deviationActionWarn, deviationActionAsk, deviationActionBlock:
		return nil
	default:
		return fmt.Errorf("unsupported deviation_action %q: valid values are warn, ask, or block", action)
	}
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
		cfg.DeviationAction = deviationActionWarn
	}
	if err := validateDeviationAction(cfg.DeviationAction); err != nil {
		return nil, err
	}
	if cfg.SeasonalityMode == "" {
		cfg.SeasonalityMode = seasonalityNone
	}
	if err := normalizeIntegrityConfig(&cfg); err != nil {
		return nil, err
	}

	// Validate SeasonalityMode. Only "none" is implemented.
	// Reject unknown values rather than silently accepting them.
	if cfg.SeasonalityMode != seasonalityNone {
		return nil, fmt.Errorf("unsupported seasonality_mode %q: only \"none\" is supported", cfg.SeasonalityMode)
	}

	// Validate LockDimensions against known metric names.
	validDims := make(map[string]bool, len(supportedDimensions))
	for _, d := range supportedDimensions {
		validDims[d] = true
	}
	for _, d := range cfg.LockDimensions {
		if !validDims[d] {
			return nil, fmt.Errorf("unsupported lock_dimension %q: valid values are %v", d, supportedDimensions)
		}
	}

	m := &Manager{
		cfg:    cfg,
		agents: make(map[string]*agentState),
	}

	// Ensure profile directory exists, then load persisted profiles.
	if cfg.ProfileDir != "" {
		if err := os.MkdirAll(cfg.ProfileDir, 0o750); err != nil {
			return nil, fmt.Errorf("creating profile dir: %w", err)
		}
		if err := m.loadProfiles(); err != nil {
			return nil, fmt.Errorf("loading profiles: %w", err)
		}
	}

	return m, nil
}

// Reconfigure updates tunables without clearing learned or locked profiles.
func (m *Manager) Reconfigure(cfg Config) error {
	if cfg.LearningWindow <= 0 {
		cfg.LearningWindow = 10
	}
	if cfg.SensitivitySigma <= 0 {
		cfg.SensitivitySigma = 2.0
	}
	if cfg.DeviationAction == "" {
		cfg.DeviationAction = deviationActionWarn
	}
	if err := validateDeviationAction(cfg.DeviationAction); err != nil {
		return err
	}
	if cfg.SeasonalityMode == "" {
		cfg.SeasonalityMode = seasonalityNone
	}
	if err := normalizeIntegrityConfig(&cfg); err != nil {
		return err
	}
	if cfg.SeasonalityMode != seasonalityNone {
		return fmt.Errorf("unsupported seasonality_mode %q: only \"none\" is supported", cfg.SeasonalityMode)
	}
	validDims := make(map[string]bool, len(supportedDimensions))
	for _, d := range supportedDimensions {
		validDims[d] = true
	}
	for _, d := range cfg.LockDimensions {
		if !validDims[d] {
			return fmt.Errorf("unsupported lock_dimension %q: valid values are %v", d, supportedDimensions)
		}
	}
	if cfg.ProfileDir != "" {
		if err := os.MkdirAll(cfg.ProfileDir, 0o750); err != nil {
			return fmt.Errorf("creating profile dir: %w", err)
		}
		candidate := &Manager{
			cfg:    cfg,
			agents: make(map[string]*agentState),
		}
		if err := candidate.loadProfiles(); err != nil {
			return fmt.Errorf("loading profiles: %w", err)
		}

		m.mu.Lock()
		profileDirChanged := !sameProfileDir(m.cfg.ProfileDir, cfg.ProfileDir)
		m.cfg = cfg
		if profileDirChanged {
			m.agents = candidate.agents
		} else {
			for agentKey, loaded := range candidate.agents {
				if existing, ok := m.agents[agentKey]; !ok || existing.profile == nil {
					m.agents[agentKey] = loaded
				}
			}
		}
		m.mu.Unlock()
		return nil
	}

	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
	return nil
}

func sameProfileDir(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return filepath.Clean(a) == filepath.Clean(b)
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
	for _, identity := range current.ToolIdentities {
		if isA2AToolIdentity(identity) && !contains(as.profile.ToolIdentities, identity) {
			deviations = append(deviations, Deviation{
				Metric:   "tool_identity:" + identity,
				Baseline: Range{Min: 0, Max: 0, Mean: 0, StdDev: 0},
				Observed: 1,
				Delta:    1,
				Severity: severityHigh,
			})
		}
	}

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

// CheckErr evaluates current session metrics against the locked profile and
// returns validation errors separately so enforcement callers can fail closed.
func (m *Manager) CheckErr(agentKey string, current SessionMetrics) ([]Deviation, error) {
	if err := validateAgentKey(agentKey); err != nil {
		return nil, err
	}
	return m.Check(agentKey, current), nil
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

// GetAgentProfile returns the current profile summary for an agent, including
// agents still in observe/learn state that have no learned profile yet.
func (m *Manager) GetAgentProfile(agentKey string) (Profile, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	as, exists := m.agents[agentKey]
	if !exists {
		return Profile{}, false
	}
	if as.profile == nil {
		return Profile{
			AgentKey: agentKey,
			State:    as.state,
		}, true
	}
	return cloneProfileSnapshot(as.profile, agentKey, as.state), true
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

	if err := m.verifyPendingProfileIntegrityForRatify(agentKey); err != nil {
		return fmt.Errorf("ratification failed: %w", err)
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

	// Delete the persisted profile BEFORE clearing in-memory state. If the
	// file cannot be removed, fail closed: leave the profile enforcing and
	// surface the error rather than reporting a forget that silently
	// resurrects the locked profile on the next restart (loadProfiles
	// re-reads ProfileDir at construction). A missing file is success.
	if m.cfg.ProfileDir != "" {
		path := filepath.Join(m.cfg.ProfileDir, agentKey+profileFileExt)
		m.persistMu.Lock()
		oldProfile, hadProfile, readErr := readExistingRegularFileForRestore(path, "persisted baseline profile", baselineProfileMaxSize)
		if readErr != nil {
			m.persistMu.Unlock()
			return fmt.Errorf("reading persisted profile for agent %q before reset: %w", agentKey, readErr)
		}
		if err := os.Remove(filepath.Clean(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			m.persistMu.Unlock()
			return fmt.Errorf("removing persisted profile for agent %q: %w", agentKey, err)
		}
		if err := m.persistIntegrityManifestLocked(map[string]bool{agentKey: true}); err != nil {
			restoreErr := restoreProfileAfterManifestFailure(path, oldProfile, hadProfile)
			m.persistMu.Unlock()
			if restoreErr != nil {
				err = fmt.Errorf("%w; restoring persisted profile after manifest failure: %w", err, restoreErr)
			}
			return m.logIntegrityPersistenceFailure("reset_manifest_update_failed", fmt.Errorf("updating profile integrity manifest after reset for agent %q: %w", agentKey, err), "agent_key", agentKey)
		}
		m.persistMu.Unlock()
	}

	as.profile = nil
	as.learning = nil
	as.state = StateObserve

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

// ListProfiles returns a copy of every tracked agent profile sorted by agent
// key. Agents still learning are returned with their current state and no
// metrics so operator list views can show progress before ratification.
func (m *Manager) ListProfiles() []Profile {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.agents))
	for k := range m.agents {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	profiles := make([]Profile, 0, len(keys))
	for _, key := range keys {
		as := m.agents[key]
		if as.profile == nil {
			profiles = append(profiles, Profile{
				AgentKey: key,
				State:    as.state,
			})
			continue
		}
		profiles = append(profiles, cloneProfileSnapshot(as.profile, key, as.state))
	}
	return profiles
}

func cloneProfileSnapshot(profile *Profile, agentKey string, state ProfileState) Profile {
	cp := *profile
	cp.AgentKey = agentKey
	cp.State = state
	cp.ToolIdentities = append([]string(nil), profile.ToolIdentities...)
	if cp.RatifiedAt != nil {
		ratifiedAt := *cp.RatifiedAt
		cp.RatifiedAt = &ratifiedAt
	}
	return cp
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

	observed := len(sessions)
	retained := len(data)
	trimmed := observed - retained
	if trimmed < 0 {
		trimmed = 0
	}

	return &Profile{
		AgentKey:             agentKey,
		State:                StateRatify,
		LearnedAt:            time.Now(),
		SessionCount:         retained,
		ObservedSessionCount: observed,
		TrimmedSessionCount:  trimmed,
		ToolIdentities:       collectToolIdentities(data),
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
	return defaultDimensions
}

// persistProfile saves a profile to disk as JSON.
func (m *Manager) persistProfile(agentKey string) error {
	if m.cfg.ProfileDir == "" {
		return nil
	}

	m.persistMu.Lock()
	defer m.persistMu.Unlock()

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
	oldProfile, hadProfile, readErr := readExistingRegularFileForRestore(path, "persisted baseline profile", baselineProfileMaxSize)
	if readErr != nil {
		return fmt.Errorf("reading existing profile before persist: %w", readErr)
	}
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return m.logIntegrityPersistenceFailure("profile_write_failed", err, "agent_key", agentKey)
	}
	if err := m.persistIntegrityManifestLocked(nil); err != nil {
		var restoreErr error
		if !integrityManifestAlreadyCommitted(err) {
			restoreErr = restoreProfileAfterManifestFailure(path, oldProfile, hadProfile)
		}
		if restoreErr != nil {
			err = fmt.Errorf("%w; restoring previous profile after manifest failure: %w", err, restoreErr)
		}
		return m.logIntegrityPersistenceFailure("profile_manifest_update_failed", fmt.Errorf("persisting profile integrity manifest: %w", err), "agent_key", agentKey)
	}
	return nil
}

func normalizeIntegrityConfig(cfg *Config) error {
	if cfg.ProfileDir == "" {
		return nil
	}
	if cfg.IntegrityKeyPath == "" {
		cfg.IntegrityKeyPath = filepath.Clean(cfg.ProfileDir) + ".integrity.key"
	}
	cfg.IntegrityKeyPath = filepath.Clean(cfg.IntegrityKeyPath)
	inside, err := pathWithin(cfg.IntegrityKeyPath, cfg.ProfileDir)
	if err != nil {
		return fmt.Errorf("validating baseline integrity key path: %w", err)
	}
	if inside {
		return fmt.Errorf("baseline integrity key path %q must be outside profile_dir %q", cfg.IntegrityKeyPath, cfg.ProfileDir)
	}
	return nil
}

func pathWithin(path, dir string) (bool, error) {
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return false, err
	}
	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil {
		return false, err
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))), nil
}

func (m *Manager) integrityManifestPath() string {
	return filepath.Join(m.cfg.ProfileDir, integrityManifestDirName, integrityManifestFileName)
}

func (m *Manager) integrityHighWaterPath() string {
	return filepath.Clean(m.cfg.IntegrityKeyPath) + ".generation"
}

func (m *Manager) acquireIntegrityHighWaterLock() (func(), error) {
	return acquireIntegrityHighWaterLock(m.cfg.IntegrityKeyPath)
}

func (m *Manager) integrityStateContextID() string {
	profileDir, err := filepath.Abs(filepath.Clean(m.cfg.ProfileDir))
	if err != nil {
		profileDir = filepath.Clean(m.cfg.ProfileDir)
	}
	keyPath, err := filepath.Abs(filepath.Clean(m.cfg.IntegrityKeyPath))
	if err != nil {
		keyPath = filepath.Clean(m.cfg.IntegrityKeyPath)
	}
	sum := sha256.Sum256([]byte("baseline-integrity-generation-v1\n" + profileDir + "\n" + keyPath))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) integrityGenerationDigest(generation uint64, manifestHMAC string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "baseline-integrity-generation-v3\n%s\n%d\n%s", m.integrityStateContextID(), generation, manifestHMAC)
	return hex.EncodeToString(mac.Sum(nil))
}

func (m *Manager) loadIntegrityKey(create bool) ([]byte, error) {
	path := filepath.Clean(m.cfg.IntegrityKeyPath)
	data, err := readRegularFileNoSymlinkInRoot(path, filepath.Dir(path), "baseline integrity key", integrityStateMaxSize)
	if err == nil {
		key, decodeErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decodeErr != nil {
			return nil, fmt.Errorf("decoding baseline integrity key: %w", decodeErr)
		}
		if len(key) != integrityKeyBytes {
			return nil, fmt.Errorf("baseline integrity key length = %d, want %d", len(key), integrityKeyBytes)
		}
		return key, nil
	}
	if !create || !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key := make([]byte, integrityKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating baseline integrity key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("creating baseline integrity key directory: %w", err)
	}
	if err := atomicfile.Write(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("writing baseline integrity key: %w", err)
	}
	return key, nil
}

func (m *Manager) readIntegrityHighWater(key []byte) (uint64, string, bool, error) {
	path := m.integrityHighWaterPath()
	data, err := readRegularFileNoSymlinkInRoot(path, filepath.Dir(path), "baseline integrity generation high-water", integrityStateMaxSize)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, "", false, nil
		}
		return 0, "", false, err
	}
	var state integrityHighWaterState
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return 0, "", false, fmt.Errorf("parse baseline integrity generation high-water: %w", err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return 0, "", false, fmt.Errorf("parse baseline integrity generation high-water: %w", err)
	}
	if state.Generation == 0 {
		return 0, "", false, errors.New("baseline integrity generation high-water must be greater than zero")
	}
	if state.Context != m.integrityStateContextID() {
		return 0, "", false, errors.New("baseline integrity generation high-water context mismatch")
	}
	storedManifestHMAC, err := decodeSHA256Hex(state.ManifestHMAC, "baseline integrity generation high-water manifest hmac")
	if err != nil {
		return 0, "", false, err
	}
	wantDigest := m.integrityGenerationDigest(state.Generation, state.ManifestHMAC, key)
	gotDigest, err := hex.DecodeString(state.Digest)
	if err != nil {
		return 0, "", false, fmt.Errorf("decode baseline integrity generation high-water digest: %w", err)
	}
	want, err := hex.DecodeString(wantDigest)
	if err != nil {
		return 0, "", false, err
	}
	if len(gotDigest) != sha256.Size {
		return 0, "", false, fmt.Errorf("baseline integrity generation high-water digest length = %d, want %d", len(gotDigest), sha256.Size)
	}
	if !hmac.Equal(gotDigest, want) {
		return 0, "", false, errors.New("baseline integrity generation high-water digest mismatch")
	}
	return state.Generation, hex.EncodeToString(storedManifestHMAC), true, nil
}

func (m *Manager) writeIntegrityHighWater(generation uint64, key []byte, manifestHMAC string) error {
	if generation == 0 {
		return errors.New("baseline integrity generation must be greater than zero")
	}
	normalizedManifestHMAC, err := decodeSHA256Hex(manifestHMAC, "baseline integrity manifest hmac")
	if err != nil {
		return err
	}
	manifestHMAC = hex.EncodeToString(normalizedManifestHMAC)
	path := m.integrityHighWaterPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating baseline integrity generation directory: %w", err)
	}
	data, err := json.Marshal(integrityHighWaterState{
		Generation:   generation,
		Context:      m.integrityStateContextID(),
		ManifestHMAC: manifestHMAC,
		Digest:       m.integrityGenerationDigest(generation, manifestHMAC, key),
	})
	if err != nil {
		return fmt.Errorf("marshaling baseline integrity generation high-water: %w", err)
	}
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return fmt.Errorf("writing baseline integrity generation high-water: %w", err)
	}
	return nil
}

func (m *Manager) nextIntegrityManifestGenerationLocked(key []byte, allowMissingHighWater bool) (uint64, error) {
	highWater, _, found, err := m.readIntegrityHighWater(key)
	if err != nil {
		return 0, fmt.Errorf("baseline integrity generation unreadable, cannot sign manifest: %w", err)
	}
	if !found && !allowMissingHighWater {
		return 0, errors.New("baseline integrity generation high-water missing, cannot sign manifest without trusted rollback floor")
	}
	next := uint64(1)
	if found {
		next = highWater + 1
		if next == 0 {
			return 0, errors.New("baseline integrity generation overflow")
		}
	}
	return next, nil
}

func (m *Manager) nextIntegrityManifestGeneration() (uint64, error) {
	integrityHighWaterMu.Lock()
	defer integrityHighWaterMu.Unlock()

	unlock, err := m.acquireIntegrityHighWaterLock()
	if err != nil {
		return 0, err
	}
	defer unlock()

	trustedState, err := m.integrityTrustedStateExists()
	if err != nil {
		return 0, fmt.Errorf("checking baseline integrity trusted state: %w", err)
	}
	key, err := m.loadIntegrityKey(!trustedState)
	if err != nil {
		return 0, err
	}
	return m.nextIntegrityManifestGenerationLocked(key, !trustedState)
}

func (m *Manager) acceptIntegrityManifestGeneration(generation uint64, manifestHMAC string, key []byte) error {
	if generation == 0 {
		return errors.New("baseline integrity manifest generation must be greater than zero")
	}
	manifestHMACBytes, err := decodeSHA256Hex(manifestHMAC, "baseline integrity manifest hmac")
	if err != nil {
		return err
	}

	integrityHighWaterMu.Lock()
	defer integrityHighWaterMu.Unlock()

	unlock, err := m.acquireIntegrityHighWaterLock()
	if err != nil {
		return err
	}
	defer unlock()

	highWater, acceptedManifestHMAC, found, err := m.readIntegrityHighWater(key)
	if err != nil {
		return fmt.Errorf("baseline integrity generation unreadable, cannot verify rollback: %w", err)
	}
	if !found {
		return errors.New("baseline integrity generation high-water missing, cannot verify rollback")
	}
	if found && generation < highWater {
		return fmt.Errorf("baseline integrity manifest rollback rejected: generation %d below accepted %d", generation, highWater)
	}
	if generation == highWater {
		acceptedManifestHMACBytes, err := decodeSHA256Hex(acceptedManifestHMAC, "accepted baseline integrity manifest hmac")
		if err != nil {
			return err
		}
		if !hmac.Equal(manifestHMACBytes, acceptedManifestHMACBytes) {
			return fmt.Errorf("baseline integrity manifest replay rejected: generation %d has a different accepted manifest", generation)
		}
	}
	if generation > highWater {
		if err := m.writeIntegrityHighWater(generation, key, hex.EncodeToString(manifestHMACBytes)); err != nil {
			return fmt.Errorf("persist baseline integrity generation high-water: %w", err)
		}
	}
	return nil
}

func (m *Manager) integrityTrustedStateExists() (bool, error) {
	for _, path := range []string{m.cfg.IntegrityKeyPath, m.integrityHighWaterPath()} {
		_, err := os.Lstat(filepath.Clean(path))
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func readRegularFileNoSymlink(path, label string, maxSize int64) ([]byte, error) {
	return readRegularFileNoSymlinkInRootWithOpenHook(path, filepath.Dir(filepath.Clean(path)), label, maxSize, nil)
}

func readRegularFileNoSymlinkWithOpenHook(path, label string, maxSize int64, beforeOpen func() error) ([]byte, error) {
	return readRegularFileNoSymlinkInRootWithOpenHook(path, filepath.Dir(filepath.Clean(path)), label, maxSize, beforeOpen)
}

func readRegularFileNoSymlinkInRoot(path, trustedRoot, label string, maxSize int64) ([]byte, error) {
	return readRegularFileNoSymlinkInRootWithOpenHook(path, trustedRoot, label, maxSize, nil)
}

func readRegularFileNoSymlinkInRootWithOpenHook(path, trustedRoot, label string, maxSize int64, beforeOpen func() error) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symlink", label)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", label)
	}
	if maxSize > 0 && info.Size() > maxSize {
		return nil, fmt.Errorf("%s exceeds maximum size", label)
	}
	canonicalRoot, relPath, err := trustedRootRelativePath(trustedRoot, cleanPath, label)
	if err != nil {
		return nil, err
	}
	if err := rejectSymlinkParents(canonicalRoot, relPath, label); err != nil {
		return nil, err
	}
	if beforeOpen != nil {
		if err := beforeOpen(); err != nil {
			return nil, fmt.Errorf("prepare open %s: %w", label, err)
		}
	}
	f, err := openRegularFileNoSymlinkBelowRoot(canonicalRoot, relPath, cleanPath)
	if err != nil {
		if errors.Is(err, errELOOP) {
			return nil, fmt.Errorf("%s symlink raced into place", label)
		}
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer func() { _ = f.Close() }()
	after, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened %s: %w", label, err)
	}
	if !after.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", label)
	}
	if !os.SameFile(info, after) {
		return nil, fmt.Errorf("%s changed during read; retry after quiescing writes", label)
	}
	if maxSize > 0 && after.Size() > maxSize {
		return nil, fmt.Errorf("%s exceeds maximum size", label)
	}
	reader := io.Reader(f)
	if maxSize > 0 {
		reader = io.LimitReader(f, maxSize+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if maxSize > 0 && int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%s exceeds maximum size", label)
	}
	return data, nil
}

func trustedRootRelativePath(trustedRoot, cleanPath, label string) (string, string, error) {
	if trustedRoot == "" {
		return "", "", fmt.Errorf("%s trusted root is empty", label)
	}
	rootAbs, err := filepath.Abs(filepath.Clean(trustedRoot))
	if err != nil {
		return "", "", fmt.Errorf("resolve trusted root for %s: %w", label, err)
	}
	pathAbs, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve path for %s: %w", label, err)
	}
	relPath, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return "", "", fmt.Errorf("resolve relative path for %s: %w", label, err)
	}
	if relPath == "." || relPath == ".." || strings.HasPrefix(relPath, ".."+string(os.PathSeparator)) {
		return "", "", fmt.Errorf("%s path %q escapes trusted root %q", label, cleanPath, trustedRoot)
	}
	canonicalRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", "", fmt.Errorf("canonicalize trusted root for %s: %w", label, err)
	}
	return canonicalRoot, relPath, nil
}

func rejectSymlinkParents(canonicalRoot, relPath, label string) error {
	if relPath == "." || relPath == "" {
		return nil
	}

	current := canonicalRoot
	parts := strings.Split(filepath.Clean(relPath), string(os.PathSeparator))
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("stat parent directory for %s: %w", label, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s parent directory %q must not be a symlink", label, current)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s parent path %q must be a directory", label, current)
		}
	}
	return nil
}

func readExistingRegularFileForRestore(path, label string, maxSize int64) ([]byte, bool, error) {
	data, err := readRegularFileNoSymlink(path, label, maxSize)
	if err == nil {
		return data, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, err
}

func restoreProfileAfterManifestFailure(path string, oldData []byte, hadProfile bool) error {
	cleanPath := filepath.Clean(path)
	if hadProfile {
		return atomicfile.Write(cleanPath, oldData, 0o600)
	}
	if err := os.Remove(cleanPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type integrityManifestCommittedError struct {
	err error
}

func (e integrityManifestCommittedError) Error() string {
	return e.err.Error()
}

func (e integrityManifestCommittedError) Unwrap() error {
	return e.err
}

func integrityManifestAlreadyCommitted(err error) bool {
	var committed integrityManifestCommittedError
	return errors.As(err, &committed)
}

func (m *Manager) integrityLogAttrs(failureClass string, err error, attrs ...any) []any {
	fields := sanitizeLogAttrs([]any{
		"failure_class", failureClass,
		"profile_dir", m.cfg.ProfileDir,
		"manifest_path", m.integrityManifestPath(),
		"key_path", m.cfg.IntegrityKeyPath,
		"high_water_path", m.integrityHighWaterPath(),
		"deviation_action", m.cfg.DeviationAction,
	})
	if err != nil {
		fields = append(fields, "error_sha256", logValueFingerprint("baseline-integrity-error-v1", err.Error()))
	}
	// Caller-supplied attrs carry agent-influenced identifiers (agent_key,
	// declared_agent_key, profile names). Preserve correlation through stable
	// fingerprints instead of logging attacker-influenced strings in the generic
	// integrity failure sinks.
	return append(fields, integrityDiagnosticLogAttrs(attrs)...)
}

func (m *Manager) pendingProfileIntegrityNonEnforcingLogAttrs(agentKey string) []any {
	return sanitizeLogAttrs([]any{
		"failure_class", "pending_profile_integrity_nonenforcing",
		"profile_dir", m.cfg.ProfileDir,
		"manifest_path", m.integrityManifestPath(),
		"key_path", m.cfg.IntegrityKeyPath,
		"high_water_path", m.integrityHighWaterPath(),
		"deviation_action", m.cfg.DeviationAction,
		"agent_key_sha256", logValueFingerprint("baseline-agent-key-v1", agentKey),
	})
}

func integrityDiagnosticLogAttrs(attrs []any) []any {
	if len(attrs) == 0 {
		return attrs
	}
	out := make([]any, 0, len(attrs))
	for i := 0; i < len(attrs); i++ {
		if attr, ok := attrs[i].(slog.Attr); ok {
			appendIntegrityDiagnosticLogAttr(&out, attr.Key, attr.Value.Any())
			continue
		}
		key, ok := attrs[i].(string)
		if !ok || i+1 >= len(attrs) {
			continue
		}
		i++
		appendIntegrityDiagnosticLogAttr(&out, key, attrs[i])
	}
	return out
}

func appendIntegrityDiagnosticLogAttr(out *[]any, key string, value any) {
	key = sanitizeLogValue(key)
	switch v := value.(type) {
	case string:
		*out = append(*out, key+"_sha256", logValueFingerprint("baseline-integrity-"+key+"-v1", v))
	case error:
		*out = append(*out, key+"_sha256", logValueFingerprint("baseline-integrity-"+key+"-v1", v.Error()))
	case slog.Attr:
		appendIntegrityDiagnosticLogAttr(out, v.Key, v.Value.Any())
	default:
		*out = append(*out, key, value)
	}
}

func logValueFingerprint(scope, value string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + value))
	return hex.EncodeToString(sum[:])
}

// sanitizeLogAttrs returns a copy of a slog key/value attr slice with
// log-control characters replaced by spaces in every value. Attr keys are
// preserved exactly because callers provide literal keys.
func sanitizeLogAttrs(attrs []any) []any {
	if len(attrs) == 0 {
		return attrs
	}
	out := make([]any, len(attrs))
	for i := 0; i < len(attrs); i++ {
		if attr, ok := attrs[i].(slog.Attr); ok {
			out[i] = sanitizeLogAttr(attr)
			continue
		}
		out[i] = attrs[i]
		if _, ok := attrs[i].(string); ok && i+1 < len(attrs) {
			i++
			out[i] = sanitizeLogAttrValue(attrs[i])
		}
	}
	return out
}

func sanitizeLogAttr(attr slog.Attr) slog.Attr {
	switch attr.Value.Kind() {
	case slog.KindString:
		attr.Value = slog.StringValue(sanitizeLogValue(attr.Value.String()))
	case slog.KindAny:
		attr.Value = slog.AnyValue(sanitizeLogAttrValue(attr.Value.Any()))
	}
	return attr
}

func sanitizeLogAttrValue(value any) any {
	switch v := value.(type) {
	case string:
		return sanitizeLogValue(v)
	case error:
		return sanitizeLogValue(v.Error())
	case slog.Attr:
		return sanitizeLogAttr(v)
	default:
		return value
	}
}

// sanitizeLogValue replaces terminal and line-breaking control characters with
// spaces so an attacker-influenced value cannot inject, split, or visually
// rewrite a forged log line.
func sanitizeLogValue(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

func (m *Manager) logIntegrityVerificationFailure(failureClass string, err error, attrs ...any) error {
	slog.Error("baseline integrity verification failed", m.integrityLogAttrs(failureClass, err, attrs...)...)
	return err
}

func (m *Manager) logIntegrityPersistenceFailure(failureClass string, err error, attrs ...any) error {
	slog.Error("baseline integrity persistence failed", m.integrityLogAttrs(failureClass, err, attrs...)...)
	return err
}

func (m *Manager) cleanupNewIntegrityTrustedState(cleanup bool, err error) error {
	if !cleanup {
		return err
	}
	var cleanupErr error
	for _, path := range []string{m.cfg.IntegrityKeyPath, m.integrityHighWaterPath()} {
		if removeErr := os.Remove(filepath.Clean(path)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, removeErr)
		}
	}
	if cleanupErr != nil {
		return fmt.Errorf("%w; cleaning newly-created baseline integrity trusted state after failed manifest commit: %w", err, cleanupErr)
	}
	return err
}

func signIntegrityManifest(manifest integrityManifest, key []byte) (string, error) {
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("marshaling canonical integrity manifest: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func decodeSHA256Hex(value, label string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", label, err)
	}
	if len(decoded) != sha256.Size {
		return nil, fmt.Errorf("%s length = %d, want %d", label, len(decoded), sha256.Size)
	}
	return decoded, nil
}

func verifyIntegrityManifest(data, key []byte) (integrityManifest, error) {
	manifest, _, err := verifyIntegrityManifestWithHMAC(data, key)
	return manifest, err
}

func verifyIntegrityManifestWithHMAC(data, key []byte) (integrityManifest, string, error) {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return integrityManifest{}, "", fmt.Errorf("decoding integrity manifest: %w", err)
	}
	var file integrityManifestFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return integrityManifest{}, "", fmt.Errorf("decoding integrity manifest: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return integrityManifest{}, "", errors.New("decoding integrity manifest: trailing data after manifest")
		}
		return integrityManifest{}, "", fmt.Errorf("decoding integrity manifest: %w", err)
	}
	if file.Manifest.SchemaVersion != integrityManifestVersion {
		return integrityManifest{}, "", fmt.Errorf("integrity manifest schema_version = %d, want %d", file.Manifest.SchemaVersion, integrityManifestVersion)
	}
	if file.Manifest.Algorithm != integrityManifestAlg {
		return integrityManifest{}, "", fmt.Errorf("integrity manifest algorithm = %q, want %q", file.Manifest.Algorithm, integrityManifestAlg)
	}
	want, err := decodeSHA256Hex(file.HMAC, "integrity manifest hmac")
	if err != nil {
		return integrityManifest{}, "", err
	}
	gotHex, err := signIntegrityManifest(file.Manifest, key)
	if err != nil {
		return integrityManifest{}, "", err
	}
	got, err := hex.DecodeString(gotHex)
	if err != nil {
		return integrityManifest{}, "", err
	}
	if !hmac.Equal(got, want) {
		return integrityManifest{}, "", errors.New("integrity manifest hmac verification failed")
	}
	return file.Manifest, hex.EncodeToString(want), nil
}

func profileBytesHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (m *Manager) persistedProfileFilesExist(exclude map[string]bool) (bool, error) {
	entries, err := os.ReadDir(filepath.Clean(m.cfg.ProfileDir))
	if err != nil {
		return false, fmt.Errorf("reading profile directory: %w", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != profileFileExt {
			continue
		}
		agentKey := strings.TrimSuffix(entry.Name(), profileFileExt)
		if exclude[agentKey] {
			continue
		}
		if entry.IsDir() {
			return false, fmt.Errorf("persisted baseline profile path %q is a directory", entry.Name())
		}
		return true, nil
	}
	return false, nil
}

func (m *Manager) persistIntegrityManifest(exclude map[string]bool) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	return m.persistIntegrityManifestLocked(exclude)
}

func profileStateIsIntegrityBound(state ProfileState) bool {
	return state == StateLocked || state == StateRatify
}

func (m *Manager) persistIntegrityManifestLocked(exclude map[string]bool) error {
	if m.cfg.ProfileDir == "" {
		return nil
	}

	keys := make([]string, 0, len(m.agents))
	for agentKey, as := range m.agents {
		if exclude[agentKey] || as == nil || as.profile == nil || !profileStateIsIntegrityBound(as.profile.State) {
			continue
		}
		keys = append(keys, agentKey)
	}
	sort.Strings(keys)

	entries := make([]integrityManifestEntry, 0, len(keys))
	for _, agentKey := range keys {
		if err := validateAgentKey(agentKey); err != nil {
			return fmt.Errorf("refusing to manifest baseline profile: %w", err)
		}
		path := filepath.Join(m.cfg.ProfileDir, agentKey+profileFileExt)
		data, err := readRegularFileNoSymlinkInRoot(path, m.cfg.ProfileDir, "baseline profile", baselineProfileMaxSize)
		if err != nil {
			return m.logIntegrityPersistenceFailure("profile_read_failed", fmt.Errorf("reading profile %q for integrity manifest: %w", agentKey, err), "agent_key", agentKey)
		}
		as := m.agents[agentKey]
		entries = append(entries, integrityManifestEntry{
			AgentKey: agentKey,
			SHA256:   profileBytesHash(data),
			State:    as.profile.State,
		})
	}

	hasProfiles, err := m.persistedProfileFilesExist(exclude)
	if err != nil {
		return m.logIntegrityPersistenceFailure("profile_scan_failed", err)
	}
	manifestPath := m.integrityManifestPath()
	if len(entries) == 0 && !hasProfiles {
		trustedState, err := m.integrityTrustedStateExists()
		if err != nil {
			return m.logIntegrityPersistenceFailure("trusted_state_check_failed", fmt.Errorf("checking baseline integrity trusted state: %w", err))
		}
		if !trustedState {
			if err := os.Remove(filepath.Clean(manifestPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return m.logIntegrityPersistenceFailure("empty_manifest_remove_failed", fmt.Errorf("removing empty baseline integrity manifest: %w", err))
			}
			_ = os.Remove(filepath.Clean(filepath.Dir(manifestPath)))
			return nil
		}
	}

	integrityHighWaterMu.Lock()
	defer integrityHighWaterMu.Unlock()

	unlock, err := m.acquireIntegrityHighWaterLock()
	if err != nil {
		return m.logIntegrityPersistenceFailure("generation_lock_failed", err)
	}
	defer unlock()

	trustedState, err := m.integrityTrustedStateExists()
	if err != nil {
		return m.logIntegrityPersistenceFailure("trusted_state_check_failed", fmt.Errorf("checking baseline integrity trusted state: %w", err))
	}
	key, err := m.loadIntegrityKey(!trustedState)
	if err != nil {
		return m.logIntegrityPersistenceFailure("key_load_failed", err)
	}
	cleanupNewTrustedState := !trustedState
	generation, err := m.nextIntegrityManifestGenerationLocked(key, !trustedState)
	if err != nil {
		err = m.cleanupNewIntegrityTrustedState(cleanupNewTrustedState, err)
		return m.logIntegrityPersistenceFailure("generation_advance_failed", err)
	}
	manifest := integrityManifest{
		SchemaVersion: integrityManifestVersion,
		Algorithm:     integrityManifestAlg,
		Generation:    generation,
		Profiles:      entries,
	}
	mac, err := signIntegrityManifest(manifest, key)
	if err != nil {
		err = m.cleanupNewIntegrityTrustedState(cleanupNewTrustedState, err)
		return m.logIntegrityPersistenceFailure("manifest_sign_failed", err, "generation", generation)
	}
	data, err := json.MarshalIndent(integrityManifestFile{
		Manifest: manifest,
		HMAC:     mac,
	}, "", "  ")
	if err != nil {
		err = m.cleanupNewIntegrityTrustedState(cleanupNewTrustedState, fmt.Errorf("marshaling integrity manifest: %w", err))
		return m.logIntegrityPersistenceFailure("manifest_marshal_failed", err, "generation", generation)
	}
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o750); err != nil {
		err = m.cleanupNewIntegrityTrustedState(cleanupNewTrustedState, fmt.Errorf("creating baseline integrity manifest directory: %w", err))
		return m.logIntegrityPersistenceFailure("manifest_dir_create_failed", err, "generation", generation)
	}
	if err := atomicfile.Write(manifestPath, data, 0o600); err != nil {
		err = m.cleanupNewIntegrityTrustedState(cleanupNewTrustedState, err)
		return m.logIntegrityPersistenceFailure("manifest_write_failed", err, "generation", generation)
	}
	if err := m.writeIntegrityHighWater(generation, key, mac); err != nil {
		err = m.logIntegrityPersistenceFailure("generation_advance_failed", err, "generation", generation)
		return integrityManifestCommittedError{err: err}
	}
	return nil
}

func (m *Manager) verifyPendingProfileIntegrityForRatify(agentKey string) error {
	if m.cfg.ProfileDir == "" {
		return nil
	}
	err := m.verifyPersistedProfileIntegrity(agentKey)
	if err == nil {
		return nil
	}
	if m.cfg.enforces() {
		return m.logIntegrityVerificationFailure("pending_profile_integrity_failed", fmt.Errorf("verifying pending baseline profile %q before ratify: %w", agentKey, err), "agent_key", agentKey)
	}
	slog.Warn("baseline pending profile integrity verification failed; continuing under non-enforcing deviation_action",
		m.pendingProfileIntegrityNonEnforcingLogAttrs(agentKey)...)
	return nil
}

func (m *Manager) verifyPersistedProfileIntegrity(agentKey string) error {
	const wantState = StateRatify

	manifestData, err := readRegularFileNoSymlinkInRoot(m.integrityManifestPath(), m.cfg.ProfileDir, "baseline integrity manifest", baselineProfileMaxSize)
	if err != nil {
		return fmt.Errorf("reading baseline integrity manifest: %w", err)
	}
	key, err := m.loadIntegrityKey(false)
	if err != nil {
		return err
	}
	manifest, manifestHMAC, err := verifyIntegrityManifestWithHMAC(manifestData, key)
	if err != nil {
		return err
	}
	for _, expected := range manifest.Profiles {
		if expected.AgentKey != agentKey {
			continue
		}
		if expected.State != wantState {
			return fmt.Errorf("baseline integrity manifest entry for agent %q has state %q, want %q", agentKey, expected.State, wantState)
		}
		path := filepath.Join(m.cfg.ProfileDir, agentKey+profileFileExt)
		data, err := readRegularFileNoSymlinkInRoot(path, m.cfg.ProfileDir, "pending baseline profile", baselineProfileMaxSize)
		if err != nil {
			return fmt.Errorf("reading pending baseline profile %q required by integrity manifest: %w", agentKey, err)
		}
		if got := profileBytesHash(data); got != expected.SHA256 {
			return fmt.Errorf("pending baseline profile %q hash mismatch against integrity manifest", agentKey)
		}
		var profile Profile
		if err := jsonscan.RejectDuplicateKeys(data); err != nil {
			return fmt.Errorf("parsing pending baseline profile %q required by integrity manifest: %w", agentKey, err)
		}
		if err := json.Unmarshal(data, &profile); err != nil {
			return fmt.Errorf("parsing pending baseline profile %q required by integrity manifest: %w", agentKey, err)
		}
		if profile.AgentKey == "" {
			profile.AgentKey = agentKey
		}
		if profile.AgentKey != agentKey {
			return fmt.Errorf("pending baseline profile %q declares agent_key %q", agentKey, profile.AgentKey)
		}
		if profile.State != wantState {
			return fmt.Errorf("pending baseline profile %q state = %q, want %q", agentKey, profile.State, wantState)
		}
		if err := m.acceptIntegrityManifestGeneration(manifest.Generation, manifestHMAC, key); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("baseline integrity manifest missing %q entry for agent %q", wantState, agentKey)
}

func (m *Manager) verifyPersistedIntegrity(entries []os.DirEntry) (map[string]Profile, error) {
	hasProfileFiles := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != profileFileExt {
			continue
		}
		if entry.IsDir() {
			err := fmt.Errorf("persisted baseline JSON path %q is a directory under enforcing deviation_action %q", entry.Name(), m.cfg.DeviationAction)
			return nil, m.logIntegrityVerificationFailure("profile_path_directory", err, "profile", entry.Name())
		}
		hasProfileFiles = true
	}

	manifestData, err := readRegularFileNoSymlinkInRoot(m.integrityManifestPath(), m.cfg.ProfileDir, "baseline integrity manifest", baselineProfileMaxSize)
	if errors.Is(err, os.ErrNotExist) {
		if hasProfileFiles {
			err := fmt.Errorf("baseline integrity manifest missing while persisted profiles exist under enforcing deviation_action %q", m.cfg.DeviationAction)
			return nil, m.logIntegrityVerificationFailure("missing_manifest", err)
		}
		trustedState, stateErr := m.integrityTrustedStateExists()
		if stateErr != nil {
			err := fmt.Errorf("checking baseline integrity trusted state under enforcing deviation_action %q: %w", m.cfg.DeviationAction, stateErr)
			return nil, m.logIntegrityVerificationFailure("trusted_state_check_failed", err)
		}
		if trustedState {
			err := fmt.Errorf("baseline integrity manifest missing while trusted integrity state exists under enforcing deviation_action %q", m.cfg.DeviationAction)
			return nil, m.logIntegrityVerificationFailure("missing_manifest_with_trusted_state", err)
		}
		return map[string]Profile{}, nil
	}
	if err != nil {
		err := fmt.Errorf("reading baseline integrity manifest under enforcing deviation_action %q: %w", m.cfg.DeviationAction, err)
		return nil, m.logIntegrityVerificationFailure("manifest_read_failed", err)
	}
	key, err := m.loadIntegrityKey(false)
	if err != nil {
		return nil, m.logIntegrityVerificationFailure("key_load_failed", err)
	}
	manifest, manifestHMAC, err := verifyIntegrityManifestWithHMAC(manifestData, key)
	if err != nil {
		return nil, m.logIntegrityVerificationFailure("manifest_invalid", err)
	}

	verified := make(map[string]Profile, len(manifest.Profiles))
	seen := make(map[string]bool, len(manifest.Profiles))
	for _, expected := range manifest.Profiles {
		if err := validateAgentKey(expected.AgentKey); err != nil {
			err := fmt.Errorf("invalid agent in baseline integrity manifest: %w", err)
			return nil, m.logIntegrityVerificationFailure("invalid_agent", err, "agent_key", expected.AgentKey, "generation", manifest.Generation)
		}
		if seen[expected.AgentKey] {
			err := fmt.Errorf("duplicate agent %q in baseline integrity manifest", expected.AgentKey)
			return nil, m.logIntegrityVerificationFailure("duplicate_agent", err, "agent_key", expected.AgentKey, "generation", manifest.Generation)
		}
		seen[expected.AgentKey] = true
		if !profileStateIsIntegrityBound(expected.State) {
			err := fmt.Errorf("baseline integrity manifest entry for agent %q has unsupported state %q", expected.AgentKey, expected.State)
			return nil, m.logIntegrityVerificationFailure("manifest_entry_state_mismatch", err, "agent_key", expected.AgentKey, "generation", manifest.Generation)
		}

		path := filepath.Join(m.cfg.ProfileDir, expected.AgentKey+profileFileExt)
		data, err := readRegularFileNoSymlinkInRoot(path, m.cfg.ProfileDir, "integrity-bound baseline profile", baselineProfileMaxSize)
		if err != nil {
			err := fmt.Errorf("reading integrity-bound baseline profile %q required by integrity manifest: %w", expected.AgentKey, err)
			return nil, m.logIntegrityVerificationFailure("profile_read_failed", err, "agent_key", expected.AgentKey, "generation", manifest.Generation)
		}
		if got := profileBytesHash(data); got != expected.SHA256 {
			err := fmt.Errorf("integrity-bound baseline profile %q hash mismatch against integrity manifest", expected.AgentKey)
			return nil, m.logIntegrityVerificationFailure("hash_mismatch", err, "agent_key", expected.AgentKey, "generation", manifest.Generation)
		}
		var profile Profile
		if err := jsonscan.RejectDuplicateKeys(data); err != nil {
			err := fmt.Errorf("parsing integrity-bound baseline profile %q required by integrity manifest: %w", expected.AgentKey, err)
			return nil, m.logIntegrityVerificationFailure("profile_parse_failed", err, "agent_key", expected.AgentKey, "generation", manifest.Generation)
		}
		if err := json.Unmarshal(data, &profile); err != nil {
			err := fmt.Errorf("parsing integrity-bound baseline profile %q required by integrity manifest: %w", expected.AgentKey, err)
			return nil, m.logIntegrityVerificationFailure("profile_parse_failed", err, "agent_key", expected.AgentKey, "generation", manifest.Generation)
		}
		if profile.AgentKey == "" {
			profile.AgentKey = expected.AgentKey
		}
		if profile.AgentKey != expected.AgentKey {
			err := fmt.Errorf("integrity-bound baseline profile %q declares agent_key %q", expected.AgentKey, profile.AgentKey)
			return nil, m.logIntegrityVerificationFailure("profile_agent_mismatch", err, "agent_key", expected.AgentKey, "declared_agent_key", profile.AgentKey, "generation", manifest.Generation)
		}
		if profile.State != expected.State {
			err := fmt.Errorf("integrity-bound baseline profile %q state = %q, want %q", expected.AgentKey, profile.State, expected.State)
			return nil, m.logIntegrityVerificationFailure("profile_state_mismatch", err, "agent_key", expected.AgentKey, "generation", manifest.Generation)
		}
		verified[expected.AgentKey] = profile
	}
	if err := m.acceptIntegrityManifestGeneration(manifest.Generation, manifestHMAC, key); err != nil {
		return nil, m.logIntegrityVerificationFailure("rollback_rejected", err, "generation", manifest.Generation)
	}
	return verified, nil
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

	verified := map[string]Profile{}
	if m.cfg.enforces() {
		verified, err = m.verifyPersistedIntegrity(entries)
		if err != nil {
			return err
		}
	}

	loadedAgents := make(map[string]string, len(entries))
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != profileFileExt {
			continue
		}
		if entry.IsDir() {
			if m.cfg.enforces() {
				err := fmt.Errorf("persisted baseline profile %q is a directory under enforcing deviation_action %q", entry.Name(), m.cfg.DeviationAction)
				return m.logIntegrityVerificationFailure("profile_path_directory", err, "profile", entry.Name())
			}
			continue
		}

		fileAgentKey := strings.TrimSuffix(entry.Name(), profileFileExt)
		var profile Profile
		if verifiedProfile, ok := verified[fileAgentKey]; ok {
			profile = verifiedProfile
		} else {
			path := filepath.Join(m.cfg.ProfileDir, entry.Name())
			data, err := readRegularFileNoSymlinkInRoot(path, m.cfg.ProfileDir, "persisted baseline profile", baselineProfileMaxSize)
			if err != nil {
				// A persisted profile that exists but cannot be read may be a
				// locked, enforcing profile. Under an enforcing action we cannot
				// prove it is not, so fail closed rather than silently start with
				// enforcement erased. Observational (warn) mode has no enforcement
				// to lose, so it skips.
				if m.cfg.enforces() {
					err := fmt.Errorf("reading persisted baseline profile %q under enforcing deviation_action %q (refusing to start without it; fix or restore the file): %w", entry.Name(), m.cfg.DeviationAction, err)
					return m.logIntegrityVerificationFailure("profile_read_failed", err, "profile", entry.Name())
				}
				slog.Warn("skipping unreadable persisted baseline profile", sanitizeLogAttrs([]any{
					"profile", entry.Name(),
					"deviation_action", m.cfg.DeviationAction,
					"error", err,
				})...)
				continue
			}

			if err := jsonscan.RejectDuplicateKeys(data); err != nil {
				if m.cfg.enforces() {
					err := fmt.Errorf("parsing persisted baseline profile %q under enforcing deviation_action %q (refusing to start with an ambiguous profile; fix or restore the file): %w", entry.Name(), m.cfg.DeviationAction, err)
					return m.logIntegrityVerificationFailure("profile_parse_failed", err, "profile", entry.Name())
				}
				slog.Warn("skipping corrupt persisted baseline profile", sanitizeLogAttrs([]any{
					"profile", entry.Name(),
					"deviation_action", m.cfg.DeviationAction,
					"error", err,
				})...)
				continue
			}
			if err := json.Unmarshal(data, &profile); err != nil {
				if m.cfg.enforces() {
					err := fmt.Errorf("parsing persisted baseline profile %q under enforcing deviation_action %q (refusing to start with a corrupt profile; fix or restore the file): %w", entry.Name(), m.cfg.DeviationAction, err)
					return m.logIntegrityVerificationFailure("profile_parse_failed", err, "profile", entry.Name())
				}
				slog.Warn("skipping corrupt persisted baseline profile", sanitizeLogAttrs([]any{
					"profile", entry.Name(),
					"deviation_action", m.cfg.DeviationAction,
					"error", err,
				})...)
				continue
			}
			if m.cfg.enforces() && profileStateIsIntegrityBound(profile.State) {
				err := fmt.Errorf("integrity-bound baseline profile %q is missing from integrity manifest under enforcing deviation_action %q", entry.Name(), m.cfg.DeviationAction)
				return m.logIntegrityVerificationFailure("profile_missing_manifest_entry", err, "profile", entry.Name())
			}
		}

		agentKey := profile.AgentKey
		if agentKey == "" {
			// Derive from filename.
			agentKey = fileAgentKey
		}
		if m.cfg.enforces() {
			if err := validateAgentKey(agentKey); err != nil {
				err := fmt.Errorf("invalid persisted baseline profile agent key in %q under enforcing deviation_action %q: %w", entry.Name(), m.cfg.DeviationAction, err)
				return m.logIntegrityVerificationFailure("invalid_agent", err, "profile", entry.Name(), "agent_key", agentKey)
			}
			if profile.AgentKey != "" && profile.AgentKey != fileAgentKey {
				err := fmt.Errorf("persisted baseline profile %q declares agent_key %q under enforcing deviation_action %q", entry.Name(), profile.AgentKey, m.cfg.DeviationAction)
				return m.logIntegrityVerificationFailure("profile_agent_mismatch", err, "profile", entry.Name(), "agent_key", fileAgentKey, "declared_agent_key", profile.AgentKey)
			}
			if previous, ok := loadedAgents[agentKey]; ok {
				err := fmt.Errorf("duplicate persisted baseline profiles for agent %q under enforcing deviation_action %q: %s and %s", agentKey, m.cfg.DeviationAction, previous, entry.Name())
				return m.logIntegrityVerificationFailure("duplicate_agent", err, "agent_key", agentKey, "profile", entry.Name(), "previous_profile", previous)
			}
			loadedAgents[agentKey] = entry.Name()
		}

		m.agents[agentKey] = &agentState{
			profile: &profile,
			state:   profile.State,
		}
	}

	return nil
}

// Helper functions.

func collectToolIdentities(sessions []SessionMetrics) []string {
	seen := make(map[string]struct{})
	for _, session := range sessions {
		for _, identity := range session.ToolIdentities {
			identity = strings.TrimSpace(identity)
			if identity == "" {
				continue
			}
			seen[identity] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	identities := make([]string, 0, len(seen))
	for identity := range seen {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	return identities
}

func isA2AToolIdentity(identity string) bool {
	return strings.HasPrefix(identity, a2aToolIdentityPrefix)
}

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
