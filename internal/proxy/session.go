// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy/baseline"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// SessionResult is the outcome of session profiling and adaptive signal recording.
type SessionResult struct {
	Blocked bool   // session-level block (anomaly in block mode)
	Detail  string // human-readable reason
	Level   int    // current escalation level for downstream UpgradeAction()
}

// Anomaly represents a behavioral anomaly detected in a session.
type Anomaly struct {
	Type   string  // domain_burst, volume_spike
	Detail string  // human-readable description
	Score  float64 // anomaly score contribution
}

// SessionState tracks behavioral state for a single agent session.
type SessionState struct {
	mu           sync.Mutex
	key          string
	kind         string // "identity" or "invocation" — set at creation, not inferred from key
	created      time.Time
	lastActivity time.Time

	// Domain tracking (rolling window)
	domainWindows []domainEntry
	lastBurstAt   time.Time // cooldown: fire burst anomaly once per window

	// Adaptive enforcement
	threatScore      float64
	escalationLevel  int // 0=normal, 1=first escalation, etc.
	currentThreshold float64
	lastEscalation   time.Time // when the current level was reached
	atBlockAll       bool      // true when current level has block_all=true

	// Behavioral baseline accumulation — collected per-session for
	// baseline learning and deviation checking.
	requestCount int
	bytesTotal   int64
	toolCalls    int
	uniqueTools  map[string]struct{}

	// Graduated quarantine state.
	airlock AirlockState

	// Sticky taint state used for exposure-based policy escalation.
	risk session.SessionRisk
}

// IsResettable returns whether this session can be reset via the admin API.
// Only identity sessions are resettable; invocation sessions (MCP transport)
// are ephemeral and not meaningful to reset.
func (s *SessionState) IsResettable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kind == sessionKindIdentity
}

// Airlock returns a pointer to the session's airlock state for tier checks
// and transitions. The returned pointer is stable for the session's lifetime.
func (s *SessionState) Airlock() *AirlockState {
	return &s.airlock
}

type domainEntry struct {
	domain string
	at     time.Time
}

// RecordRequest records a request and returns any anomalies detected.
// The caller must pass the current config for threshold values.
// When the session is at block_all level, lastActivity is NOT refreshed
// so idle eviction can eventually clean up stuck sessions (prevents
// death spiral where blocked retries keep the session alive forever).
func (s *SessionState) RecordRequest(domain string, cfg *config.SessionProfiling) []Anomaly {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	// Don't refresh activity at block_all levels — let idle eviction work.
	// Without this, blocked retries keep the session alive forever.
	if !s.atBlockAll {
		s.lastActivity = now
	}

	// Accumulate baseline metrics.
	s.requestCount++

	var anomalies []Anomaly

	// Domain burst detection: count unique new domains in the rolling window.
	windowCutoff := now.Add(-time.Duration(cfg.WindowMinutes) * time.Minute)
	s.domainWindows, _ = pruneDomainWindow(s.domainWindows, domain, windowCutoff, now)

	uniqueDomains := countUniqueDomains(s.domainWindows)
	if uniqueDomains >= cfg.DomainBurst {
		// Score only on first detection per window. Repeat detections still
		// return the anomaly (so AnomalyAction=block fires) but with Score 0
		// to prevent adaptive escalation from repeated signals.
		windowDur := time.Duration(cfg.WindowMinutes) * time.Minute
		score := 0.0
		if s.lastBurstAt.IsZero() || now.Sub(s.lastBurstAt) >= windowDur {
			s.lastBurstAt = now
			score = 2.0
		}
		anomalies = append(anomalies, Anomaly{
			Type:   "domain_burst",
			Detail: fmt.Sprintf("%d new domains in %dm window (threshold: %d)", uniqueDomains, cfg.WindowMinutes, cfg.DomainBurst),
			Score:  score,
		})
	}

	return anomalies
}

// countUniqueDomains counts distinct domain names in the slice.
func countUniqueDomains(entries []domainEntry) int {
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		seen[e.domain] = struct{}{}
	}
	return len(seen)
}

// pruneDomainWindow removes expired entries, appends domain if not already
// present, and returns the updated slice plus the unique domain count.
// Shared by per-session RecordRequest and per-IP RecordIPDomain.
func pruneDomainWindow(entries []domainEntry, domain string, windowCutoff, now time.Time) ([]domainEntry, int) {
	pruned := entries[:0]
	for _, de := range entries {
		if de.at.After(windowCutoff) {
			pruned = append(pruned, de)
		}
	}

	seen := false
	for _, de := range pruned {
		if de.domain == domain {
			seen = true
			break
		}
	}
	if !seen {
		pruned = append(pruned, domainEntry{domain: domain, at: now})
	}

	return pruned, countUniqueDomains(pruned)
}

// maxLevelDuration is the maximum time a session stays at an escalation level
// before automatically de-escalating by one level. This prevents death spirals
// where false positives (e.g. entropy on CONNECT hostnames) permanently lock
// a session at critical. The session must accumulate new real signals to
// re-escalate.
const maxLevelDuration = 5 * time.Minute

// deescalationCheckInterval is how often the background sweep checks all
// sessions for time-based de-escalation. Runs independently of traffic so
// idle sessions recover even when no requests arrive.
const deescalationCheckInterval = 30 * time.Second

// RecordSignal adds a threat signal to the session's score.
// Returns (escalated, fromLevel, toLevel) if threshold was crossed.
// Time-based recovery is handled exclusively by TryAutoRecover, not here.
// Caller must hold no locks on SessionState.
func (s *SessionState) RecordSignal(sig session.SignalType, threshold float64) (bool, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	points := session.SignalPoints[sig]
	s.threatScore += points

	// Initialize threshold on first use
	if s.currentThreshold == 0 && threshold > 0 {
		s.currentThreshold = threshold
	}

	if s.currentThreshold > 0 && s.threatScore >= s.currentThreshold {
		oldLevel := s.escalationLevel
		s.escalationLevel++
		s.lastEscalation = time.Now()
		// Double the threshold to prevent oscillation
		s.currentThreshold *= 2

		from := session.EscalationLabel(oldLevel)
		to := session.EscalationLabel(s.escalationLevel)
		return true, from, to
	}

	return false, "", ""
}

// RecordClean decays the threat score for a clean request (no signals).
func (s *SessionState) RecordClean(decayRate float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.threatScore -= decayRate
	if s.threatScore < 0 {
		s.threatScore = 0
	}
}

// SetBlockAll sets whether the session is at a block_all escalation level.
// Called by the proxy after escalation or de-escalation when it has access
// to the adaptive enforcement config. Controls whether RecordRequest
// refreshes lastActivity (block_all must NOT refresh to allow idle eviction).
func (s *SessionState) SetBlockAll(blocked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.atBlockAll = blocked
}

// BlockAll returns whether the session is at a block_all escalation level (thread-safe).
func (s *SessionState) BlockAll() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.atBlockAll
}

// TryAutoRecover checks whether the session has been at its current
// escalation level for longer than maxLevelDuration and drops one level
// if so. It takes a blockAllCheck callback that recomputes atBlockAll
// from live config so custom configs with block_all at lower escalation
// levels work correctly. This is the sole time-based recovery path.
//
// Returns (changed, fromLevel, toLevel). The caller is responsible for
// emitting metrics/logs when changed is true.
func (s *SessionState) TryAutoRecover(blockAllCheck func(int) bool) (bool, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.escalationLevel <= 0 || s.lastEscalation.IsZero() {
		return false, 0, 0
	}
	if time.Since(s.lastEscalation) <= maxLevelDuration {
		return false, 0, 0
	}

	from := s.escalationLevel
	s.escalationLevel--
	s.lastEscalation = time.Now()

	if s.currentThreshold > 0 {
		s.currentThreshold /= 2
	}
	s.threatScore = s.currentThreshold / 2
	s.atBlockAll = blockAllCheck(s.escalationLevel)

	return true, from, s.escalationLevel
}

// ThreatScore returns the current threat score (thread-safe).
func (s *SessionState) ThreatScore() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.threatScore
}

// IsEscalated returns whether this session has been escalated.
func (s *SessionState) IsEscalated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.escalationLevel > 0
}

// EscalationLevel returns the current escalation level (thread-safe).
func (s *SessionState) EscalationLevel() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.escalationLevel
}

// Reset zeros all enforcement fields in place and refreshes lastActivity.
// The session remains in the map so live Recorder pointers stay valid.
// Returns previous score and level for the API response.
func (s *SessionState) Reset() (prevScore float64, prevLevel int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevScore = s.threatScore
	prevLevel = s.escalationLevel

	s.threatScore = 0
	s.escalationLevel = 0
	s.currentThreshold = 0
	s.lastEscalation = time.Time{}
	s.atBlockAll = false
	s.domainWindows = nil
	s.lastBurstAt = time.Time{}
	s.lastActivity = time.Now()
	s.requestCount = 0
	s.bytesTotal = 0
	s.toolCalls = 0
	s.uniqueTools = nil

	// Reset airlock to none tier. Direct field access is safe because
	// we hold s.mu and SetTier only allows upward transitions.
	s.airlock.mu.Lock()
	s.airlock.tier = config.AirlockTierNone
	s.airlock.enteredAt = time.Time{}
	s.airlock.callCancelFuncsLocked()
	s.airlock.mu.Unlock()

	return prevScore, prevLevel
}

// RiskSnapshot returns a copy of the session taint state.
func (s *SessionState) RiskSnapshot() session.SessionRisk {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.risk.Snapshot()
}

// ObserveRisk folds a new taint observation into the session's sticky risk state.
func (s *SessionState) ObserveRisk(observation session.RiskObservation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.risk.Observe(observation)
}

// RecordBytes adds to the session's cumulative byte count.
// Called by transport handlers after completing a request.
func (s *SessionState) RecordBytes(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytesTotal += n
}

// RecordToolCall increments the session's tool call counter and tracks
// unique tool names. Called by MCP proxy when a tool invocation completes.
func (s *SessionState) RecordToolCall(toolName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.toolCalls++
	if s.uniqueTools == nil {
		s.uniqueTools = make(map[string]struct{})
	}
	s.uniqueTools[toolName] = struct{}{}
}

// BaselineMetrics returns a snapshot of the session's accumulated metrics
// suitable for passing to baseline.Manager.RecordSession or Check.
func (s *SessionState) BaselineMetrics() baseline.SessionMetrics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return baseline.SessionMetrics{
		ToolCalls:   s.toolCalls,
		UniqueTools: len(s.uniqueTools),
		Domains:     countUniqueDomains(s.domainWindows),
		BytesTotal:  s.bytesTotal,
		DurationSec: s.lastActivity.Sub(s.created).Seconds(),
		Requests:    s.requestCount,
	}
}

// Session key classification constants.
const (
	sessionKindIdentity   = "identity"
	sessionKindInvocation = "invocation"
)

// invocationPrefixes lists MCP transport prefixes that identify invocation keys.
var invocationPrefixes = []string{"mcp-stdio-", "mcp-http-", "mcp-ws-"}

// SessionSnapshot is a read-only DTO for the admin API.
type SessionSnapshot struct {
	Key             string    `json:"key"`
	Agent           string    `json:"agent"`
	ClientIP        string    `json:"client_ip"`
	Kind            string    `json:"kind"`
	ThreatScore     float64   `json:"threat_score"`
	EscalationLevel string    `json:"escalation_level"`
	BlockAll        bool      `json:"block_all"`
	AirlockTier     string    `json:"airlock_tier"`
	TaintLevel      string    `json:"taint_level"`
	Contaminated    bool      `json:"contaminated"`
	LastActivity    time.Time `json:"last_activity"`
}

// classifySessionKey determines whether a key is an identity key or an
// MCP invocation key, and extracts agent/IP for identity keys.
func classifySessionKey(key string) (kind, agent, clientIP string) {
	for _, prefix := range invocationPrefixes {
		if strings.HasPrefix(key, prefix) {
			return sessionKindInvocation, "", ""
		}
	}
	if idx := strings.LastIndex(key, "|"); idx > 0 {
		return sessionKindIdentity, key[:idx], key[idx+1:]
	}
	return sessionKindIdentity, "", key
}

// BaselineResult holds the outcome of a behavioral baseline deviation check.
type BaselineResult struct {
	Blocked    bool                 // true when DeviationAction is "block" and deviations found
	Deviations []baseline.Deviation // specific metrics that deviated
	Action     string               // the configured action: "warn", "ask", or "block"
}

// SessionManager manages per-client sessions with eviction and cleanup.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState

	// ipDomains tracks domain diversity per source IP, independent of agent
	// header. This catches domain burst attacks where the attacker rotates
	// the X-Pipelock-Agent header per request to create fresh sessions.
	ipDomains       map[string][]domainEntry
	ipBurstCooldown map[string]time.Time // per-IP burst cooldown timestamps

	cfgPtr         atomic.Pointer[config.SessionProfiling]
	adaptiveCfgPtr atomic.Pointer[config.AdaptiveEnforcement]
	airlockCfgPtr  atomic.Pointer[config.Airlock]
	metrics        *metrics.Metrics // nil-safe; used for gauge/counter updates
	logger         *audit.Logger    // nil-safe; used for airlock de-escalation logging
	done           chan struct{}
	closed         sync.Once

	// Behavioral baseline: profile-then-lock analysis.
	// nil when behavioral_baseline.enabled is false.
	baselineMgr    *baseline.Manager
	baselineAction string // "warn", "ask", or "block" — cached from config
}

// SessionManagerOptions configures optional SessionManager behavior.
type SessionManagerOptions struct {
	AirlockCfg *config.Airlock
	Logger     *audit.Logger
}

// NewSessionManager creates a session manager with background cleanup.
// The metrics parameter is optional (nil disables gauge/counter updates).
// The adaptiveCfg parameter is optional (nil when adaptive enforcement is disabled).
func NewSessionManager(cfg *config.SessionProfiling, adaptiveCfg *config.AdaptiveEnforcement, m *metrics.Metrics, opts ...SessionManagerOptions) *SessionManager {
	sm := &SessionManager{
		sessions:        make(map[string]*SessionState),
		ipDomains:       make(map[string][]domainEntry),
		ipBurstCooldown: make(map[string]time.Time),
		metrics:         m,
		done:            make(chan struct{}),
	}
	sm.cfgPtr.Store(cfg)
	sm.adaptiveCfgPtr.Store(adaptiveCfg)
	if len(opts) > 0 {
		if opts[0].AirlockCfg != nil {
			sm.airlockCfgPtr.Store(opts[0].AirlockCfg)
		}
		sm.logger = opts[0].Logger
	}

	go sm.cleanupLoop()
	go sm.deescalationLoop()
	return sm
}

// EnableBaseline initializes the behavioral baseline manager from config.
// Must be called after NewSessionManager. No-op if cfg is nil or not enabled.
// Returns an error if the baseline manager fails to initialize (e.g., bad
// profile directory).
func (sm *SessionManager) EnableBaseline(cfg *config.BehavioralBaseline) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	mgr, err := baseline.NewManager(baseline.Config{
		Enabled:          cfg.Enabled,
		LearningWindow:   cfg.LearningWindow,
		DeviationAction:  cfg.DeviationAction,
		ProfileDir:       cfg.ProfileDir,
		AutoRatify:       cfg.AutoRatify,
		SensitivitySigma: cfg.SensitivitySigma,
		LockDimensions:   cfg.LockDimensions,
		PoisonResistance: cfg.PoisonResistance,
		SeasonalityMode:  cfg.SeasonalityMode,
	})
	if err != nil {
		return fmt.Errorf("baseline init: %w", err)
	}
	sm.baselineMgr = mgr
	sm.baselineAction = cfg.DeviationAction
	return nil
}

// BaselineManager returns the baseline manager, or nil if not enabled.
func (sm *SessionManager) BaselineManager() *baseline.Manager {
	return sm.baselineMgr
}

// CheckBaseline evaluates the current session metrics against the agent's
// locked behavioral profile. Returns nil result when baseline is disabled
// or the agent has no locked profile yet (still learning).
func (sm *SessionManager) CheckBaseline(agentKey string, sess *SessionState) *BaselineResult {
	if sm.baselineMgr == nil {
		return nil
	}
	metrics := sess.BaselineMetrics()
	deviations := sm.baselineMgr.Check(agentKey, metrics)
	if len(deviations) == 0 {
		return nil
	}
	return &BaselineResult{
		Blocked:    sm.baselineAction == config.ActionBlock,
		Deviations: deviations,
		Action:     sm.baselineAction,
	}
}

// recordSessionBaseline records the session's accumulated metrics into the
// baseline manager for learning. Called during session eviction/cleanup.
func (sm *SessionManager) recordSessionBaseline(sess *SessionState) {
	if sm.baselineMgr == nil {
		return
	}
	// Extract agent key from session key. Only identity sessions produce
	// meaningful baselines; invocation sessions are ephemeral.
	sess.mu.Lock()
	kind := sess.kind
	key := sess.key
	sess.mu.Unlock()

	if kind != sessionKindIdentity {
		return
	}

	_, agent, _ := classifySessionKey(key)
	if agent == "" {
		// Fall back to full key when no "|" separator exists.
		agent = key
	}
	bm := sess.BaselineMetrics()
	sm.baselineMgr.RecordSession(agent, bm)
}

// GetOrCreate returns the session for a key, creating if needed.
// Evicts oldest idle session if at capacity.
func (sm *SessionManager) GetOrCreate(key string) *SessionState {
	// Fast path: read lock
	sm.mu.RLock()
	if sess, ok := sm.sessions[key]; ok {
		sm.mu.RUnlock()
		return sess
	}
	sm.mu.RUnlock()

	// Slow path: write lock
	sm.mu.Lock()

	// Double-check after acquiring write lock
	if sess, ok := sm.sessions[key]; ok {
		sm.mu.Unlock()
		return sess
	}

	// Evict if at capacity. Capture the evicted session for baseline
	// recording after the lock is released.
	var evicted *SessionState
	cfg := sm.cfgPtr.Load()
	if len(sm.sessions) >= cfg.MaxSessions {
		evicted = sm.evictOldest()
	}

	// Determine session kind from key format at creation time.
	kind := sessionKindIdentity
	for _, prefix := range invocationPrefixes {
		if strings.HasPrefix(key, prefix) {
			kind = sessionKindInvocation
			break
		}
	}

	now := time.Now()
	sess := &SessionState{
		key:              key,
		kind:             kind,
		created:          now,
		lastActivity:     now,
		currentThreshold: 0, // set by adaptive enforcement when enabled
		airlock:          AirlockState{tier: config.AirlockTierNone},
	}
	sm.sessions[key] = sess
	if sm.metrics != nil {
		sm.metrics.SetSessionsActive(float64(len(sm.sessions)))
	}
	sm.mu.Unlock()

	// Record evicted session's baseline after releasing the map lock.
	if evicted != nil {
		sm.recordSessionBaseline(evicted)
	}

	return sess
}

// Len returns the number of active sessions.
func (sm *SessionManager) Len() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// RecordIPDomain checks domain diversity across all agent identities from the
// same source IP. This catches header rotation attacks where an attacker sends
// each request with a different X-Pipelock-Agent value to avoid per-session
// domain burst detection. Returns anomalies when the IP crosses the burst
// threshold regardless of which agent identity was used.
func (sm *SessionManager) RecordIPDomain(clientIP, domain string, cfg *config.SessionProfiling) []Anomaly {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	windowCutoff := now.Add(-time.Duration(cfg.WindowMinutes) * time.Minute)

	pruned, uniqueDomains := pruneDomainWindow(sm.ipDomains[clientIP], domain, windowCutoff, now)
	sm.ipDomains[clientIP] = pruned

	var anomalies []Anomaly
	if uniqueDomains >= cfg.DomainBurst {
		// Same cooldown pattern as per-session burst: score once per window,
		// anomaly returned every time so AnomalyAction=block still fires.
		windowDur := time.Duration(cfg.WindowMinutes) * time.Minute
		lastBurst := sm.ipBurstCooldown[clientIP]
		score := 0.0
		if lastBurst.IsZero() || now.Sub(lastBurst) >= windowDur {
			sm.ipBurstCooldown[clientIP] = now
			score = 3.0
		}
		anomalies = append(anomalies, Anomaly{
			Type:   "ip_domain_burst",
			Detail: fmt.Sprintf("%d unique domains from IP in %dm window (threshold: %d)", uniqueDomains, cfg.WindowMinutes, cfg.DomainBurst),
			Score:  score,
		})
	}

	return anomalies
}

// UpdateConfig swaps the session manager's config pointer so that TTL,
// capacity, threshold, and cleanup interval changes take effect on the
// next operation. Pass nil for adaptiveCfg to clear adaptive enforcement
// (e.g., when it is disabled via hot reload).
func (sm *SessionManager) UpdateConfig(cfg *config.SessionProfiling, adaptiveCfg *config.AdaptiveEnforcement, airlockCfg *config.Airlock) {
	sm.cfgPtr.Store(cfg)
	sm.adaptiveCfgPtr.Store(adaptiveCfg)
	sm.airlockCfgPtr.Store(airlockCfg)

	// Recompute atBlockAll for all sessions from the new adaptive config.
	// This handles three cases:
	// - Adaptive disabled → clear all flags
	// - block_all matrix changed → recompute per session level
	// - No change → flags stay the same (recompute is idempotent)
	sm.mu.RLock()
	for _, sess := range sm.sessions {
		if adaptiveCfg == nil || !adaptiveCfg.Enabled {
			sess.SetBlockAll(false)
		} else {
			level := sess.EscalationLevel()
			isBlockAll := decide.UpgradeAction("", level, adaptiveCfg) == config.ActionBlock
			sess.SetBlockAll(isBlockAll)
		}
	}
	sm.mu.RUnlock()
}

// Close stops the cleanup goroutine.
func (sm *SessionManager) Close() {
	sm.closed.Do(func() {
		close(sm.done)
	})
}

// Snapshot returns a sorted read-only snapshot of all sessions.
// Identity sessions sort first (by key), then invocation sessions (by key).
// Copies session pointers under RLock then releases it before reading each
// session's state, so the manager-level lock is held only briefly.
func (sm *SessionManager) Snapshot() []SessionSnapshot {
	sm.mu.RLock()
	keys := make([]string, 0, len(sm.sessions))
	sessions := make([]*SessionState, 0, len(sm.sessions))
	for k, s := range sm.sessions {
		keys = append(keys, k)
		sessions = append(sessions, s)
	}
	sm.mu.RUnlock()

	snaps := make([]SessionSnapshot, len(sessions))
	for i, s := range sessions {
		s.mu.Lock()
		kind, agent, ip := classifySessionKey(keys[i])
		snaps[i] = SessionSnapshot{
			Key:             keys[i],
			Agent:           agent,
			ClientIP:        ip,
			Kind:            kind,
			ThreatScore:     s.threatScore,
			EscalationLevel: session.EscalationLabel(s.escalationLevel),
			BlockAll:        s.atBlockAll,
			AirlockTier:     s.airlock.Tier(),
			TaintLevel:      s.risk.Level.String(),
			Contaminated:    s.risk.Contaminated,
			LastActivity:    s.lastActivity,
		}
		s.mu.Unlock()
	}

	sort.Slice(snaps, func(i, j int) bool {
		if snaps[i].Kind != snaps[j].Kind {
			return snaps[i].Kind < snaps[j].Kind // "identity" < "invocation"
		}
		return snaps[i].Key < snaps[j].Key
	})
	return snaps
}

// SessionExists returns whether the given key has an active session.
// Uses a read lock for minimal contention on the hot path.
func (sm *SessionManager) SessionExists(key string) bool {
	sm.mu.RLock()
	_, ok := sm.sessions[key]
	sm.mu.RUnlock()
	return ok
}

// ResetSession resets enforcement state for the given identity key.
// Also clears IP-level burst state for the client IP and decrements
// the adaptive gauge if the session was escalated.
// Does NOT check session kind — caller is responsible for ensuring the key
// belongs to a resettable session. Prefer ResetSessionIfResettable for the
// admin API, which atomically checks kind + resets under a single lock.
// Returns a snapshot of the previous state and whether the key was found.
func (sm *SessionManager) ResetSession(key string) (prev SessionSnapshot, found bool) {
	_, agent, ip := classifySessionKey(key)

	sm.mu.Lock()
	sess, ok := sm.sessions[key]
	if !ok {
		sm.mu.Unlock()
		return SessionSnapshot{}, false
	}

	// Clear IP-level state (shared across all identities on this IP).
	if ip != "" {
		delete(sm.ipDomains, ip)
		delete(sm.ipBurstCooldown, ip)
	}

	// Reset session in place while still holding sm.mu to prevent an
	// eviction race between lock release and Reset.
	prevScore, prevLevel := sess.Reset()
	sm.mu.Unlock()

	// Decrement adaptive gauge if session was escalated (lock-free prometheus op).
	if prevLevel > 0 && sm.metrics != nil {
		sm.metrics.SetAdaptiveSessionLevel(session.EscalationLabel(prevLevel), -1)
	}

	prev = SessionSnapshot{
		Key:             key,
		Agent:           agent,
		ClientIP:        ip,
		Kind:            sessionKindIdentity,
		ThreatScore:     prevScore,
		EscalationLevel: session.EscalationLabel(prevLevel),
		BlockAll:        false,
		TaintLevel:      sess.RiskSnapshot().Level.String(),
		Contaminated:    sess.RiskSnapshot().Contaminated,
		LastActivity:    time.Now(),
	}
	return prev, true
}

// ErrInvocationReset is returned when a caller attempts to reset an
// invocation (MCP transport) session, which is ephemeral and not meaningful
// to reset.
var ErrInvocationReset = errors.New("cannot reset invocation session")

// ResetSessionIfResettable atomically looks up a session, verifies it is an
// identity session (not invocation), and resets it under a single sm.mu.Lock.
// This eliminates the TOCTOU race where a session could be evicted or replaced
// between a separate lookup and reset.
//
// Returns:
//   - found=false, err=nil: session does not exist
//   - found=true, err=ErrInvocationReset: session exists but is not resettable
//   - found=true, err=nil: reset succeeded, prev contains the previous state
func (sm *SessionManager) ResetSessionIfResettable(key string) (prev SessionSnapshot, found bool, err error) {
	_, agent, ip := classifySessionKey(key)

	sm.mu.Lock()
	sess, ok := sm.sessions[key]
	if !ok {
		sm.mu.Unlock()
		return SessionSnapshot{}, false, nil
	}

	// Check kind under sm.mu to prevent TOCTOU with eviction/replacement.
	sess.mu.Lock()
	kind := sess.kind
	sess.mu.Unlock()

	if kind != sessionKindIdentity {
		sm.mu.Unlock()
		return SessionSnapshot{Key: key, Kind: kind}, true, ErrInvocationReset
	}

	// Clear IP-level state (shared across all identities on this IP).
	if ip != "" {
		delete(sm.ipDomains, ip)
		delete(sm.ipBurstCooldown, ip)
	}

	// Reset session in place while still holding sm.mu to prevent an
	// eviction race between lock release and Reset.
	prevScore, prevLevel := sess.Reset()
	sm.mu.Unlock()

	// Decrement adaptive gauge if session was escalated (lock-free prometheus op).
	if prevLevel > 0 && sm.metrics != nil {
		sm.metrics.SetAdaptiveSessionLevel(session.EscalationLabel(prevLevel), -1)
	}

	prev = SessionSnapshot{
		Key:             key,
		Agent:           agent,
		ClientIP:        ip,
		Kind:            sessionKindIdentity,
		ThreatScore:     prevScore,
		EscalationLevel: session.EscalationLabel(prevLevel),
		BlockAll:        false,
		TaintLevel:      sess.RiskSnapshot().Level.String(),
		Contaminated:    sess.RiskSnapshot().Contaminated,
		LastActivity:    time.Now(),
	}
	return prev, true, nil
}

// ForceSetAirlockTier atomically looks up a session by key and sets the
// airlock tier under sm.mu.RLock. This eliminates the TOCTOU race where a
// session could be evicted between a separate lookup and ForceSetTier call.
// Returns (found, changed, from, to).
func (sm *SessionManager) ForceSetAirlockTier(key, tier string) (found, changed bool, from, to string) {
	sm.mu.RLock()
	sess, exists := sm.sessions[key]
	if !exists {
		sm.mu.RUnlock()
		return false, false, "", ""
	}
	// Hold RLock across the tier change so cleanup/eviction can't remove
	// the session between lookup and mutation. ForceSetTier acquires its
	// own mutex internally (lock ordering: sm.mu > airlock.mu).
	changed, from, to = sess.Airlock().ForceSetTier(tier)
	sm.mu.RUnlock()
	return true, changed, from, to
}

// cleanupLoop runs periodic cleanup of expired sessions.
// Uses a timer (not ticker) so that cleanup_interval_seconds changes
// from UpdateConfig take effect on the next iteration.
func (sm *SessionManager) cleanupLoop() {
	interval := time.Duration(sm.cfgPtr.Load().CleanupIntervalSeconds) * time.Second
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-sm.done:
			return
		case <-timer.C:
			sm.cleanup()
			interval = time.Duration(sm.cfgPtr.Load().CleanupIntervalSeconds) * time.Second
			timer.Reset(interval)
		}
	}
}

// cleanup removes sessions idle beyond TTL and prunes stale IP domain entries.
// Evicted sessions are recorded in the behavioral baseline (if enabled) after
// the map lock is released to avoid holding sm.mu during baseline I/O.
func (sm *SessionManager) cleanup() {
	cfg := sm.cfgPtr.Load()
	ttl := time.Duration(cfg.SessionTTLMinutes) * time.Minute
	cutoff := time.Now().Add(-ttl)

	// Phase 1: identify and remove expired sessions under lock.
	var evictedSessions []*SessionState

	sm.mu.Lock()
	for key, sess := range sm.sessions {
		sess.mu.Lock()
		idle := sess.lastActivity.Before(cutoff)
		escLevel := sess.escalationLevel
		airlockTier := sess.airlock.Tier()
		sess.mu.Unlock()

		// Airlock sessions are exempt from idle eviction. A session in
		// quarantine must not be evicted or it would escape enforcement.
		// Empty string is the zero value (equivalent to "none").
		if airlockTier != config.AirlockTierNone && airlockTier != "" {
			continue
		}

		if idle {
			if escLevel > 0 {
				if sm.metrics != nil {
					sm.metrics.SetAdaptiveSessionLevel(session.EscalationLabel(escLevel), -1)
				}
			}
			evictedSessions = append(evictedSessions, sess)
			delete(sm.sessions, key)
		}
	}

	// Prune IP domain entries and burst cooldowns older than the rolling window.
	windowCutoff := time.Now().Add(-time.Duration(cfg.WindowMinutes) * time.Minute)
	for ip, entries := range sm.ipDomains {
		pruned := entries[:0]
		for _, de := range entries {
			if de.at.After(windowCutoff) {
				pruned = append(pruned, de)
			}
		}
		if len(pruned) == 0 {
			delete(sm.ipDomains, ip)
			delete(sm.ipBurstCooldown, ip)
		} else {
			sm.ipDomains[ip] = pruned
		}
	}

	evicted := len(evictedSessions)
	if sm.metrics != nil {
		for range evicted {
			sm.metrics.RecordSessionEvicted()
		}
		sm.metrics.SetSessionsActive(float64(len(sm.sessions)))
	}
	sm.mu.Unlock()

	// Phase 2: record evicted sessions in baseline (lock-free path).
	for _, sess := range evictedSessions {
		sm.recordSessionBaseline(sess)
	}
}

// deescalationLoop runs periodic de-escalation checks on all sessions.
// Unlike cleanupLoop, this uses a fixed interval (not config-driven)
// because recovery timing is a security property, not a tuning knob.
func (sm *SessionManager) deescalationLoop() {
	ticker := time.NewTicker(deescalationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.done:
			return
		case <-ticker.C:
			sm.sweepDeescalation()
		}
	}
}

// sweepDeescalation checks all sessions for time-based de-escalation.
// This is the primary recovery mechanism for the deny-spiral bug: it runs
// independently of traffic so idle sessions recover even with no requests.
func (sm *SessionManager) sweepDeescalation() {
	adaptiveCfg := sm.adaptiveCfgPtr.Load()
	if adaptiveCfg == nil || !adaptiveCfg.Enabled {
		return
	}

	blockAllCheck := func(level int) bool {
		return decide.UpgradeAction("", level, adaptiveCfg) == config.ActionBlock
	}

	sm.mu.RLock()
	sessions := make([]*SessionState, 0, len(sm.sessions))
	for _, sess := range sm.sessions {
		sessions = append(sessions, sess)
	}
	sm.mu.RUnlock()

	for _, sess := range sessions {
		changed, from, to := sess.TryAutoRecover(blockAllCheck)
		if changed && sm.metrics != nil {
			fromLabel := session.EscalationLabel(from)
			toLabel := session.EscalationLabel(to)
			// Only emit gauge updates if the session is still live in the map.
			// Cleanup may have evicted and already decremented its gauge.
			sm.mu.RLock()
			_, stillLive := sm.sessions[sess.key]
			sm.mu.RUnlock()
			if stillLive {
				sm.metrics.RecordSessionAutoDeescalation(fromLabel, toLabel)
				if from > 0 {
					sm.metrics.SetAdaptiveSessionLevel(fromLabel, -1)
				}
				if to > 0 {
					sm.metrics.SetAdaptiveSessionLevel(toLabel, 1)
				}
			}
		}

		// Airlock timer-based de-escalation.
		if airlockCfg := sm.airlockCfgPtr.Load(); airlockCfg != nil && airlockCfg.Enabled {
			airlockChanged, airlockFrom, airlockTo := sess.airlock.TryDeescalate(&airlockCfg.Timers)
			if airlockChanged {
				if sm.metrics != nil {
					sm.metrics.RecordAirlockTransition(airlockFrom, airlockTo, "timer")
				}
				if sm.logger != nil {
					sm.logger.LogAirlockDeescalate(sess.key, airlockFrom, airlockTo, "", "")
				}
			}
		}
	}
}

// trySessionRecovery attempts time-based de-escalation on a session and emits
// metrics if recovery fires. Returns (changed, fromLabel, toLabel) for callers
// that need to log the transition. No-op when adaptive enforcement is disabled,
// the session is nil, or the session is not a *SessionState.
func trySessionRecovery(rec session.Recorder, adaptiveCfg *config.AdaptiveEnforcement, m *metrics.Metrics) (bool, string, string) {
	if adaptiveCfg == nil || !adaptiveCfg.Enabled {
		return false, "", ""
	}
	ss, ok := rec.(*SessionState)
	if !ok || ss == nil {
		return false, "", ""
	}
	blockAllCheck := func(level int) bool {
		return decide.UpgradeAction("", level, adaptiveCfg) == config.ActionBlock
	}
	changed, from, to := ss.TryAutoRecover(blockAllCheck)
	if !changed {
		return false, "", ""
	}
	fromLabel := session.EscalationLabel(from)
	toLabel := session.EscalationLabel(to)
	if m != nil {
		m.RecordSessionAutoDeescalation(fromLabel, toLabel)
		if from > 0 {
			m.SetAdaptiveSessionLevel(fromLabel, -1)
		}
		if to > 0 {
			m.SetAdaptiveSessionLevel(toLabel, 1)
		}
	}
	return true, fromLabel, toLabel
}

// storeAdapter wraps SessionManager to implement session.Store.
// SessionState already satisfies session.Recorder via its RecordSignal,
// RecordClean, EscalationLevel, and ThreatScore methods.
type storeAdapter struct {
	sm *SessionManager
}

func (a *storeAdapter) GetOrCreate(key string) session.Recorder {
	return a.sm.GetOrCreate(key)
}

// AsStore returns a session.Store interface for this SessionManager.
func (sm *SessionManager) AsStore() session.Store {
	return &storeAdapter{sm: sm}
}

// evictOldest removes the session with the oldest lastActivity.
// Must be called with sm.mu held for writing. Returns the evicted
// session (if any) so the caller can record baseline metrics after
// releasing the lock.
func (sm *SessionManager) evictOldest() *SessionState {
	var oldestKey string
	var oldestTime time.Time
	var oldestSess *SessionState

	var oldestEscLevel int

	for key, sess := range sm.sessions {
		sess.mu.Lock()
		la := sess.lastActivity
		escLevel := sess.escalationLevel
		airlockTier := sess.airlock.Tier()
		sess.mu.Unlock()

		// Skip quarantined sessions: evicting them would escape enforcement.
		if airlockTier != config.AirlockTierNone && airlockTier != "" {
			continue
		}

		if oldestKey == "" || la.Before(oldestTime) {
			oldestKey = key
			oldestTime = la
			oldestEscLevel = escLevel
			oldestSess = sess
		}
	}

	if oldestKey != "" {
		if oldestEscLevel > 0 {
			if sm.metrics != nil {
				sm.metrics.SetAdaptiveSessionLevel(session.EscalationLabel(oldestEscLevel), -1)
			}
		}
		delete(sm.sessions, oldestKey)
		if sm.metrics != nil {
			sm.metrics.RecordSessionEvicted()
		}
	}
	return oldestSess
}
