// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
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
	metrics        *metrics.Metrics // nil-safe; used for gauge/counter updates
	done           chan struct{}
	closed         sync.Once
}

// NewSessionManager creates a session manager with background cleanup.
// The metrics parameter is optional (nil disables gauge/counter updates).
// The adaptiveCfg parameter is optional (nil when adaptive enforcement is disabled).
func NewSessionManager(cfg *config.SessionProfiling, adaptiveCfg *config.AdaptiveEnforcement, m *metrics.Metrics) *SessionManager {
	sm := &SessionManager{
		sessions:        make(map[string]*SessionState),
		ipDomains:       make(map[string][]domainEntry),
		ipBurstCooldown: make(map[string]time.Time),
		metrics:         m,
		done:            make(chan struct{}),
	}
	sm.cfgPtr.Store(cfg)
	sm.adaptiveCfgPtr.Store(adaptiveCfg)

	go sm.cleanupLoop()
	go sm.deescalationLoop()
	return sm
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
	defer sm.mu.Unlock()

	// Double-check after acquiring write lock
	if sess, ok := sm.sessions[key]; ok {
		return sess
	}

	// Evict if at capacity
	cfg := sm.cfgPtr.Load()
	if len(sm.sessions) >= cfg.MaxSessions {
		sm.evictOldest()
	}

	now := time.Now()
	sess := &SessionState{
		key:              key,
		created:          now,
		lastActivity:     now,
		currentThreshold: 0, // set by adaptive enforcement when enabled
	}
	sm.sessions[key] = sess
	if sm.metrics != nil {
		sm.metrics.SetSessionsActive(float64(len(sm.sessions)))
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
func (sm *SessionManager) UpdateConfig(cfg *config.SessionProfiling, adaptiveCfg *config.AdaptiveEnforcement) {
	sm.cfgPtr.Store(cfg)
	sm.adaptiveCfgPtr.Store(adaptiveCfg)

	// Recompute atBlockAll for all sessions from the new adaptive config.
	// This handles three cases:
	// 1. Adaptive disabled → clear all flags
	// 2. block_all matrix changed → recompute per session level
	// 3. No change → flags stay the same (recompute is idempotent)
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
func (sm *SessionManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	cfg := sm.cfgPtr.Load()
	ttl := time.Duration(cfg.SessionTTLMinutes) * time.Minute
	cutoff := time.Now().Add(-ttl)

	evicted := 0
	for key, sess := range sm.sessions {
		sess.mu.Lock()
		idle := sess.lastActivity.Before(cutoff)
		escLevel := sess.escalationLevel
		sess.mu.Unlock()

		if idle {
			if escLevel > 0 {
				if sm.metrics != nil {
					sm.metrics.SetAdaptiveSessionLevel(session.EscalationLabel(escLevel), -1)
				}
			}
			delete(sm.sessions, key)
			evicted++
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

	if sm.metrics != nil {
		for range evicted {
			sm.metrics.RecordSessionEvicted()
		}
		sm.metrics.SetSessionsActive(float64(len(sm.sessions)))
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
		if changed {
			fromLabel := session.EscalationLabel(from)
			toLabel := session.EscalationLabel(to)
			if sm.metrics != nil {
				sm.metrics.RecordSessionAutoDeescalation(fromLabel, toLabel)
				sm.metrics.SetAdaptiveSessionLevel(fromLabel, -1)
				sm.metrics.SetAdaptiveSessionLevel(toLabel, 1)
			}
		}
	}
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
// Must be called with sm.mu held for writing.
func (sm *SessionManager) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	var oldestEscLevel int

	for key, sess := range sm.sessions {
		sess.mu.Lock()
		la := sess.lastActivity
		escLevel := sess.escalationLevel
		sess.mu.Unlock()

		if oldestKey == "" || la.Before(oldestTime) {
			oldestKey = key
			oldestTime = la
			oldestEscLevel = escLevel
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
}
