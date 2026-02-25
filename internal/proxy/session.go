package proxy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

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

	// Adaptive enforcement
	threatScore      float64
	escalationLevel  int // 0=normal, 1=first escalation, etc.
	currentThreshold float64
}

type domainEntry struct {
	domain string
	at     time.Time
}

// RecordRequest records a request and returns any anomalies detected.
// The caller must pass the current config for threshold values.
func (s *SessionState) RecordRequest(domain string, cfg *config.SessionProfiling) []Anomaly {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.lastActivity = now

	var anomalies []Anomaly

	// Domain burst detection: count unique new domains in the rolling window.
	windowCutoff := now.Add(-time.Duration(cfg.WindowMinutes) * time.Minute)
	s.domainWindows, _ = pruneDomainWindow(s.domainWindows, domain, windowCutoff, now)

	uniqueDomains := countUniqueDomains(s.domainWindows)
	if uniqueDomains >= cfg.DomainBurst {
		anomalies = append(anomalies, Anomaly{
			Type:   "domain_burst",
			Detail: fmt.Sprintf("%d new domains in %dm window (threshold: %d)", uniqueDomains, cfg.WindowMinutes, cfg.DomainBurst),
			Score:  2.0,
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

// SignalType identifies a threat signal for adaptive enforcement.
type SignalType int

const (
	SignalDLPNearMiss   SignalType = iota // +1 point
	SignalBlock                           // +3 points
	SignalDomainAnomaly                   // +2 points
)

// signalPoints maps signal types to their score contribution.
var signalPoints = map[SignalType]float64{
	SignalDLPNearMiss:   1.0,
	SignalBlock:         3.0,
	SignalDomainAnomaly: 2.0,
}

// escalationLabels maps escalation levels to human-readable names.
var escalationLabels = []string{"normal", "elevated", "high"}

// RecordSignal adds a threat signal to the session's score.
// Returns (escalated, fromLevel, toLevel) if threshold was crossed.
// Caller must hold no locks on SessionState.
func (s *SessionState) RecordSignal(sig SignalType, threshold float64) (bool, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	points := signalPoints[sig]
	s.threatScore += points

	// Initialize threshold on first use
	if s.currentThreshold == 0 && threshold > 0 {
		s.currentThreshold = threshold
	}

	if s.currentThreshold > 0 && s.threatScore >= s.currentThreshold {
		oldLevel := s.escalationLevel
		s.escalationLevel++
		// Double the threshold to prevent oscillation
		s.currentThreshold *= 2

		from := escalationLabel(oldLevel)
		to := escalationLabel(s.escalationLevel)
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

func escalationLabel(level int) string {
	if level >= 0 && level < len(escalationLabels) {
		return escalationLabels[level]
	}
	return fmt.Sprintf("level_%d", level)
}

// SessionManager manages per-client sessions with eviction and cleanup.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState

	// ipDomains tracks domain diversity per source IP, independent of agent
	// header. This catches domain burst attacks where the attacker rotates
	// the X-Pipelock-Agent header per request to create fresh sessions.
	ipDomains map[string][]domainEntry

	cfgPtr  atomic.Pointer[config.SessionProfiling]
	metrics *metrics.Metrics // nil-safe; used for gauge/counter updates
	done    chan struct{}
	closed  sync.Once
}

// NewSessionManager creates a session manager with background cleanup.
// The metrics parameter is optional (nil disables gauge/counter updates).
func NewSessionManager(cfg *config.SessionProfiling, m *metrics.Metrics) *SessionManager {
	sm := &SessionManager{
		sessions:  make(map[string]*SessionState),
		ipDomains: make(map[string][]domainEntry),
		metrics:   m,
		done:      make(chan struct{}),
	}
	sm.cfgPtr.Store(cfg)

	go sm.cleanupLoop()
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
		anomalies = append(anomalies, Anomaly{
			Type:   "ip_domain_burst",
			Detail: fmt.Sprintf("%d unique domains from IP in %dm window (threshold: %d)", uniqueDomains, cfg.WindowMinutes, cfg.DomainBurst),
			Score:  3.0, // higher than per-agent burst: indicates intentional evasion
		})
	}

	return anomalies
}

// UpdateConfig swaps the session manager's config pointer so that TTL,
// capacity, threshold, and cleanup interval changes take effect on the
// next operation.
func (sm *SessionManager) UpdateConfig(cfg *config.SessionProfiling) {
	sm.cfgPtr.Store(cfg)
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
		sess.mu.Unlock()

		if idle {
			delete(sm.sessions, key)
			evicted++
		}
	}

	// Prune IP domain entries older than the rolling window.
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

// evictOldest removes the session with the oldest lastActivity.
// Must be called with sm.mu held for writing.
func (sm *SessionManager) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, sess := range sm.sessions {
		sess.mu.Lock()
		la := sess.lastActivity
		sess.mu.Unlock()

		if oldestKey == "" || la.Before(oldestTime) {
			oldestKey = key
			oldestTime = la
		}
	}

	if oldestKey != "" {
		delete(sm.sessions, oldestKey)
		if sm.metrics != nil {
			sm.metrics.RecordSessionEvicted()
		}
	}
}
