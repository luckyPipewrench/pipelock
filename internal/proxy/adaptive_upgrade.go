package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// adaptiveUpgrade carries the inputs shared by the adaptive-enforcement audit
// log line and its matching Prometheus counter. The two emissions must always
// move together: the audit log records the per-session escalation decision and
// the counter feeds operator dashboards. Recording one without the other would
// desync the audit trail from the metrics, so they are emitted as one unit.
type adaptiveUpgrade struct {
	SessionKey string
	Level      string
	FromAction string
	ToAction   string
	Scanner    string
	ClientIP   string
	RequestID  string
}

// recordAdaptiveUpgrade emits the adaptive-upgrade audit log line and the
// matching Prometheus counter for a single enforcement upgrade. It is the one
// source of truth for that pair across every transport (fetch, forward,
// CONNECT, WebSocket, TLS intercept), so a change to the audit/metric contract
// is made in one place rather than at ~28 call sites.
//
// m may be nil: the TLS-intercept path holds its proxy-level metrics behind an
// optional proxy reference, and Metrics.RecordAdaptiveUpgrade is itself
// nil-safe, so a nil m skips the counter exactly as the prior per-site
// `if ic.Proxy != nil` guards did. logger is non-nil at every current call
// site; it is dereferenced directly to preserve the existing behavior.
func recordAdaptiveUpgrade(logger *audit.Logger, m *metrics.Metrics, u adaptiveUpgrade) {
	logger.LogAdaptiveUpgrade(u.SessionKey, u.Level, u.FromAction, u.ToAction, u.Scanner, u.ClientIP, u.RequestID)
	m.RecordAdaptiveUpgrade(u.FromAction, u.ToAction, u.Level)
}
