package emit

import (
	"os"
	"strings"
	"time"
)

// Severity represents the importance level of an audit event.
type Severity int

const (
	SeverityInfo     Severity = iota // Normal operations
	SeverityWarn                     // Suspicious activity, worth investigating
	SeverityCritical                 // Needs immediate attention
)

// String returns the lowercase string representation of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityWarn:
		return "warn"
	case SeverityCritical:
		return "critical"
	default:
		return "info"
	}
}

// ParseSeverity converts a string to a Severity level.
// The comparison is case-insensitive. Returns SeverityInfo for unrecognized values.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "warn":
		return SeverityWarn
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// Event represents a structured audit event for external emission.
type Event struct {
	Severity   Severity
	Type       string // Event type ("blocked", "kill_switch_deny", etc.)
	Timestamp  time.Time
	InstanceID string         // Pipelock instance identifier
	Fields     map[string]any // All structured fields from the audit call
}

// DefaultInstanceID returns the hostname or "pipelock" as fallback.
func DefaultInstanceID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "pipelock"
}

// EventSeverity maps audit event type strings to their severity level.
// Severity is hardcoded — users control emission threshold, not event severity.
var EventSeverity = map[string]Severity{
	// Critical: needs immediate attention
	"kill_switch_deny": SeverityCritical,
	// Note: chain_detection and adaptive_escalation severity depends on action,
	// handled by the caller via ChainDetectionSeverity / EscalationSeverity helpers.

	// Warn: suspicious, worth investigating
	"blocked":             SeverityWarn,
	"anomaly":             SeverityWarn,
	"session_anomaly":     SeverityWarn,
	"mcp_unknown_tool":    SeverityWarn,
	"ws_blocked":          SeverityWarn,
	"response_scan":       SeverityWarn,
	"ws_scan":             SeverityWarn,
	"adaptive_escalation": SeverityWarn, // default; overridden to Critical if escalating to block
	"error":               SeverityWarn, // errors are suspicious

	// Info: normal operations
	"allowed":       SeverityInfo,
	"tunnel_open":   SeverityInfo,
	"tunnel_close":  SeverityInfo,
	"ws_open":       SeverityInfo,
	"ws_close":      SeverityInfo,
	"config_reload": SeverityInfo,
	"redirect":      SeverityInfo,
	"forward_http":  SeverityInfo,
}

// ChainDetectionSeverity returns the severity for a chain detection event
// based on the action taken.
func ChainDetectionSeverity(action string) Severity {
	if action == "block" {
		return SeverityCritical
	}
	return SeverityWarn
}

// EscalationSeverity returns the severity for an adaptive escalation event.
// Escalation to "block" is critical; everything else is warn.
func EscalationSeverity(toLevel string) Severity {
	if toLevel == "block" {
		return SeverityCritical
	}
	return SeverityWarn
}
