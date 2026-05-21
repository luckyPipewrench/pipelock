// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

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

// Severity-name string constants. Single source of truth for the lowercase
// labels exposed to users (config min_severity, OTLP severity text, etc.).
const (
	severityNameInfo     = "info"
	severityNameWarn     = "warn"
	severityNameCritical = "critical"
)

// String returns the lowercase string representation of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityWarn:
		return severityNameWarn
	case SeverityCritical:
		return severityNameCritical
	default:
		return severityNameInfo
	}
}

// ParseSeverity converts a string to a Severity level.
// The comparison is case-insensitive. Returns SeverityInfo for unrecognized values.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case severityNameWarn:
		return SeverityWarn
	case severityNameCritical:
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
	return instanceIDFallback
}

// EventAdaptiveUpgrade is the event type emitted when adaptive enforcement
// changes the action applied to a request (e.g. warn → block).
const EventAdaptiveUpgrade = "adaptive_upgrade"

// EventMediaExposure is the event type emitted when a media response
// (image/audio/video) reaches an agent through the proxy. Fires on both
// allowed and blocked paths so the taint/authority policy system can
// correlate exposure with downstream sensitive actions. Fields include
// content_type, source URL, size, and whether the response was forwarded
// or blocked.
const EventMediaExposure = "media_exposure"

// EventTextStego is the event type emitted when normalize.ZalgoSuspicious
// reports excessive combining-mark density on a scanned text response. The
// text is already neutralized by StripCombiningMarks in the scanner
// pipeline, so this event is an exposure/provenance signal, not a block
// trigger. Fields include source URL, density, and a snippet hash.
const EventTextStego = "text_stego_detected"

// actionBlock is the action string that indicates a request was blocked.
// Used internally for severity mapping — block actions map to SeverityCritical.
const actionBlock = "block"

// EventAnomaly is the event-type key for session anomaly findings (suspicious
// signal classes that warrant operator review but do not necessarily block).
const EventAnomaly = "anomaly"

// EventAdaptiveEscalation is the event-type key for adaptive enforcement
// escalations (e.g. warn → block transitions on accumulated signal).
const EventAdaptiveEscalation = "adaptive_escalation"

// Event type constants used as keys in EventSeverity. Pulled into named
// constants so the test suite and OTLP emitter can reference them by name.
const (
	EventKillSwitchDeny     = "kill_switch_deny"
	EventBlocked            = "blocked"
	EventSessionAnomaly     = "session_anomaly"
	EventMCPUnknownTool     = "mcp_unknown_tool"
	EventResponseScan       = "response_scan"
	EventError              = "error"
	EventResponseScanExempt = "response_scan_exempt"
	EventTunnelClose        = "tunnel_close"
	EventConfigReload       = "config_reload"
	EventRedirect           = "redirect"
	EventForwardHTTP        = "forward_http"
	EventToolRedirect       = "tool_redirect"
	EventWSBlocked          = "ws_blocked"
	EventWSScan             = "ws_scan"
	EventTunnelOpen         = "tunnel_open"
	EventWSOpen             = "ws_open"
	EventWSClose            = "ws_close"
)

// instanceIDFallback is the default instance identifier when hostname lookup fails.
const instanceIDFallback = "pipelock"

// networkUDP is the canonical network value for UDP transports (syslog, etc.).
const networkUDP = "udp"

// EventSeverity maps audit event type strings to their severity level.
// Severity is hardcoded — users control emission threshold, not event severity.
var EventSeverity = map[string]Severity{
	// Critical: needs immediate attention
	EventKillSwitchDeny: SeverityCritical,
	// Note: chain_detection, adaptive_escalation, and adaptive_upgrade severity
	// depends on action, handled by the caller via ChainDetectionSeverity /
	// EscalationSeverity / UpgradeSeverity helpers.

	// Warn: suspicious, worth investigating
	EventBlocked:        SeverityWarn,
	EventAnomaly:        SeverityWarn,
	EventSessionAnomaly: SeverityWarn,
	EventMCPUnknownTool: SeverityWarn,
	EventWSBlocked:      SeverityWarn,
	EventResponseScan:   SeverityWarn,
	EventWSScan:         SeverityWarn,
	// adaptive_escalation: default warn; overridden to Critical if escalating to block
	EventAdaptiveEscalation: SeverityWarn,
	// adaptive_upgrade: default warn; overridden to Critical if upgrading to block
	EventAdaptiveUpgrade: SeverityWarn,
	EventError:           SeverityWarn, // errors are suspicious

	// Warn: security-relevant operational events
	EventResponseScanExempt: SeverityWarn, // scanning was skipped; operators need visibility
	EventMediaExposure:      SeverityWarn, // media reached agent; provenance signal for taint system
	EventTextStego:          SeverityWarn, // suspicious combining-mark density; exposure signal

	// Info: normal operations
	"allowed":         SeverityInfo,
	EventTunnelOpen:   SeverityInfo,
	EventTunnelClose:  SeverityInfo,
	EventWSOpen:       SeverityInfo,
	EventWSClose:      SeverityInfo,
	EventConfigReload: SeverityInfo,
	EventRedirect:     SeverityInfo,
	EventForwardHTTP:  SeverityInfo,
	EventToolRedirect: SeverityInfo,
}

// ChainDetectionSeverity returns the severity for a chain detection event
// based on the action taken.
func ChainDetectionSeverity(action string) Severity {
	if action == actionBlock {
		return SeverityCritical
	}
	return SeverityWarn
}

// EscalationSeverity returns the severity for an adaptive escalation event.
// Escalation to "block" is critical; everything else is warn.
func EscalationSeverity(toAction string) Severity {
	if toAction == actionBlock {
		return SeverityCritical
	}
	return SeverityWarn
}

// UpgradeSeverity returns the severity for an adaptive upgrade event.
// Upgrading to "block" is critical; everything else is warn.
func UpgradeSeverity(toAction string) Severity {
	if toAction == actionBlock {
		return SeverityCritical
	}
	return SeverityWarn
}
