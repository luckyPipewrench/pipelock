// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"os"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/eventcatalog"
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

// FieldCorrelationID is the event field carrying the vetted value of the
// operator-configured emit.correlation_header for the originating request.
// JSON sinks emit it as fields.correlation_id, OTLP as the correlation_id log
// attribute, CEF as cs3 with cs3Label=correlationId, and OCSF as
// metadata.correlation_uid. It is absent when the feature is off or the value
// failed hygiene checks.
const FieldCorrelationID = "correlation_id"

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
const EventAdaptiveUpgrade = eventcatalog.EventAdaptiveUpgrade

// EventMediaExposure is the event type emitted when a media response
// (image/audio/video) reaches an agent through the proxy. Fires on both
// allowed and blocked paths so the taint/authority policy system can
// correlate exposure with downstream sensitive actions. Fields include
// content_type, source URL, size, and whether the response was forwarded
// or blocked.
const EventMediaExposure = eventcatalog.EventMediaExposure

// EventTextStego is the event type emitted when normalize.ZalgoSuspicious
// reports excessive combining-mark density on a scanned text response. The
// text is already neutralized by StripCombiningMarks in the scanner
// pipeline, so this event is an exposure/provenance signal, not a block
// trigger. Fields include source URL, density, and a snippet hash.
const EventTextStego = eventcatalog.EventTextStego

// EventLicenseExpiry is emitted when the active enterprise license enters a
// renewal warning band.
const EventLicenseExpiry = eventcatalog.EventLicenseExpiry

// actionBlock is the action string that indicates a request was blocked.
// Used internally for severity mapping - block actions map to SeverityCritical.
const actionBlock = "block"

// EventAnomaly is the event-type key for session anomaly findings (suspicious
// signal classes that warrant operator review but do not necessarily block).
const EventAnomaly = eventcatalog.EventAnomaly

// EventAdaptiveEscalation is the event-type key for adaptive enforcement
// escalations (e.g. warn → block transitions on accumulated signal).
const EventAdaptiveEscalation = eventcatalog.EventAdaptiveEscalation

// EventAdaptiveRecovery is the event-type key for adaptive enforcement
// de-escalations after timer-based or clean-request recovery.
const EventAdaptiveRecovery = eventcatalog.EventAdaptiveRecovery

// Event type constants used as keys in EventSeverity. Pulled into named
// constants so the test suite and OTLP emitter can reference them by name.
const (
	EventStartup                = eventcatalog.EventStartup
	EventShutdown               = eventcatalog.EventShutdown
	EventAgentListener          = eventcatalog.EventAgentListener
	EventAllowed                = eventcatalog.EventAllowed
	EventKillSwitchDeny         = eventcatalog.EventKillSwitchDeny
	EventBlocked                = eventcatalog.EventBlocked
	EventDLPWarn                = eventcatalog.EventDLPWarn
	EventAddressProtection      = eventcatalog.EventAddressProtection
	EventBodyDLP                = eventcatalog.EventBodyDLP
	EventBodyPromptInjection    = eventcatalog.EventBodyPromptInjection
	EventHeaderDLP              = eventcatalog.EventHeaderDLP
	EventSNIMismatch            = eventcatalog.EventSNIMismatch
	EventTaintDecision          = eventcatalog.EventTaintDecision
	EventAirlockEnter           = eventcatalog.EventAirlockEnter
	EventAirlockDeny            = eventcatalog.EventAirlockDeny
	EventSessionAnomaly         = eventcatalog.EventSessionAnomaly
	EventMCPUnknownTool         = eventcatalog.EventMCPUnknownTool
	EventResponseScan           = eventcatalog.EventResponseScan
	EventResponseScanSuppressed = eventcatalog.EventResponseScanSuppressed
	EventError                  = eventcatalog.EventError
	EventResponseScanExempt     = eventcatalog.EventResponseScanExempt
	EventTunnelClose            = eventcatalog.EventTunnelClose
	EventConfigReload           = eventcatalog.EventConfigReload
	EventRedirect               = eventcatalog.EventRedirect
	EventForwardHTTP            = eventcatalog.EventForwardHTTP
	EventInterceptHTTP          = eventcatalog.EventInterceptHTTP
	EventToolRedirect           = eventcatalog.EventToolRedirect
	EventWSBlocked              = eventcatalog.EventWSBlocked
	EventWSScan                 = eventcatalog.EventWSScan
	EventTunnelOpen             = eventcatalog.EventTunnelOpen
	EventWSOpen                 = eventcatalog.EventWSOpen
	EventWSClose                = eventcatalog.EventWSClose
	EventAirlockDeescalate      = eventcatalog.EventAirlockDeescalate
	EventSessionAdmin           = eventcatalog.EventSessionAdmin
	EventShieldRewrite          = eventcatalog.EventShieldRewrite
	EventRuleBundleDegraded     = eventcatalog.EventRuleBundleDegraded
	EventAuthorityVerification  = eventcatalog.EventAuthorityVerification
	// EventDashboardAuthFailed records a rejected dashboard authentication
	// attempt without including the credential itself.
	EventDashboardAuthFailed = eventcatalog.EventDashboardAuthFailed
)

// instanceIDFallback is the default instance identifier when hostname lookup fails.
const instanceIDFallback = "pipelock"

// networkUDP is the canonical network value for UDP transports (syslog, etc.).
const networkUDP = "udp"

// EventSeverity maps audit event type strings to their severity level.
// Severity is hardcoded - users control emission threshold, not event severity.
var EventSeverity = builtinEventSeverities()

func builtinEventSeverities() map[string]Severity {
	severities := make(map[string]Severity)
	for _, descriptor := range eventcatalog.Builtins() {
		if descriptor.Severity != "" {
			severities[descriptor.Name] = ParseSeverity(descriptor.Severity)
		}
	}
	return severities
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
