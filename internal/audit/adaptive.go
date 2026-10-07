// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"github.com/luckyPipewrench/pipelock/internal/emit"
	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
)

// LogSessionAnomaly logs a session behavioral anomaly detection.
func (l *Logger) LogSessionAnomaly(sessionKey, anomalyType, detail, clientIP, requestID string, score float64) {
	technique := TechniqueForScanner("session_anomaly")

	e := newLogEntry(l.zl.Warn(), EventSessionAnomaly).
		str("session", sessionKey).
		str("anomaly_type", anomalyType).
		str("detail", detail).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditSessionAnomaly, anomalyType)).
		str("client_ip", clientIP).
		str("request_id", requestID).
		scoreField(score).
		str("mitre_technique", technique)
	e.msg("session anomaly detected")

	if l.emitter != nil {
		// Emit fields: omit client_ip and request_id when empty.
		fields := map[string]any{
			"session":         e.fields["session"],
			"anomaly_type":    e.fields["anomaly_type"],
			"detail":          e.fields["detail"],
			"score":           score,
			"mitre_technique": technique,
		}
		copyRemediationHint(fields, e.fields)
		if clientIP != "" {
			fields["client_ip"] = clientIP
		}
		if requestID != "" {
			fields["request_id"] = requestID
		}
		l.emitEvent(string(EventSessionAnomaly), fields)
	}
}

// LogAdaptiveEscalation logs an enforcement level escalation.
func (l *Logger) LogAdaptiveEscalation(sessionKey, from, to, clientIP, requestID string, score float64) {
	e := newLogEntry(l.zl.Warn(), EventAdaptiveEscalation).
		str("session", sessionKey).
		str("from", from).
		str("to", to).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditAdaptiveEnforcement, to)).
		str("client_ip", clientIP).
		str("request_id", requestID).
		scoreField(score)
	e.msg("enforcement escalated")

	if l.emitter != nil {
		// Emit fields: omit client_ip and request_id when empty.
		fields := map[string]any{
			"session": e.fields["session"],
			"from":    from,
			"to":      to,
			"score":   score,
		}
		copyRemediationHint(fields, e.fields)
		if clientIP != "" {
			fields["client_ip"] = clientIP
		}
		if requestID != "" {
			fields["request_id"] = requestID
		}
		l.emitEventWithSeverity(emit.EscalationSeverity(to), string(EventAdaptiveEscalation), fields)
	}
}

// LogAdaptiveRecoveryOptions contains the fields for an adaptive recovery event.
type LogAdaptiveRecoveryOptions struct {
	SessionKey string
	Scope      string
	From       string
	To         string
	Reason     string
	ClientIP   string
	RequestID  string
}

// LogAdaptiveRecovery logs an adaptive enforcement de-escalation.
func (l *Logger) LogAdaptiveRecovery(opts LogAdaptiveRecoveryOptions) {
	e := newLogEntry(l.zl.Info(), EventAdaptiveRecovery).
		str("session", opts.SessionKey).
		optStr("scope", opts.Scope).
		str("from", opts.From).
		str("to", opts.To).
		str("reason", opts.Reason).
		optStr("client_ip", opts.ClientIP).
		optStr("request_id", opts.RequestID)
	e.msg("adaptive enforcement recovered")

	if l.emitter != nil {
		l.emitEvent(string(EventAdaptiveRecovery), e.fields)
	}
}

// LogAdaptiveUpgrade logs an adaptive enforcement action upgrade - when the
// session's escalation level causes a stronger action to be applied to a
// request than would otherwise have been (e.g. warn → block).
func (l *Logger) LogAdaptiveUpgrade(sessionKey, level, fromAction, toAction, scanner, clientIP, requestID string) {
	// Derive severity from toAction (block=critical, else warn).
	derivedSev := severityWarn
	if toAction == actionBlock {
		derivedSev = severityCritical
	}

	e := newLogEntry(l.zl.Warn(), EventAdaptiveUpgrade).
		str("session", sessionKey).
		str("escalation_level", level).
		str("from_action", fromAction).
		str("to_action", toAction).
		str("scanner", scanner).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditAdaptiveEnforcement, scanner)).
		str("client_ip", clientIP).
		str("request_id", requestID)
	e.msg("adaptive enforcement upgrade")

	if l.emitter != nil {
		sev := emit.SeverityWarn
		if toAction == actionBlock && scanner != "session_deny" {
			// Actual escalation transitions emit at critical.
			// session_deny (enforcement of existing block_all) stays at warn
			// to prevent webhook flood - one critical on escalation, not
			// one per denied request.
			sev = emit.SeverityCritical
		}
		fields := map[string]any{
			"session":          e.fields["session"],
			"escalation_level": level,
			"from_action":      fromAction,
			"to_action":        toAction,
			"scanner":          scanner,
			"severity":         derivedSev,
		}
		copyRemediationHint(fields, e.fields)
		if clientIP != "" {
			fields["client_ip"] = clientIP
		}
		if requestID != "" {
			fields["request_id"] = requestID
		}
		l.emitEventWithSeverity(sev, string(EventAdaptiveUpgrade), fields)
	}
}
