// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"

	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	// EventDLPWarn is emitted when a warn-mode DLP pattern matches.
	// The match is informational only - no enforcement action is taken.
	EventDLPWarn EventType = "dlp_warn"
	// EventDLPCredentialAudienceAllow records the narrow compiled-in exception
	// for a provider credential sent to its declared audience.
	EventDLPCredentialAudienceAllow EventType = "dlp_credential_audience_allow" // #nosec G101 -- audit event identifier, not credential material
	EventDLPIssuerCookieAllow       EventType = "dlp_issuer_cookie_allow"       // #nosec G101 -- audit event identifier, not credential material
)

// LogDLPWarn emits an audit event for a DLP pattern match in warn mode.
// Transport identifies the scanning surface (e.g., "fetch", "forward", "mcp_input", "body").
func (l *Logger) LogDLPWarn(ctx LogContext, patternName, severity, transport string) {
	l.logDLPInformational(ctx, patternName, severity, transport, "warn", "warn")
}

// LogDLPDropped records a DLP match deliberately left unenforced by policy.
// It reuses the dlp_warn event vocabulary so existing audit and emit consumers
// can find informational DLP observations without a parallel event stream.
func (l *Logger) LogDLPDropped(ctx LogContext, patternName, severity, surface, reason string) {
	l.logDLPInformational(ctx, patternName, severity, surface, "informational", reason)
}

// LogDLPCredentialAudienceAllow records the pattern, carrier, and canonical
// upstream destination for the deliberate compiled audience exception. The
// destination has already been parsed by the proxy-owned scanner path and
// contains no credential material.
func (l *Logger) LogDLPCredentialAudienceAllow(ctx LogContext, patternName, surface, destination string) {
	l.logDLPAllowance(ctx, EventDLPCredentialAudienceAllow, patternName, surface, destination, "DLP credential allowed for declared audience")
}

// LogDLPIssuerCookieAllow records an intercepted HTTPS cookie allowance. The
// destination and pattern are bounded metadata; the cookie value is omitted.
func (l *Logger) LogDLPIssuerCookieAllow(ctx LogContext, patternName, destination string) {
	l.logDLPAllowance(ctx, EventDLPIssuerCookieAllow, patternName, "header", destination, "DLP cookie allowed for observed issuer")
}

func (l *Logger) logDLPAllowance(ctx LogContext, event EventType, patternName, surface, destination, message string) {
	technique := TechniqueForScanner(ScannerDLP)
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, ScannerDLP)

	e := newLogEntry(l.zl.Info(), event).
		str("pattern", patternName).
		str("surface", surface).
		str("destination", destination).
		str("mitre_technique", technique).
		str("method", ctx.Method()).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		optStr("client_ip", ctx.ClientIP()).
		optStr("request_id", ctx.RequestID()).
		agentField(ctx.Agent(), ctx.AgentAuth())
	e.msg(message)

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(event), e.fields)
	}
}

func (l *Logger) logDLPInformational(ctx LogContext, patternName, severity, surface, mode, reason string) {
	technique := TechniqueForScanner(ScannerDLP)
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, ScannerDLP)

	e := newLogEntry(l.zl.Warn(), EventDLPWarn).
		str("mode", mode).
		str("pattern", patternName).
		str("severity", severity).
		str("transport", surface).
		str("reason", reason).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.ScannerDLP, patternName)).
		str("mitre_technique", technique).
		str("method", ctx.Method()).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		optStr("client_ip", ctx.ClientIP()).
		optStr("request_id", ctx.RequestID()).
		agentField(ctx.Agent(), ctx.AgentAuth())
	e.msg("DLP informational match")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventDLPWarn), e.fields)
	}
}
