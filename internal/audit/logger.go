// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package audit provides structured JSON audit logging for all Pipelock events.
package audit

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/rs/zerolog"
)

// sanitizeString strips control characters and ANSI escape sequences from a
// string before logging. Prevents terminal escape injection via crafted URLs
// (e.g., \x1b[2J to clear screen when tailing audit logs).
func sanitizeString(s string) string {
	// Fast path: most strings have no control characters.
	clean := true
	for _, r := range s {
		if r != '\t' && r != '\n' && (unicode.IsControl(r) || r == '\x1b') {
			clean = false
			break
		}
	}
	if clean {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	inEscape := false
	for _, r := range s {
		if inEscape {
			// ANSI escape sequences end with a letter (A-Z, a-z).
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		if r == '\x1b' {
			inEscape = true
			continue
		}
		// Allow tabs and newlines but strip other control chars.
		if r != '\t' && r != '\n' && unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// EventType describes the kind of audit event.
type EventType string

// Event type constants for structured audit log entries.
const (
	EventAllowed            EventType = "allowed"
	EventBlocked            EventType = "blocked"
	EventError              EventType = "error"
	EventAnomaly            EventType = "anomaly"
	EventResponseScan       EventType = "response_scan"
	EventRedirect           EventType = "redirect"
	EventTunnelOpen         EventType = "tunnel_open"
	EventTunnelClose        EventType = "tunnel_close"
	EventForwardHTTP        EventType = "forward_http"
	EventConfigReload       EventType = "config_reload"
	EventWSOpen             EventType = "ws_open"
	EventWSClose            EventType = "ws_close"
	EventWSBlocked          EventType = "ws_blocked"
	EventWSScan             EventType = "ws_scan"
	EventSessionAnomaly     EventType = "session_anomaly"
	EventAdaptiveEscalation EventType = "adaptive_escalation"
	EventMCPUnknownTool     EventType = "mcp_unknown_tool"
	EventKillSwitchDeny     EventType = "kill_switch_deny"
	EventSNIMismatch        EventType = "sni_mismatch"
	EventBodyDLP            EventType = "body_dlp"
	EventHeaderDLP          EventType = "header_dlp"
	EventChainDetection     EventType = "chain_detection"
	EventAddressProtection  EventType = "address_protection"
	EventAgentListener      EventType = "agent_listener"
	EventFileSentryDLP      EventType = "file_sentry_dlp"

	EventCrossRequestEntropyExceeded EventType = "cross_request_entropy_exceeded"
	EventCrossRequestDLPMatch        EventType = "cross_request_dlp_match"
	EventCrossRequestEntropyAnomaly  EventType = "cross_request_entropy_anomaly"

	EventAdaptiveUpgrade EventType = "adaptive_upgrade"
	EventToolRedirect    EventType = "tool_redirect"
)

// WebSocket frame direction constants used in audit log entries.
const (
	DirectionClientToServer = "client_to_server"
	DirectionServerToClient = "server_to_client"
)

// Scanner label for DLP audit events (used in technique mapping).
const ScannerDLP = "dlp"

// actionBlock mirrors config.ActionBlock without importing the config package
// (which would create a dependency cycle). Used for emit severity mapping.
const actionBlock = "block"

// Severity constants mirroring config.Severity* to avoid a dependency cycle.
const (
	severityCritical = "critical"
	severityWarn     = "warn"
)

// BundleRuleHit records which community bundle rule triggered a detection.
// Included in audit events and webhook payloads when bundle rules match.
type BundleRuleHit struct {
	RuleID        string `json:"rule_id"`
	Bundle        string `json:"bundle"`
	BundleVersion string `json:"bundle_version"`
}

// Logger handles structured audit logging using zerolog.
type Logger struct {
	zl             zerolog.Logger
	includeAllowed bool
	includeBlocked bool
	fileHandle     *os.File      // non-nil if logging to file
	emitter        *emit.Emitter // optional external event emitter
}

// New creates a new audit logger. The caller should call Close when done.
func New(format, output, filePath string, includeAllowed, includeBlocked bool) (*Logger, error) {
	var writers []io.Writer

	if output == "stdout" || output == "both" {
		if format == "text" {
			writers = append(writers, zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
		} else {
			writers = append(writers, os.Stdout)
		}
	}

	var fileHandle *os.File
	if output == "file" || output == "both" {
		f, err := os.OpenFile(filepath.Clean(filePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		writers = append(writers, f)
		fileHandle = f
	}

	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	var w io.Writer
	if len(writers) == 1 {
		w = writers[0]
	} else {
		w = zerolog.MultiLevelWriter(writers...)
	}

	zl := zerolog.New(w).With().
		Timestamp().
		Str("component", "pipelock").
		Logger()

	return &Logger{
		zl:             zl,
		includeAllowed: includeAllowed,
		includeBlocked: includeBlocked,
		fileHandle:     fileHandle,
	}, nil
}

// NewNop returns a no-op logger that discards all events.
func NewNop() *Logger {
	return &Logger{
		zl: zerolog.Nop(),
	}
}

// SetEmitter sets the event emitter for external emission.
// Must be called before the logger is used concurrently (i.e., before
// the proxy starts serving). Not safe for concurrent use with Log methods.
func (l *Logger) SetEmitter(e *emit.Emitter) {
	l.emitter = e
}

// LogAllowed logs a successful, allowed request.
func (l *Logger) LogAllowed(method, url, clientIP, requestID string, statusCode, sizeBytes int, duration time.Duration, agent string) {
	if !l.includeAllowed {
		return
	}
	ev := l.zl.Info().
		Str("event", string(EventAllowed)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Int("status_code", statusCode).
		Int("size_bytes", sizeBytes).
		Dur("duration_ms", duration)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev.Msg("request allowed")
}

// LogBlocked logs a blocked request with the reason.
func (l *Logger) LogBlocked(method, url, scanner, reason, clientIP, requestID, agent string) {
	technique := TechniqueForScanner(scanner)

	// includeBlocked gates local audit log only — external emission always fires
	// so SIEM/webhook consumers see blocked events regardless of local verbosity.
	if l.includeBlocked {
		event := l.zl.Warn().
			Str("event", string(EventBlocked)).
			Str("method", method).
			Str("url", sanitizeString(url)).
			Str("client_ip", clientIP).
			Str("request_id", requestID).
			Str("scanner", scanner).
			Str("reason", sanitizeString(reason))
		if agent != "" {
			event = event.Str("agent", sanitizeString(agent))
		}
		if technique != "" {
			event = event.Str("mitre_technique", technique)
		}
		event.Msg("request blocked")
	}

	if l.emitter != nil {
		fields := map[string]any{
			"method":     method,
			"url":        sanitizeString(url),
			"scanner":    scanner,
			"reason":     sanitizeString(reason),
			"client_ip":  clientIP,
			"request_id": requestID,
		}
		if agent != "" {
			fields["agent"] = sanitizeString(agent)
		}
		if technique != "" {
			fields["mitre_technique"] = technique
		}
		l.emitter.Emit(context.Background(), string(EventBlocked), fields)
	}
}

// LogError logs a fetch error.
func (l *Logger) LogError(method, url, clientIP, requestID, agent string, err error) {
	ev := l.zl.Error().
		Str("event", string(EventError)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev.Err(err).
		Msg("request error")

	if l.emitter != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		fields := map[string]any{
			"method":     method,
			"url":        sanitizeString(url),
			"client_ip":  clientIP,
			"request_id": requestID,
			"error":      errStr,
		}
		if agent != "" {
			fields["agent"] = sanitizeString(agent)
		}
		l.emitter.Emit(context.Background(), string(EventError), fields)
	}
}

// LogAnomaly logs suspicious but not blocked activity. The scanner parameter
// identifies which scanner/check produced the anomaly (e.g. "dlp", "ssrf").
// Pass an empty string for operational anomalies that aren't scanner-driven
// (startup warnings, readability failures, redirect hints).
func (l *Logger) LogAnomaly(method, url, scanner, reason, clientIP, requestID, agent string, score float64) {
	technique := TechniqueForScanner(scanner)

	event := l.zl.Warn().
		Str("event", string(EventAnomaly)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		event = event.Str("agent", sanitizeString(agent))
	}
	if scanner != "" {
		event = event.Str("scanner", scanner)
	}
	if technique != "" {
		event = event.Str("mitre_technique", technique)
	}
	event.Str("reason", sanitizeString(reason)).
		Float64("score", score).
		Msg("anomaly detected")

	if l.emitter != nil {
		fields := map[string]any{
			"method":     method,
			"url":        sanitizeString(url),
			"reason":     sanitizeString(reason),
			"client_ip":  clientIP,
			"request_id": requestID,
			"score":      score,
		}
		if agent != "" {
			fields["agent"] = sanitizeString(agent)
		}
		if scanner != "" {
			fields["scanner"] = scanner
		}
		if technique != "" {
			fields["mitre_technique"] = technique
		}
		l.emitter.Emit(context.Background(), string(EventAnomaly), fields)
	}
}

// LogResponseScan logs a response content scan that found prompt injection patterns.
// When bundleRules is non-empty, bundle provenance is included in the audit event
// and webhook payload so SIEM consumers can identify which community rules matched.
func (l *Logger) LogResponseScan(url, clientIP, requestID, agent, action string, matchCount int, patternNames []string, bundleRules []BundleRuleHit) {
	technique := TechniqueForScanner("response_scan")

	event := l.zl.Warn().
		Str("event", string(EventResponseScan)).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Str("action", action).
		Int("match_count", matchCount).
		Strs("patterns", patternNames).
		Str("mitre_technique", technique)
	if agent != "" {
		event = event.Str("agent", sanitizeString(agent))
	}
	if len(bundleRules) > 0 {
		event = event.Interface("bundle_rules", bundleRules)
	}
	event.Msg("response scan detected prompt injection")

	if l.emitter != nil {
		data := map[string]any{
			"url":             sanitizeString(url),
			"client_ip":       clientIP,
			"request_id":      requestID,
			"action":          action,
			"match_count":     matchCount,
			"patterns":        patternNames,
			"mitre_technique": technique,
		}
		if agent != "" {
			data["agent"] = sanitizeString(agent)
		}
		if len(bundleRules) > 0 {
			data["bundle_rules"] = bundleRules
		}
		l.emitter.Emit(context.Background(), string(EventResponseScan), data)
	}
}

// LogTunnelOpen logs a CONNECT tunnel establishment.
func (l *Logger) LogTunnelOpen(target, clientIP, requestID, agent string) {
	if !l.includeAllowed {
		return
	}
	ev := l.zl.Info().
		Str("event", string(EventTunnelOpen)).
		Str("target", sanitizeString(target)).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev.Msg("tunnel opened")
}

// LogTunnelClose logs a CONNECT tunnel teardown with traffic stats.
func (l *Logger) LogTunnelClose(target, clientIP, requestID, agent string, totalBytes int64, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	ev := l.zl.Info().
		Str("event", string(EventTunnelClose)).
		Str("target", sanitizeString(target)).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev.Int64("total_bytes", totalBytes).
		Dur("duration_ms", duration).
		Msg("tunnel closed")
}

// LogForwardHTTP logs a forward proxy HTTP request (absolute-URI).
func (l *Logger) LogForwardHTTP(method, url, clientIP, requestID, agent string, statusCode, sizeBytes int, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	ev := l.zl.Info().
		Str("event", string(EventForwardHTTP)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev.Int("status_code", statusCode).
		Int("size_bytes", sizeBytes).
		Dur("duration_ms", duration).
		Msg("forward proxy request")
}

// LogRedirect logs a redirect hop in the chain.
func (l *Logger) LogRedirect(originalURL, redirectURL, clientIP, requestID, agent string, hop int) {
	ev := l.zl.Info().
		Str("event", string(EventRedirect)).
		Str("original_url", sanitizeString(originalURL)).
		Str("redirect_url", sanitizeString(redirectURL)).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev.Int("hop", hop).
		Msg("redirect followed")
}

// LogToolRedirect logs an MCP tool call redirect event. This is distinct from
// LogRedirect (HTTP redirect hops). result is "redirected" or "blocked" (on failure).
func (l *Logger) LogToolRedirect(sessionID, toolName, argsDigest, redirectProfile, redirectReason, policyRule, result string, latencyMs int64) {
	ev := l.zl.Info().
		Str("event", string(EventToolRedirect)).
		Str("tool_name", sanitizeString(toolName)).
		Str("args_digest", argsDigest).
		Str("redirect_profile", sanitizeString(redirectProfile)).
		Str("redirect_reason", sanitizeString(redirectReason)).
		Str("policy_rule", sanitizeString(policyRule)).
		Str("result", result).
		Int64("latency_ms", latencyMs)
	if sessionID != "" {
		ev = ev.Str("session_id", sessionID)
	}
	ev.Msg("tool call redirected")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventToolRedirect), map[string]any{
			"tool_name":        toolName,
			"args_digest":      argsDigest,
			"redirect_profile": redirectProfile,
			"redirect_reason":  redirectReason,
			"policy_rule":      policyRule,
			"result":           result,
			"latency_ms":       latencyMs,
		})
	}
}

// LogConfigReload logs a configuration reload event.
func (l *Logger) LogConfigReload(status, detail, configHash string) {
	l.zl.Info().
		Str("event", string(EventConfigReload)).
		Str("status", status).
		Str("detail", detail).
		Str("config_hash", configHash).
		Msg("configuration reloaded")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventConfigReload), map[string]any{
			"status":      status,
			"detail":      detail,
			"config_hash": configHash,
		})
	}
}

// LogStartup logs that the proxy has started.
func (l *Logger) LogStartup(listenAddr, mode, version, configHash string) {
	l.zl.Info().
		Str("event", "startup").
		Str("listen", listenAddr).
		Str("mode", mode).
		Str("version", version).
		Str("config_hash", configHash).
		Msg("pipelock started")
}

// LogShutdown logs that the proxy is shutting down.
func (l *Logger) LogShutdown(reason string) {
	l.zl.Info().
		Str("event", "shutdown").
		Str("reason", reason).
		Msg("pipelock stopping")
}

// LogAgentListener logs that a per-agent listener has started.
func (l *Logger) LogAgentListener(addr, agent string) {
	l.zl.Info().
		Str("event", string(EventAgentListener)).
		Str("listen", addr).
		Str("agent", sanitizeString(agent)).
		Msg("agent listener started")
}

// LogWSOpen logs a WebSocket proxy connection establishment.
func (l *Logger) LogWSOpen(target, clientIP, requestID, agent string) {
	if !l.includeAllowed {
		return
	}
	l.zl.Info().
		Str("event", string(EventWSOpen)).
		Str("target", sanitizeString(target)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Str("agent", sanitizeString(agent)).
		Msg("websocket opened")
}

// LogWSClose logs a WebSocket proxy connection teardown with traffic stats.
func (l *Logger) LogWSClose(target, clientIP, requestID, agent string, clientToServer, serverToClient int64, textFrames, binaryFrames int64, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	l.zl.Info().
		Str("event", string(EventWSClose)).
		Str("target", sanitizeString(target)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Str("agent", sanitizeString(agent)).
		Int64("client_to_server_bytes", clientToServer).
		Int64("server_to_client_bytes", serverToClient).
		Int64("text_frames", textFrames).
		Int64("binary_frames", binaryFrames).
		Dur("duration_ms", duration).
		Msg("websocket closed")
}

// LogWSBlocked logs a blocked WebSocket frame or connection.
func (l *Logger) LogWSBlocked(target, direction, scannerName, reason, clientIP, requestID string) {
	technique := TechniqueForScanner(scannerName)

	// includeBlocked gates local audit log only — external emission always fires.
	if l.includeBlocked {
		event := l.zl.Warn().
			Str("event", string(EventWSBlocked)).
			Str("target", sanitizeString(target)).
			Str("direction", direction).
			Str("scanner", scannerName).
			Str("reason", sanitizeString(reason)).
			Str("client_ip", clientIP).
			Str("request_id", requestID)
		if technique != "" {
			event = event.Str("mitre_technique", technique)
		}
		event.Msg("websocket blocked")
	}

	if l.emitter != nil {
		fields := map[string]any{
			"target":     sanitizeString(target),
			"direction":  direction,
			"scanner":    scannerName,
			"reason":     sanitizeString(reason),
			"client_ip":  clientIP,
			"request_id": requestID,
		}
		if technique != "" {
			fields["mitre_technique"] = technique
		}
		l.emitter.Emit(context.Background(), string(EventWSBlocked), fields)
	}
}

// LogWSScan logs a WebSocket frame scan hit (warn/strip action).
// Direction determines the MITRE technique: client_to_server is DLP/exfil (T1048),
// server_to_client is prompt injection detection (T1059).
// When bundleRules is non-empty, bundle provenance is included in the audit event.
func (l *Logger) LogWSScan(target, direction, clientIP, requestID, action string, matchCount int, patternNames []string, bundleRules []BundleRuleHit) {
	scanner := string(EventResponseScan)
	if direction == DirectionClientToServer {
		scanner = ScannerDLP
	}
	technique := TechniqueForScanner(scanner)

	event := l.zl.Warn().
		Str("event", string(EventWSScan)).
		Str("target", sanitizeString(target)).
		Str("direction", direction).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Str("action", action).
		Int("match_count", matchCount).
		Strs("patterns", patternNames).
		Str("mitre_technique", technique)
	if len(bundleRules) > 0 {
		event = event.Interface("bundle_rules", bundleRules)
	}
	event.Msg("websocket scan hit")

	if l.emitter != nil {
		data := map[string]any{
			"target":          sanitizeString(target),
			"direction":       direction,
			"client_ip":       clientIP,
			"request_id":      requestID,
			"action":          action,
			"match_count":     matchCount,
			"patterns":        patternNames,
			"mitre_technique": technique,
		}
		if len(bundleRules) > 0 {
			data["bundle_rules"] = bundleRules
		}
		l.emitter.Emit(context.Background(), string(EventWSScan), data)
	}
}

// LogSessionAnomaly logs a session behavioral anomaly detection.
func (l *Logger) LogSessionAnomaly(sessionKey, anomalyType, detail, clientIP, requestID string, score float64) {
	technique := TechniqueForScanner("session_anomaly")

	l.zl.Warn().
		Str("event", string(EventSessionAnomaly)).
		Str("session", sanitizeString(sessionKey)).
		Str("anomaly_type", anomalyType).
		Str("detail", sanitizeString(detail)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Float64("score", score).
		Str("mitre_technique", technique).
		Msg("session anomaly detected")

	if l.emitter != nil {
		fields := map[string]any{
			"session":         sanitizeString(sessionKey),
			"anomaly_type":    anomalyType,
			"detail":          sanitizeString(detail),
			"score":           score,
			"mitre_technique": technique,
		}
		if clientIP != "" {
			fields["client_ip"] = clientIP
		}
		if requestID != "" {
			fields["request_id"] = requestID
		}
		l.emitter.Emit(context.Background(), string(EventSessionAnomaly), fields)
	}
}

// LogAdaptiveEscalation logs an enforcement level escalation.
func (l *Logger) LogAdaptiveEscalation(sessionKey, from, to, clientIP, requestID string, score float64) {
	l.zl.Warn().
		Str("event", string(EventAdaptiveEscalation)).
		Str("session", sanitizeString(sessionKey)).
		Str("from", from).
		Str("to", to).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Float64("score", score).
		Msg("enforcement escalated")

	if l.emitter != nil {
		fields := map[string]any{
			"session": sanitizeString(sessionKey),
			"from":    from,
			"to":      to,
			"score":   score,
		}
		if clientIP != "" {
			fields["client_ip"] = clientIP
		}
		if requestID != "" {
			fields["request_id"] = requestID
		}
		l.emitter.EmitWithSeverity(context.Background(), emit.EscalationSeverity(to), string(EventAdaptiveEscalation), fields)
	}
}

// LogAdaptiveUpgrade logs an adaptive enforcement action upgrade — when the
// session's escalation level causes a stronger action to be applied to a
// request than would otherwise have been (e.g. warn → block).
func (l *Logger) LogAdaptiveUpgrade(sessionKey, level, fromAction, toAction, scanner, clientIP, requestID string) {
	// Derive severity from toAction (block=critical, else warn).
	derivedSev := severityWarn
	if toAction == actionBlock {
		derivedSev = severityCritical
	}

	l.zl.Warn().
		Str("event", string(EventAdaptiveUpgrade)).
		Str("session", sanitizeString(sessionKey)).
		Str("escalation_level", level).
		Str("from_action", fromAction).
		Str("to_action", toAction).
		Str("scanner", scanner).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Msg("adaptive enforcement upgrade")

	if l.emitter != nil {
		sev := emit.SeverityWarn
		if toAction == actionBlock {
			sev = emit.SeverityCritical
		}
		fields := map[string]any{
			"session":          sanitizeString(sessionKey),
			"escalation_level": level,
			"from_action":      fromAction,
			"to_action":        toAction,
			"scanner":          scanner,
			"severity":         derivedSev,
		}
		if clientIP != "" {
			fields["client_ip"] = clientIP
		}
		if requestID != "" {
			fields["request_id"] = requestID
		}
		l.emitter.EmitWithSeverity(context.Background(), sev, string(EventAdaptiveUpgrade), fields)
	}
}

// LogMCPUnknownTool logs a tool call to a tool not in the session baseline.
func (l *Logger) LogMCPUnknownTool(toolName, action string) {
	technique := TechniqueForScanner("mcp_unknown_tool")

	l.zl.Warn().
		Str("event", string(EventMCPUnknownTool)).
		Str("tool", sanitizeString(toolName)).
		Str("action", action).
		Str("mitre_technique", technique).
		Msg("tool not in session baseline")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventMCPUnknownTool), map[string]any{
			"tool":            sanitizeString(toolName),
			"action":          action,
			"mitre_technique": technique,
		})
	}
}

// LogSNIMismatch logs an SNI verification failure (domain fronting, malformed
// TLS, or timeout). Fields are structured per audit policy: connect_host and
// sni_host are explicit, never parsed from error text.
func (l *Logger) LogSNIMismatch(connectHost, sniHost, clientIP, requestID, agent, category string) {
	technique := TechniqueForScanner("sni_mismatch")

	ev := l.zl.Warn().
		Str("event", string(EventSNIMismatch)).
		Str("connect_host", sanitizeString(connectHost)).
		Str("sni_host", sanitizeString(sniHost)).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev.Str("category", category).
		Str("mitre_technique", technique).
		Msg("SNI verification failed")

	if l.emitter != nil {
		fields := map[string]any{
			"connect_host":    sanitizeString(connectHost),
			"sni_host":        sanitizeString(sniHost),
			"client_ip":       clientIP,
			"request_id":      requestID,
			"category":        category,
			"mitre_technique": technique,
		}
		if agent != "" {
			fields["agent"] = sanitizeString(agent)
		}
		l.emitter.Emit(context.Background(), string(EventSNIMismatch), fields)
	}
}

// LogKillSwitchDeny logs a request denied by the kill switch.
func (l *Logger) LogKillSwitchDeny(transport, endpoint, source, message, clientIP string) {
	l.zl.Info().
		Str("event", string(EventKillSwitchDeny)).
		Str("transport", sanitizeString(transport)).
		Str("endpoint", sanitizeString(endpoint)).
		Str("source", sanitizeString(source)).
		Str("deny_message", sanitizeString(message)).
		Str("client_ip", sanitizeString(clientIP)).
		Msg("kill switch denied request")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventKillSwitchDeny), map[string]any{
			"transport":    sanitizeString(transport),
			"endpoint":     sanitizeString(endpoint),
			"source":       sanitizeString(source),
			"deny_message": sanitizeString(message),
			"client_ip":    sanitizeString(clientIP),
		})
	}
}

// LogBodyDLP logs a request body DLP scan detection.
// When bundleRules is non-empty, bundle provenance is included in the audit event.
func (l *Logger) LogBodyDLP(method, url, action, clientIP, requestID, agent string, matchCount int, patternNames []string, bundleRules []BundleRuleHit) {
	technique := TechniqueForScanner(ScannerDLP)

	ev := l.zl.Warn().
		Str("event", string(EventBodyDLP)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("action", action).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev = ev.Int("match_count", matchCount).
		Strs("patterns", patternNames).
		Str("mitre_technique", technique)
	if len(bundleRules) > 0 {
		ev = ev.Interface("bundle_rules", bundleRules)
	}
	ev.Msg("request body DLP scan hit")

	if l.emitter != nil {
		fields := map[string]any{
			"method":          method,
			"url":             sanitizeString(url),
			"action":          action,
			"client_ip":       clientIP,
			"request_id":      requestID,
			"match_count":     matchCount,
			"patterns":        patternNames,
			"mitre_technique": technique,
		}
		if agent != "" {
			fields["agent"] = sanitizeString(agent)
		}
		if len(bundleRules) > 0 {
			fields["bundle_rules"] = bundleRules
		}
		l.emitter.Emit(context.Background(), string(EventBodyDLP), fields)
	}
}

// LogBodyScan logs a request body scan hit with a configurable event type.
// Used to distinguish address_protection from body_dlp in audit output.
func (l *Logger) LogBodyScan(method, url string, eventType EventType, action, clientIP, requestID, agent string, matchCount int, findingNames []string) {
	label := string(eventType)
	ev := l.zl.Warn().
		Str("event", label).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("action", action).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev.Int("match_count", matchCount).
		Strs("findings", findingNames).
		Msg("request body " + label + " scan hit")

	if l.emitter != nil {
		fields := map[string]any{
			"method":      method,
			"url":         sanitizeString(url),
			"action":      action,
			"client_ip":   clientIP,
			"request_id":  requestID,
			"match_count": matchCount,
			"findings":    findingNames,
		}
		if agent != "" {
			fields["agent"] = sanitizeString(agent)
		}
		l.emitter.Emit(context.Background(), label, fields)
	}
}

// LogHeaderDLP logs a request header DLP scan detection.
// When bundleRules is non-empty, bundle provenance is included in the audit event.
func (l *Logger) LogHeaderDLP(method, url, headerName, action, clientIP, requestID, agent string, patternNames []string, bundleRules []BundleRuleHit) {
	technique := TechniqueForScanner(ScannerDLP)

	ev := l.zl.Warn().
		Str("event", string(EventHeaderDLP)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("header", sanitizeString(headerName)).
		Str("action", action).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
	if agent != "" {
		ev = ev.Str("agent", sanitizeString(agent))
	}
	ev = ev.Strs("patterns", patternNames).
		Str("mitre_technique", technique)
	if len(bundleRules) > 0 {
		ev = ev.Interface("bundle_rules", bundleRules)
	}
	ev.Msg("request header DLP scan hit")

	if l.emitter != nil {
		fields := map[string]any{
			"method":          method,
			"url":             sanitizeString(url),
			"header":          sanitizeString(headerName),
			"action":          action,
			"client_ip":       clientIP,
			"request_id":      requestID,
			"patterns":        patternNames,
			"mitre_technique": technique,
		}
		if agent != "" {
			fields["agent"] = sanitizeString(agent)
		}
		if len(bundleRules) > 0 {
			fields["bundle_rules"] = bundleRules
		}
		l.emitter.Emit(context.Background(), string(EventHeaderDLP), fields)
	}
}

// LogChainDetection logs a tool call chain pattern detection.
// LogChainDetection logs a tool call chain pattern match.
// Severity is derived from action (block=critical, warn=warn) per the
// architectural rule that event severity is hardcoded, not caller-controlled.
// The pattern's own severity is preserved as pattern_severity metadata.
func (l *Logger) LogChainDetection(pattern, patternSeverity, action, toolName, sessionKey string) {
	technique := TechniqueForChainPattern(pattern)

	// Derive severity from action, not from caller input.
	derivedSev := severityWarn
	if action == actionBlock {
		derivedSev = severityCritical
	}

	l.zl.Warn().
		Str("event", string(EventChainDetection)).
		Str("pattern", sanitizeString(pattern)).
		Str("pattern_severity", patternSeverity).
		Str("severity", derivedSev).
		Str("action", action).
		Str("tool", sanitizeString(toolName)).
		Str("session", sanitizeString(sessionKey)).
		Str("mitre_technique", technique).
		Msg("chain pattern detected")

	if l.emitter != nil {
		sev := emit.SeverityWarn
		if action == actionBlock {
			sev = emit.SeverityCritical
		}
		l.emitter.EmitWithSeverity(context.Background(), sev, string(EventChainDetection), map[string]any{
			"pattern":          sanitizeString(pattern),
			"pattern_severity": patternSeverity,
			"severity":         derivedSev,
			"action":           action,
			"tool":             sanitizeString(toolName),
			"session":          sanitizeString(sessionKey),
			"mitre_technique":  technique,
		})
	}
}

// With returns a sub-logger that includes the given key-value pair in every
// log entry. The sub-logger shares the parent's file handle and config but
// does NOT own the file — only the root logger should be Close()'d.
func (l *Logger) With(key, value string) *Logger {
	return &Logger{
		zl:             l.zl.With().Str(key, value).Logger(),
		includeAllowed: l.includeAllowed,
		includeBlocked: l.includeBlocked,
		emitter:        l.emitter,
	}
}

// Close cleans up the logger, flushing and closing any open file handles.
// Close is idempotent and safe to call multiple times.
func (l *Logger) Close() {
	if l.fileHandle != nil {
		_ = l.fileHandle.Sync()
		_ = l.fileHandle.Close()
		l.fileHandle = nil
	}
}
