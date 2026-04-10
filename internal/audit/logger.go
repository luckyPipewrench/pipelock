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

// logEntry builds zerolog event and emit fields in parallel, eliminating
// the double-build pattern across all Log* methods.
type logEntry struct {
	event  *zerolog.Event
	fields map[string]any
}

func newLogEntry(event *zerolog.Event, eventType EventType) *logEntry {
	return &logEntry{
		event:  event.Str("event", string(eventType)),
		fields: map[string]any{},
	}
}

// newLogEntryRaw creates a logEntry with a raw event name string (for startup/shutdown
// which use plain strings instead of EventType constants).
func newLogEntryRaw(event *zerolog.Event, eventName string) *logEntry {
	return &logEntry{
		event:  event.Str("event", eventName),
		fields: map[string]any{},
	}
}

func (e *logEntry) str(key, value string) *logEntry {
	sanitized := sanitizeString(value)
	e.event = e.event.Str(key, sanitized)
	e.fields[key] = sanitized
	return e
}

func (e *logEntry) optStr(key, value string) *logEntry {
	if value == "" {
		return e
	}
	return e.str(key, value)
}

func (e *logEntry) intField(key string, value int) *logEntry {
	e.event = e.event.Int(key, value)
	e.fields[key] = value
	return e
}

func (e *logEntry) int64Field(key string, value int64) *logEntry {
	e.event = e.event.Int64(key, value)
	e.fields[key] = value
	return e
}

func (e *logEntry) float64Field(key string, value float64) *logEntry {
	e.event = e.event.Float64(key, value)
	e.fields[key] = value
	return e
}

// durMS adds a "duration_ms" duration field to both zerolog and emit.
// All duration fields in audit use the same key, so it is hardcoded to
// satisfy the unparam linter.
func (e *logEntry) durMS(value time.Duration) *logEntry {
	e.event = e.event.Dur("duration_ms", value)
	e.fields["duration_ms"] = value.Milliseconds()
	return e
}

func (e *logEntry) strs(key string, values []string) *logEntry {
	sanitized := make([]string, len(values))
	for i, v := range values {
		sanitized[i] = sanitizeString(v)
	}
	e.event = e.event.Strs(key, sanitized)
	e.fields[key] = sanitized
	return e
}

func (e *logEntry) errField(err error) *logEntry {
	e.event = e.event.Err(err)
	errStr := ""
	if err != nil {
		errStr = sanitizeString(err.Error())
	}
	e.fields["error"] = errStr
	return e
}

// bundleRulesField adds "bundle_rules" to both zerolog and emit. All
// Interface-typed audit fields use this key, so it is hardcoded to satisfy
// the unparam linter. Called as a statement (never chained) because it is
// always conditional on len(bundleRules) > 0.
func (e *logEntry) bundleRulesField(value any) {
	e.event = e.event.Interface("bundle_rules", value)
	e.fields["bundle_rules"] = value
}

// msg sends the zerolog message. Call this instead of e.event.Msg() to keep
// the logEntry API consistent.
func (e *logEntry) msg(text string) {
	e.event.Msg(text)
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

	EventAdaptiveUpgrade    EventType = "adaptive_upgrade"
	EventToolRedirect       EventType = "tool_redirect"
	EventSessionAdmin       EventType = "session_admin"
	EventResponseScanExempt EventType = "response_scan_exempt"

	EventAirlockEnter      EventType = "airlock_enter"
	EventAirlockDeny       EventType = "airlock_deny"
	EventAirlockDeescalate EventType = "airlock_deescalate"
	EventShieldRewrite     EventType = "shield_rewrite"
	EventMediaExposure     EventType = "media_exposure"
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

// LogContext carries common fields shared across all audit log events.
type LogContext struct {
	Method    string
	URL       string
	ClientIP  string
	RequestID string
	Agent     string
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
func (l *Logger) LogAllowed(ctx LogContext, statusCode, sizeBytes int, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventAllowed).
		str("method", ctx.Method).
		str("url", ctx.URL).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		intField("status_code", statusCode).
		intField("size_bytes", sizeBytes).
		durMS(duration).
		optStr("agent", ctx.Agent)
	e.msg("request allowed")
}

// LogBlocked logs a blocked request with the reason.
func (l *Logger) LogBlocked(ctx LogContext, scanner, reason string) {
	technique := TechniqueForScanner(scanner)

	e := newLogEntry(l.zl.Warn(), EventBlocked).
		str("method", ctx.Method).
		str("url", ctx.URL).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		str("scanner", scanner).
		str("reason", reason).
		optStr("agent", ctx.Agent).
		optStr("mitre_technique", technique)

	// includeBlocked gates local audit log only — external emission always fires
	// so SIEM/webhook consumers see blocked events regardless of local verbosity.
	if l.includeBlocked {
		e.msg("request blocked")
	}
	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventBlocked), e.fields)
	}
}

// LogError logs a fetch error.
func (l *Logger) LogError(ctx LogContext, err error) {
	e := newLogEntry(l.zl.Error(), EventError).
		str("method", ctx.Method).
		str("url", ctx.URL).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent).
		errField(err)
	e.msg("request error")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventError), e.fields)
	}
}

// LogAnomaly logs suspicious but not blocked activity. The scanner parameter
// identifies which scanner/check produced the anomaly (e.g. "dlp", "ssrf").
// Pass an empty string for operational anomalies that aren't scanner-driven
// (startup warnings, readability failures, redirect hints).
func (l *Logger) LogAnomaly(ctx LogContext, scanner, reason string, score float64) {
	technique := TechniqueForScanner(scanner)

	e := newLogEntry(l.zl.Warn(), EventAnomaly).
		str("method", ctx.Method).
		str("url", ctx.URL).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent).
		optStr("scanner", scanner).
		optStr("mitre_technique", technique).
		str("reason", reason).
		float64Field("score", score)
	e.msg("anomaly detected")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventAnomaly), e.fields)
	}
}

// LogResponseScanExempt logs when response injection scanning is skipped because
// the destination host matched response_scanning.exempt_domains. This is a dedicated
// event type (not "anomaly") so SIEM consumers can filter exemption events separately
// from actual security anomalies.
func (l *Logger) LogResponseScanExempt(ctx LogContext, hostname string) {
	event := l.zl.Info().
		Str("event", string(EventResponseScanExempt)).
		Str("method", ctx.Method).
		Str("url", sanitizeString(ctx.URL)).
		Str("hostname", hostname).
		Str("enforcement_type", "response_scanning").
		Str("reason", "exempt_domains match")
	if ctx.ClientIP != "" {
		event = event.Str("client_ip", ctx.ClientIP)
	}
	if ctx.RequestID != "" {
		event = event.Str("request_id", ctx.RequestID)
	}
	if ctx.Agent != "" {
		event = event.Str("agent", sanitizeString(ctx.Agent))
	}
	event.Msg("response scan skipped: exempt domain")

	if l.emitter != nil {
		fields := map[string]any{
			"method":           ctx.Method,
			"url":              sanitizeString(ctx.URL),
			"hostname":         hostname,
			"enforcement_type": "response_scanning",
			"reason":           "exempt_domains match",
		}
		if ctx.ClientIP != "" {
			fields["client_ip"] = ctx.ClientIP
		}
		if ctx.RequestID != "" {
			fields["request_id"] = ctx.RequestID
		}
		if ctx.Agent != "" {
			fields["agent"] = sanitizeString(ctx.Agent)
		}
		l.emitter.Emit(context.Background(), string(EventResponseScanExempt), fields)
	}
}

// MediaExposureInfo carries the structured fields for a media_exposure
// event emitted by the audit logger. Populated by the proxy media policy
// helper (see internal/proxy/media_policy.go) and passed to
// LogMediaExposure so the audit layer and emit sinks see a dedicated
// media_exposure event type rather than a generic anomaly.
//
// Separate from internal/proxy.MediaExposureFields (which holds the
// pre-wiring payload) so the audit package doesn't import internal/proxy.
type MediaExposureInfo struct {
	Transport       string // "forward", "connect", "fetch", "reverse"
	ContentType     string
	Format          string // "jpeg", "png", "unknown"
	SizeBytes       int
	MetadataRemoved int
	BytesRemoved    int
	Blocked         bool
	BlockReason     string
}

// LogMediaExposure emits a dedicated media_exposure audit event with the
// structured fields taint/authority and SIEM consumers need to correlate
// media reaching an agent with downstream sensitive actions. Severity is
// SeverityWarn (set in internal/emit via EventSeverity map). Both the
// zerolog stream and the emitter sink receive the same field set.
//
// Unlike LogAnomaly this is not a suspicion marker — it is an exposure
// provenance signal. Every media response that reaches the agent (allowed
// or blocked) should produce one event when media_policy.log_media_exposure
// is enabled, so the downstream policy engine can build an exposure
// timeline.
func (l *Logger) LogMediaExposure(ctx LogContext, info MediaExposureInfo) {
	e := newLogEntry(l.zl.Warn(), EventMediaExposure).
		optStr("method", ctx.Method).
		str("url", ctx.URL).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent).
		str("transport", info.Transport).
		str("content_type", info.ContentType).
		optStr("format", info.Format).
		intField("size_bytes", info.SizeBytes)
	if info.MetadataRemoved > 0 {
		e = e.intField("metadata_segments_removed", info.MetadataRemoved).
			intField("metadata_bytes_removed", info.BytesRemoved)
	}
	// Record block state as a structured field so SIEM consumers can
	// filter blocked vs allowed exposures without parsing the reason.
	e.event = e.event.Bool("blocked", info.Blocked)
	e.fields["blocked"] = info.Blocked
	if info.Blocked && info.BlockReason != "" {
		e = e.str("block_reason", info.BlockReason)
	}
	if info.Blocked {
		e.msg("media response blocked by policy")
	} else {
		e.msg("media response reached agent")
	}

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventMediaExposure), e.fields)
	}
}

// LogResponseScan logs a response content scan that found prompt injection patterns.
// When bundleRules is non-empty, bundle provenance is included in the audit event
// and webhook payload so SIEM consumers can identify which community rules matched.
func (l *Logger) LogResponseScan(ctx LogContext, action string, matchCount int, patternNames []string, bundleRules []BundleRuleHit) {
	technique := TechniqueForScanner("response_scan")

	e := newLogEntry(l.zl.Warn(), EventResponseScan).
		optStr("method", ctx.Method).
		str("url", ctx.URL).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		str("action", action).
		intField("match_count", matchCount).
		strs("patterns", patternNames).
		str("mitre_technique", technique).
		optStr("agent", ctx.Agent)
	if len(bundleRules) > 0 {
		e.bundleRulesField(bundleRules)
	}
	e.msg("response scan detected prompt injection")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventResponseScan), e.fields)
	}
}

// LogTunnelOpen logs a CONNECT tunnel establishment.
func (l *Logger) LogTunnelOpen(ctx LogContext, target string) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventTunnelOpen).
		str("target", target).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent)
	e.msg("tunnel opened")
}

// LogTunnelClose logs a CONNECT tunnel teardown with traffic stats.
func (l *Logger) LogTunnelClose(ctx LogContext, target string, totalBytes int64, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventTunnelClose).
		str("target", target).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent).
		int64Field("total_bytes", totalBytes).
		durMS(duration)
	e.msg("tunnel closed")
}

// LogForwardHTTP logs a forward proxy HTTP request (absolute-URI).
func (l *Logger) LogForwardHTTP(ctx LogContext, statusCode, sizeBytes int, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventForwardHTTP).
		str("method", ctx.Method).
		str("url", ctx.URL).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent).
		intField("status_code", statusCode).
		intField("size_bytes", sizeBytes).
		durMS(duration)
	e.msg("forward proxy request")
}

// LogRedirect logs a redirect hop in the chain.
func (l *Logger) LogRedirect(originalURL, redirectURL, clientIP, requestID, agent string, hop int) {
	e := newLogEntry(l.zl.Info(), EventRedirect).
		str("original_url", originalURL).
		str("redirect_url", redirectURL).
		str("client_ip", clientIP).
		str("request_id", requestID).
		optStr("agent", agent).
		intField("hop", hop)
	e.msg("redirect followed")
}

// LogToolRedirect logs an MCP tool call redirect event. This is distinct from
// LogRedirect (HTTP redirect hops). result is "redirected" or "blocked" (on failure).
func (l *Logger) LogToolRedirect(sessionID, toolName, argsDigest, redirectProfile, redirectReason, policyRule, result string, latencyMs int64) {
	e := newLogEntry(l.zl.Info(), EventToolRedirect).
		str("tool_name", toolName).
		str("args_digest", argsDigest).
		str("redirect_profile", redirectProfile).
		str("redirect_reason", redirectReason).
		str("policy_rule", policyRule).
		str("result", result).
		int64Field("latency_ms", latencyMs)
	// session_id is local-log only — not emitted to external sinks.
	if sessionID != "" {
		e.event = e.event.Str("session_id", sanitizeString(sessionID))
	}
	e.msg("tool call redirected")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventToolRedirect), e.fields)
	}
}

// LogConfigReload logs a configuration reload event.
func (l *Logger) LogConfigReload(status, detail, configHash string) {
	e := newLogEntry(l.zl.Info(), EventConfigReload).
		str("status", status).
		str("detail", detail).
		str("config_hash", configHash)
	e.msg("configuration reloaded")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventConfigReload), e.fields)
	}
}

// LogStartup logs that the proxy has started.
func (l *Logger) LogStartup(listenAddr, mode, version, configHash string) {
	e := newLogEntryRaw(l.zl.Info(), "startup").
		str("listen", listenAddr).
		str("mode", mode).
		str("version", version).
		str("config_hash", configHash)
	e.msg("pipelock started")
}

// LogShutdown logs that the proxy is shutting down.
func (l *Logger) LogShutdown(reason string) {
	e := newLogEntryRaw(l.zl.Info(), "shutdown").
		str("reason", reason)
	e.msg("pipelock stopping")
}

// LogAgentListener logs that a per-agent listener has started.
func (l *Logger) LogAgentListener(addr, agent string) {
	e := newLogEntry(l.zl.Info(), EventAgentListener).
		str("listen", addr).
		str("agent", agent)
	e.msg("agent listener started")
}

// LogWSOpen logs a WebSocket proxy connection establishment.
func (l *Logger) LogWSOpen(target, clientIP, requestID, agent string) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventWSOpen).
		str("target", target).
		str("client_ip", clientIP).
		str("request_id", requestID).
		str("agent", agent)
	e.msg("websocket opened")
}

// LogWSClose logs a WebSocket proxy connection teardown with traffic stats.
func (l *Logger) LogWSClose(target, clientIP, requestID, agent string, clientToServer, serverToClient int64, textFrames, binaryFrames int64, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventWSClose).
		str("target", target).
		str("client_ip", clientIP).
		str("request_id", requestID).
		str("agent", agent).
		int64Field("client_to_server_bytes", clientToServer).
		int64Field("server_to_client_bytes", serverToClient).
		int64Field("text_frames", textFrames).
		int64Field("binary_frames", binaryFrames).
		durMS(duration)
	e.msg("websocket closed")
}

// LogWSBlocked logs a blocked WebSocket frame or connection.
func (l *Logger) LogWSBlocked(target, direction, scannerName, reason, clientIP, requestID string) {
	technique := TechniqueForScanner(scannerName)

	e := newLogEntry(l.zl.Warn(), EventWSBlocked).
		str("target", target).
		str("direction", direction).
		str("scanner", scannerName).
		str("reason", reason).
		str("client_ip", clientIP).
		str("request_id", requestID).
		optStr("mitre_technique", technique)

	// includeBlocked gates local audit log only — external emission always fires.
	if l.includeBlocked {
		e.msg("websocket blocked")
	}
	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventWSBlocked), e.fields)
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

	e := newLogEntry(l.zl.Warn(), EventWSScan).
		str("target", target).
		str("direction", direction).
		str("client_ip", clientIP).
		str("request_id", requestID).
		str("action", action).
		intField("match_count", matchCount).
		strs("patterns", patternNames).
		str("mitre_technique", technique)
	if len(bundleRules) > 0 {
		e.bundleRulesField(bundleRules)
	}
	e.msg("websocket scan hit")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventWSScan), e.fields)
	}
}

// LogSessionAnomaly logs a session behavioral anomaly detection.
func (l *Logger) LogSessionAnomaly(sessionKey, anomalyType, detail, clientIP, requestID string, score float64) {
	technique := TechniqueForScanner("session_anomaly")

	e := newLogEntry(l.zl.Warn(), EventSessionAnomaly).
		str("session", sessionKey).
		str("anomaly_type", anomalyType).
		str("detail", detail).
		str("client_ip", clientIP).
		str("request_id", requestID).
		float64Field("score", score).
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
	e := newLogEntry(l.zl.Warn(), EventAdaptiveEscalation).
		str("session", sessionKey).
		str("from", from).
		str("to", to).
		str("client_ip", clientIP).
		str("request_id", requestID).
		float64Field("score", score)
	e.msg("enforcement escalated")

	if l.emitter != nil {
		// Emit fields: omit client_ip and request_id when empty.
		fields := map[string]any{
			"session": e.fields["session"],
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

	e := newLogEntry(l.zl.Warn(), EventAdaptiveUpgrade).
		str("session", sessionKey).
		str("escalation_level", level).
		str("from_action", fromAction).
		str("to_action", toAction).
		str("scanner", scanner).
		str("client_ip", clientIP).
		str("request_id", requestID)
	e.msg("adaptive enforcement upgrade")

	if l.emitter != nil {
		sev := emit.SeverityWarn
		if toAction == actionBlock && scanner != "session_deny" {
			// Actual escalation transitions emit at critical.
			// session_deny (enforcement of existing block_all) stays at warn
			// to prevent webhook flood — one critical on escalation, not
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

	e := newLogEntry(l.zl.Warn(), EventMCPUnknownTool).
		str("tool", toolName).
		str("action", action).
		str("mitre_technique", technique)
	e.msg("tool not in session baseline")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventMCPUnknownTool), e.fields)
	}
}

// LogSNIMismatch logs an SNI verification failure (domain fronting, malformed
// TLS, or timeout). Fields are structured per audit policy: connect_host and
// sni_host are explicit, never parsed from error text.
func (l *Logger) LogSNIMismatch(connectHost, sniHost, clientIP, requestID, agent, category string) {
	technique := TechniqueForScanner("sni_mismatch")

	e := newLogEntry(l.zl.Warn(), EventSNIMismatch).
		str("connect_host", connectHost).
		str("sni_host", sniHost).
		str("client_ip", clientIP).
		str("request_id", requestID).
		optStr("agent", agent).
		str("category", category).
		str("mitre_technique", technique)
	e.msg("SNI verification failed")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventSNIMismatch), e.fields)
	}
}

// LogKillSwitchDeny logs a request denied by the kill switch.
func (l *Logger) LogKillSwitchDeny(transport, endpoint, source, message, clientIP string) {
	e := newLogEntry(l.zl.Info(), EventKillSwitchDeny).
		str("transport", transport).
		str("endpoint", endpoint).
		str("source", source).
		str("deny_message", message).
		str("client_ip", clientIP)
	e.msg("kill switch denied request")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventKillSwitchDeny), e.fields)
	}
}

// LogBodyDLP logs a request body DLP scan detection.
// When bundleRules is non-empty, bundle provenance is included in the audit event.
func (l *Logger) LogBodyDLP(ctx LogContext, action string, matchCount int, patternNames []string, bundleRules []BundleRuleHit) {
	technique := TechniqueForScanner(ScannerDLP)

	e := newLogEntry(l.zl.Warn(), EventBodyDLP).
		str("method", ctx.Method).
		str("url", ctx.URL).
		str("action", action).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent).
		intField("match_count", matchCount).
		strs("patterns", patternNames).
		str("mitre_technique", technique)
	if len(bundleRules) > 0 {
		e.bundleRulesField(bundleRules)
	}
	e.msg("request body DLP scan hit")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventBodyDLP), e.fields)
	}
}

// LogBodyScan logs a request body scan hit with a configurable event type.
// Used to distinguish address_protection from body_dlp in audit output.
func (l *Logger) LogBodyScan(ctx LogContext, eventType EventType, action string, matchCount int, findingNames []string) {
	e := newLogEntry(l.zl.Warn(), eventType).
		str("method", ctx.Method).
		str("url", ctx.URL).
		str("action", action).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent).
		intField("match_count", matchCount).
		strs("findings", findingNames)
	e.msg("request body " + string(eventType) + " scan hit")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(eventType), e.fields)
	}
}

// LogHeaderDLP logs a request header DLP scan detection.
// When bundleRules is non-empty, bundle provenance is included in the audit event.
func (l *Logger) LogHeaderDLP(ctx LogContext, headerName, action string, patternNames []string, bundleRules []BundleRuleHit) {
	technique := TechniqueForScanner(ScannerDLP)

	e := newLogEntry(l.zl.Warn(), EventHeaderDLP).
		str("method", ctx.Method).
		str("url", ctx.URL).
		str("header", headerName).
		str("action", action).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent).
		strs("patterns", patternNames).
		str("mitre_technique", technique)
	if len(bundleRules) > 0 {
		e.bundleRulesField(bundleRules)
	}
	e.msg("request header DLP scan hit")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventHeaderDLP), e.fields)
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

	e := newLogEntry(l.zl.Warn(), EventChainDetection).
		str("pattern", pattern).
		str("pattern_severity", patternSeverity).
		str("severity", derivedSev).
		str("action", action).
		str("tool", toolName).
		str("session", sessionKey).
		str("mitre_technique", technique)
	e.msg("chain pattern detected")

	if l.emitter != nil {
		sev := emit.SeverityWarn
		if action == actionBlock {
			sev = emit.SeverityCritical
		}
		l.emitter.EmitWithSeverity(context.Background(), sev, string(EventChainDetection), e.fields)
	}
}

// LogSessionAdmin logs a session admin API operation (list, reset, auth failure).
func (l *Logger) LogSessionAdmin(action, clientIP, sessionKey, result string, statusCode int) {
	e := newLogEntry(l.zl.Info(), EventSessionAdmin).
		str("action", action).
		str("client_ip", clientIP).
		intField("status_code", statusCode).
		optStr("session_key", sessionKey).
		optStr("result", result)
	e.msg("session admin API")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventSessionAdmin), e.fields)
	}
}

// LogAirlockEnter logs that a session entered an airlock tier.
func (l *Logger) LogAirlockEnter(sessionKey, tier, trigger, clientIP, requestID string) {
	e := newLogEntry(l.zl.Warn(), EventAirlockEnter).
		str("session", sessionKey).
		str("tier", tier).
		str("trigger", trigger).
		optStr("client_ip", clientIP).
		optStr("request_id", requestID)
	e.msg("session entered airlock")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventAirlockEnter), e.fields)
	}
}

// LogAirlockDeny logs a request denied by airlock enforcement.
func (l *Logger) LogAirlockDeny(sessionKey, tier, transport, method, clientIP, requestID string) {
	e := newLogEntry(l.zl.Warn(), EventAirlockDeny).
		str("session", sessionKey).
		str("tier", tier).
		str("transport", transport).
		str("method", method).
		optStr("client_ip", clientIP).
		optStr("request_id", requestID)
	e.msg("airlock denied request")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventAirlockDeny), e.fields)
	}
}

// LogAirlockDeescalate logs that a session's airlock tier was automatically reduced.
func (l *Logger) LogAirlockDeescalate(sessionKey, from, to, clientIP, requestID string) {
	e := newLogEntry(l.zl.Info(), EventAirlockDeescalate).
		str("session", sessionKey).
		str("from", from).
		str("to", to).
		optStr("client_ip", clientIP).
		optStr("request_id", requestID)
	e.msg("airlock de-escalated")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventAirlockDeescalate), e.fields)
	}
}

// LogShieldRewrite logs that browser shield rewrote response content.
func (l *Logger) LogShieldRewrite(category string, hits int, transport, targetURL, clientIP, requestID string) {
	e := newLogEntry(l.zl.Info(), EventShieldRewrite).
		str("category", category).
		intField("hits", hits).
		str("transport", transport).
		str("url", targetURL).
		optStr("client_ip", clientIP).
		optStr("request_id", requestID)
	e.msg("browser shield rewrote content")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventShieldRewrite), e.fields)
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
