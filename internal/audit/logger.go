// Package audit provides structured JSON audit logging for all Pipelock events.
package audit

import (
	"context"
	"io"
	"os"
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
)

// WebSocket frame direction constants used in audit log entries.
const (
	DirectionClientToServer = "client_to_server"
	DirectionServerToClient = "server_to_client"
)

// Scanner label for DLP audit events (used in technique mapping).
const ScannerDLP = "dlp"

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
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: path validated by config layer
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
func (l *Logger) LogAllowed(method, url, clientIP, requestID string, statusCode, sizeBytes int, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	l.zl.Info().
		Str("event", string(EventAllowed)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Int("status_code", statusCode).
		Int("size_bytes", sizeBytes).
		Dur("duration_ms", duration).
		Msg("request allowed")
}

// LogBlocked logs a blocked request with the reason.
func (l *Logger) LogBlocked(method, url, scanner, reason, clientIP, requestID string) {
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
		if technique != "" {
			fields["mitre_technique"] = technique
		}
		l.emitter.Emit(context.Background(), string(EventBlocked), fields)
	}
}

// LogError logs a fetch error.
func (l *Logger) LogError(method, url, clientIP, requestID string, err error) {
	l.zl.Error().
		Str("event", string(EventError)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Err(err).
		Msg("request error")

	if l.emitter != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		l.emitter.Emit(context.Background(), string(EventError), map[string]any{
			"method":     method,
			"url":        sanitizeString(url),
			"client_ip":  clientIP,
			"request_id": requestID,
			"error":      errStr,
		})
	}
}

// LogAnomaly logs suspicious but not blocked activity. The scanner parameter
// identifies which scanner/check produced the anomaly (e.g. "dlp", "ssrf").
// Pass an empty string for operational anomalies that aren't scanner-driven
// (startup warnings, readability failures, redirect hints).
func (l *Logger) LogAnomaly(method, url, scanner, reason, clientIP, requestID string, score float64) {
	technique := TechniqueForScanner(scanner)

	event := l.zl.Warn().
		Str("event", string(EventAnomaly)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID)
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
func (l *Logger) LogResponseScan(url, clientIP, requestID, action string, matchCount int, patternNames []string) {
	technique := TechniqueForScanner("response_scan")

	l.zl.Warn().
		Str("event", string(EventResponseScan)).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Str("action", action).
		Int("match_count", matchCount).
		Strs("patterns", patternNames).
		Str("mitre_technique", technique).
		Msg("response scan detected prompt injection")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventResponseScan), map[string]any{
			"url":             sanitizeString(url),
			"client_ip":       clientIP,
			"request_id":      requestID,
			"action":          action,
			"match_count":     matchCount,
			"patterns":        patternNames,
			"mitre_technique": technique,
		})
	}
}

// LogTunnelOpen logs a CONNECT tunnel establishment.
func (l *Logger) LogTunnelOpen(target, clientIP, requestID string) {
	if !l.includeAllowed {
		return
	}
	l.zl.Info().
		Str("event", string(EventTunnelOpen)).
		Str("target", sanitizeString(target)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Msg("tunnel opened")
}

// LogTunnelClose logs a CONNECT tunnel teardown with traffic stats.
func (l *Logger) LogTunnelClose(target, clientIP, requestID string, totalBytes int64, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	l.zl.Info().
		Str("event", string(EventTunnelClose)).
		Str("target", sanitizeString(target)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Int64("total_bytes", totalBytes).
		Dur("duration_ms", duration).
		Msg("tunnel closed")
}

// LogForwardHTTP logs a forward proxy HTTP request (absolute-URI).
func (l *Logger) LogForwardHTTP(method, url, clientIP, requestID string, statusCode, sizeBytes int, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	l.zl.Info().
		Str("event", string(EventForwardHTTP)).
		Str("method", method).
		Str("url", sanitizeString(url)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Int("status_code", statusCode).
		Int("size_bytes", sizeBytes).
		Dur("duration_ms", duration).
		Msg("forward proxy request")
}

// LogRedirect logs a redirect hop in the chain.
func (l *Logger) LogRedirect(originalURL, redirectURL, clientIP, requestID string, hop int) {
	l.zl.Info().
		Str("event", string(EventRedirect)).
		Str("original_url", sanitizeString(originalURL)).
		Str("redirect_url", sanitizeString(redirectURL)).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Int("hop", hop).
		Msg("redirect followed")
}

// LogConfigReload logs a configuration reload event.
func (l *Logger) LogConfigReload(status, detail string) {
	l.zl.Info().
		Str("event", string(EventConfigReload)).
		Str("status", status).
		Str("detail", detail).
		Msg("configuration reloaded")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventConfigReload), map[string]any{
			"status": status,
			"detail": detail,
		})
	}
}

// LogStartup logs that the proxy has started.
func (l *Logger) LogStartup(listenAddr, mode string) {
	l.zl.Info().
		Str("event", "startup").
		Str("listen", listenAddr).
		Str("mode", mode).
		Msg("pipelock started")
}

// LogShutdown logs that the proxy is shutting down.
func (l *Logger) LogShutdown(reason string) {
	l.zl.Info().
		Str("event", "shutdown").
		Str("reason", reason).
		Msg("pipelock stopping")
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
func (l *Logger) LogWSScan(target, direction, clientIP, requestID, action string, matchCount int, patternNames []string) {
	scanner := string(EventResponseScan)
	if direction == DirectionClientToServer {
		scanner = ScannerDLP
	}
	technique := TechniqueForScanner(scanner)

	l.zl.Warn().
		Str("event", string(EventWSScan)).
		Str("target", sanitizeString(target)).
		Str("direction", direction).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Str("action", action).
		Int("match_count", matchCount).
		Strs("patterns", patternNames).
		Str("mitre_technique", technique).
		Msg("websocket scan hit")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventWSScan), map[string]any{
			"target":          sanitizeString(target),
			"direction":       direction,
			"client_ip":       clientIP,
			"request_id":      requestID,
			"action":          action,
			"match_count":     matchCount,
			"patterns":        patternNames,
			"mitre_technique": technique,
		})
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
