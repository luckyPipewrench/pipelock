// Package audit provides structured JSON audit logging for all Pipelock events.
package audit

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// EventType describes the kind of audit event.
type EventType string

const (
	EventAllowed EventType = "allowed"
	EventBlocked EventType = "blocked"
	EventError   EventType = "error"
	EventAnomaly EventType = "anomaly"
)

// Logger handles structured audit logging using zerolog.
type Logger struct {
	zl             zerolog.Logger
	includeAllowed bool
	includeBlocked bool
	fileHandle     *os.File // non-nil if logging to file
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
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
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

// LogAllowed logs a successful, allowed request.
func (l *Logger) LogAllowed(method, url, clientIP, requestID string, statusCode, sizeBytes int, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	l.zl.Info().
		Str("event", string(EventAllowed)).
		Str("method", method).
		Str("url", url).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Int("status_code", statusCode).
		Int("size_bytes", sizeBytes).
		Dur("duration_ms", duration).
		Msg("request allowed")
}

// LogBlocked logs a blocked request with the reason.
func (l *Logger) LogBlocked(method, url, scanner, reason, clientIP, requestID string) {
	if !l.includeBlocked {
		return
	}
	l.zl.Warn().
		Str("event", string(EventBlocked)).
		Str("method", method).
		Str("url", url).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Str("scanner", scanner).
		Str("reason", reason).
		Msg("request blocked")
}

// LogError logs a fetch error.
func (l *Logger) LogError(method, url, clientIP, requestID string, err error) {
	l.zl.Error().
		Str("event", string(EventError)).
		Str("method", method).
		Str("url", url).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Err(err).
		Msg("request error")
}

// LogAnomaly logs suspicious but not blocked activity.
func (l *Logger) LogAnomaly(method, url, reason, clientIP, requestID string, score float64) {
	l.zl.Warn().
		Str("event", string(EventAnomaly)).
		Str("method", method).
		Str("url", url).
		Str("client_ip", clientIP).
		Str("request_id", requestID).
		Str("reason", reason).
		Float64("score", score).
		Msg("anomaly detected")
}

// LogRedirect logs a redirect hop in the chain.
func (l *Logger) LogRedirect(originalURL, redirectURL string, hop int) {
	l.zl.Info().
		Str("event", "redirect").
		Str("original_url", originalURL).
		Str("redirect_url", redirectURL).
		Int("hop", hop).
		Msg("redirect followed")
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

// Close cleans up the logger, flushing and closing any open file handles.
// Close is idempotent and safe to call multiple times.
func (l *Logger) Close() {
	if l.fileHandle != nil {
		_ = l.fileHandle.Sync()
		_ = l.fileHandle.Close()
		l.fileHandle = nil
	}
}
