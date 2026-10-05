// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/emit"
	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
)

// FieldCorrelationID is the emitted-event field that carries the value of the
// operator-configured emit.correlation_header for the request an event
// belongs to.
const FieldCorrelationID = emit.FieldCorrelationID

// CorrelationIDMaxBytes caps an accepted correlation value. Longer values are
// omitted rather than truncated, so a cut can never leave a partial secret.
const CorrelationIDMaxBytes = 128

// CorrelationID is a client-supplied request tag that passed every hygiene
// check. Its field is unexported so the only way to obtain a non-empty value
// outside this package is CorrelationIDFromHeader, which runs the charset,
// length, and DLP checks. That keeps a raw header value from reaching an
// emitted event by a caller forgetting a step.
type CorrelationID struct {
	value string
}

// String returns the vetted value, or "" when no value was accepted.
func (c CorrelationID) String() string { return c.value }

// IsZero reports whether no value was accepted.
func (c CorrelationID) IsZero() bool { return c.value == "" }

// sanitizeCorrelationValue applies the charset and length policy. Leading and
// trailing spaces are trimmed (HTTP optional whitespace). The remainder must be
// 1..CorrelationIDMaxBytes bytes of printable ASCII (0x20-0x7E). Anything else,
// including control characters, DEL, and non-ASCII bytes, rejects the whole
// value: it returns "".
func sanitizeCorrelationValue(raw string) string {
	v := strings.Trim(raw, " \t")
	if v == "" || len(v) > CorrelationIDMaxBytes {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if b := v[i]; b < 0x20 || b > 0x7e {
			return ""
		}
	}
	return v
}

// CorrelationIDFromHeader extracts and vets the configured correlation header
// from a request. It returns the zero CorrelationID, and the request proceeds
// unaffected, when the feature is off (empty headerName), the header is absent
// or repeated, the value fails the charset or length policy, no scanner is
// available, or text DLP reports any match (blocking or informational). The
// DLP scan is the quiet variant so a secret-shaped tag does not produce warn
// telemetry of its own; it still runs the environment and file secret-leak
// checks, so a proxy-held secret placed in the header is never copied to a
// SIEM.
func CorrelationIDFromHeader(ctx context.Context, h http.Header, headerName string, sc *scannerpkg.Scanner) CorrelationID {
	if headerName == "" || sc == nil || h == nil {
		return CorrelationID{}
	}
	values := h.Values(headerName)
	if len(values) != 1 {
		return CorrelationID{}
	}
	v := sanitizeCorrelationValue(values[0])
	if v == "" {
		return CorrelationID{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res := sc.ScanTextForDLPQuiet(ctx, v)
	if !res.Clean || len(res.Matches) > 0 || len(res.InformationalMatches) > 0 {
		return CorrelationID{}
	}
	return CorrelationID{value: v}
}

// WithCorrelation records the request's vetted correlation tag on a copy of
// the context. It is attached only to externally emitted events, never to the
// local audit log or any signed record.
func (c LogContext) WithCorrelation(id CorrelationID) LogContext {
	c.correlation = id
	return c
}

// Correlation returns the vetted correlation tag, if any.
func (c LogContext) Correlation() CorrelationID { return c.correlation }

// WithCorrelation returns a sub-logger whose externally emitted events carry
// the vetted correlation tag when the event does not already set one. Like
// With, the sub-logger shares the parent's sinks and must not be Close()'d. A
// zero id returns the receiver unchanged; a nil receiver returns nil.
func (l *Logger) WithCorrelation(id CorrelationID) *Logger {
	if l == nil || id.IsZero() {
		return l
	}
	sub := *l
	sub.fileHandle = nil
	sub.filePath = ""
	sub.fileCreated = false
	sub.correlation = id
	return &sub
}

// correlationField adds the correlation tag to the emitted fields only. The
// zerolog event is deliberately untouched: the feature is scoped to external
// event emission.
func (e *logEntry) correlationField(id CorrelationID) *logEntry {
	if !id.IsZero() {
		e.fields[FieldCorrelationID] = id.value
	}
	return e
}

// withEmitCorrelation stamps the logger's correlation tag onto an emitted
// field map that does not already carry one.
func (l *Logger) withEmitCorrelation(fields map[string]any) map[string]any {
	if l.correlation.IsZero() {
		return fields
	}
	if _, ok := fields[FieldCorrelationID]; ok {
		return fields
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields[FieldCorrelationID] = l.correlation.value
	return fields
}

// emitEvent sends an event to the external emitter, adding the sub-logger's
// correlation tag. Every audit emission goes through here or
// emitEventWithSeverity so the tag cannot be skipped on one path.
func (l *Logger) emitEvent(eventType string, fields map[string]any) {
	if l.emitter == nil {
		return
	}
	l.emitter.Emit(context.Background(), eventType, l.withEmitCorrelation(fields))
}

// emitEventWithSeverity is emitEvent with an explicit severity override.
func (l *Logger) emitEventWithSeverity(sev emit.Severity, eventType string, fields map[string]any) {
	if l.emitter == nil {
		return
	}
	l.emitter.EmitWithSeverity(context.Background(), sev, eventType, l.withEmitCorrelation(fields))
}
