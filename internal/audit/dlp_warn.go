// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import "context"

// EventDLPWarn is emitted when a warn-mode DLP pattern matches.
// The match is informational only — no enforcement action is taken.
const EventDLPWarn EventType = "dlp_warn"

// LogDLPWarn emits an audit event for a DLP pattern match in warn mode.
// Transport identifies the scanning surface (e.g., "fetch", "forward", "mcp_input", "body").
func (l *Logger) LogDLPWarn(ctx LogContext, patternName, severity, transport string) {
	technique := TechniqueForScanner(ScannerDLP)

	e := newLogEntry(l.zl.Warn(), EventDLPWarn).
		str("mode", "warn").
		str("pattern", patternName).
		str("severity", severity).
		str("transport", transport).
		str("mitre_technique", technique).
		str("method", ctx.Method).
		optStr("url", ctx.URL).
		optStr("target", ctx.Target).
		optStr("resource", ctx.Resource).
		optStr("client_ip", ctx.ClientIP).
		optStr("request_id", ctx.RequestID).
		optStr("agent", ctx.Agent)
	e.msg("DLP warn-mode match (informational)")

	if l.emitter != nil {
		l.emitter.Emit(context.Background(), string(EventDLPWarn), e.fields)
	}
}
