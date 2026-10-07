// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
)

// LogWSOpen logs a WebSocket proxy connection establishment.
func (l *Logger) LogWSOpen(target, clientIP, requestID, agent string) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventWSOpen).
		str("target", target).
		str("client_ip", clientIP).
		str("request_id", requestID).
		agentField(agent, string(envelope.ActorAuthUnknown))
	e.msg("websocket opened")

	if l.emitter != nil {
		l.emitEvent(string(EventWSOpen), e.fields)
	}
}

// WSCloseEvent bundles the per-event fields LogWSClose emits.
type WSCloseEvent struct {
	Target    string
	ClientIP  string
	RequestID string
	Agent     string
	// AgentAuth is how the agent label was established. It travels with the
	// label so the pair is emitted together; an empty value is recorded as the
	// fail-closed unknown grade rather than omitted.
	AgentAuth      string
	ClientToServer int64
	ServerToClient int64
	TextFrames     int64
	BinaryFrames   int64
	Duration       time.Duration
}

// LogWSClose logs a WebSocket proxy connection teardown with traffic stats.
func (l *Logger) LogWSClose(ev WSCloseEvent) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventWSClose).
		str("target", ev.Target).
		str("client_ip", ev.ClientIP).
		str("request_id", ev.RequestID).
		agentField(ev.Agent, ev.AgentAuth).
		int64Field("client_to_server_bytes", ev.ClientToServer).
		int64Field("server_to_client_bytes", ev.ServerToClient).
		int64Field("text_frames", ev.TextFrames).
		int64Field("binary_frames", ev.BinaryFrames).
		durMS(ev.Duration)
	e.msg("websocket closed")

	if l.emitter != nil {
		l.emitEvent(string(EventWSClose), e.fields)
	}
}

// WSBlockedEvent bundles the per-event fields LogWSBlocked emits.
//
// This is a struct rather than a parameter list because the event needs the
// agent label and its provenance grade, and a block decision is exactly where
// an auditor needs to know whether the label was infrastructure-bound or merely
// caller-supplied. Adding two more positional parameters would have pushed the
// call past the project's six-parameter limit at twenty-one call sites.
type WSBlockedEvent struct {
	Target    string
	Direction string
	Scanner   string
	Reason    string
	ClientIP  string
	RequestID string
	Agent     string
	// AgentAuth is how the agent label was established. An empty value is
	// recorded as the fail-closed unknown grade.
	AgentAuth string
}

// LogWSBlocked logs a blocked WebSocket frame or connection.
func (l *Logger) LogWSBlocked(ev WSBlockedEvent) {
	target, direction, scannerName := ev.Target, ev.Direction, ev.Scanner
	reason, clientIP, requestID := ev.Reason, ev.ClientIP, ev.RequestID
	technique := TechniqueForScanner(scannerName)

	e := newLogEntry(l.zl.Warn(), EventWSBlocked).
		str("target", target).
		str("direction", direction).
		str("scanner", scannerName).
		str("reason", reason).
		str("client_ip", clientIP).
		str("request_id", requestID).
		agentField(ev.Agent, ev.AgentAuth).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerName, reason)).
		optStr("mitre_technique", technique)

	// includeBlocked gates local audit log only - external emission always fires.
	if l.includeBlocked {
		e.msg("websocket blocked")
	}
	if l.emitter != nil {
		l.emitEvent(string(EventWSBlocked), e.fields)
	}
}

// WSScanEvent bundles the per-event fields LogWSScan emits.
// Direction is one of DirectionClientToServer / DirectionServerToClient.
type WSScanEvent struct {
	Target    string
	Direction string
	ClientIP  string
	RequestID string
	Agent     string
	// AgentAuth is how the agent label was established. See WSCloseEvent.
	AgentAuth    string
	Action       string
	Scanner      string
	MatchCount   int
	PatternNames []string
	BundleRules  []BundleRuleHit
}

// LogWSScan logs a WebSocket frame scan hit (warn/strip action).
// Direction determines the MITRE technique: client_to_server is DLP/exfil (T1048),
// server_to_client is prompt injection detection (T1059).
// When BundleRules is non-empty, bundle provenance is included in the audit event.
func (l *Logger) LogWSScan(ev WSScanEvent) {
	scanner := ev.Scanner
	if scanner == "" {
		scanner = scannerpkg.AuditResponseScan
		if ev.Direction == DirectionClientToServer {
			scanner = scannerpkg.ScannerDLP
		}
	}
	technique := TechniqueForScanner(scanner)
	ctx := LogContext{target: ev.Target}
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, scanner)

	e := newLogEntry(l.zl.Warn(), EventWSScan).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		str("direction", ev.Direction).
		str("client_ip", ev.ClientIP).
		str("request_id", ev.RequestID).
		agentField(ev.Agent, ev.AgentAuth).
		str("action", ev.Action).
		str("scanner", scanner).
		intField("match_count", ev.MatchCount).
		strs("patterns", ev.PatternNames).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scanner, strings.Join(ev.PatternNames, ", "))).
		str("mitre_technique", technique)
	if len(ev.BundleRules) > 0 {
		e.bundleRulesField(ev.BundleRules)
	}
	e.msg("websocket scan hit")

	if l.emitter != nil {
		l.emitEvent(string(EventWSScan), e.fields)
	}
}

// LogSessionAnomaly logs a session behavioral anomaly detection.
// copyRemediationHint copies remediation_hint from a log entry's fields into an
// external-emitter fields map when the entry set one, so the emitted event and
// the structured log carry the same operator guidance.
