// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// LogTunnelOpen logs a CONNECT tunnel establishment.
func (l *Logger) LogTunnelOpen(ctx LogContext) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventTunnelOpen).
		optStr("target", ctx.target).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth)
	e.msg("tunnel opened")

	if l.emitter != nil {
		l.emitEvent(string(EventTunnelOpen), e.fields)
	}
}

// LogTunnelClose logs a CONNECT tunnel teardown with traffic stats.
func (l *Logger) LogTunnelClose(ctx LogContext, totalBytes int64, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventTunnelClose).
		optStr("target", ctx.target).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		int64Field("total_bytes", totalBytes).
		durMS(duration)
	e.msg("tunnel closed")

	if l.emitter != nil {
		l.emitEvent(string(EventTunnelClose), e.fields)
	}
}

// InterceptTiming describes where one TLS-intercepted request spent its time.
// Upstream is zero when the request never reached the destination.
type InterceptTiming struct {
	StatusCode      int
	SizeBytes       int64
	Duration        time.Duration
	Upstream        time.Duration
	ReachedUpstream bool
	RequestCanceled bool
}

// LogInterceptHTTP logs one TLS-intercepted request with its timing split.
// duration_ms is the whole request. upstream_ms is the wait for response
// headers, starting when the request finished sending, or when the connection
// was ready if the response arrived before the send was reported complete; it
// is absent when the request was never sent. The remainder covers request
// checks, DNS and connecting, sending when upstream_ms does not include it,
// and reading, scanning and delivering the body. The url field holds the
// destination only, never a path or query.
func (l *Logger) LogInterceptHTTP(ctx LogContext, t InterceptTiming) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventInterceptHTTP).
		str("method", ctx.method).
		optStr("url", dropURLContentSegments(ctx.url, false)).
		optStr("target", dropURLContentSegments(ctx.target, false)).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		intField("status_code", t.StatusCode).
		int64Field("size_bytes", t.SizeBytes).
		durMS(t.Duration)
	if t.ReachedUpstream {
		e.upstreamMS(t.Upstream)
	}
	e.boolField("request_canceled", t.RequestCanceled)
	e.msg("intercepted request")

	if l.emitter != nil {
		l.emitEvent(string(EventInterceptHTTP), e.fields)
	}
}

// LogForwardHTTP logs a forward proxy HTTP request (absolute-URI).
// URL and target fields retain only the destination, never request content.
func (l *Logger) LogForwardHTTP(ctx LogContext, statusCode, sizeBytes int, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventForwardHTTP).
		str("method", ctx.method).
		optStr("url", dropURLContentSegments(ctx.url, false)).
		optStr("target", dropURLContentSegments(ctx.target, false)).
		optStr("resource", ctx.resource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		intField("status_code", statusCode).
		intField("size_bytes", sizeBytes).
		durMS(duration)
	e.msg("forward proxy request")

	if l.emitter != nil {
		l.emitEvent(string(EventForwardHTTP), e.fields)
	}
}

// LogRedirect logs an observed redirect before target admission. The target
// may be refused or returned to a forward client without being dispatched.
// Both URLs retain only the destination because admission has not checked them.
func (l *Logger) LogRedirect(originalURL, redirectURL, clientIP, requestID, agent string, hop int) {
	e := newLogEntry(l.zl.Info(), EventRedirect).
		str("original_url", dropURLContentSegments(originalURL, false)).
		str("redirect_url", dropURLContentSegments(redirectURL, false)).
		str("client_ip", clientIP).
		str("request_id", requestID).
		agentField(agent, string(envelope.ActorAuthUnknown)).
		intField("hop", hop)
	e.msg("redirect observed")

	if l.emitter != nil {
		l.emitEvent(string(EventRedirect), e.fields)
	}
}

// ToolRedirectEvent bundles the per-event fields LogToolRedirect emits.
// SessionID is local-log only; the remaining fields surface to external
// emission sinks.
type ToolRedirectEvent struct {
	SessionID       string
	ToolName        string
	ArgsDigest      string
	RedirectProfile string
	RedirectReason  string
	PolicyRule      string
	Result          string
	LatencyMs       int64
}

// LogToolRedirect logs an MCP tool call redirect event. Distinct from
// LogRedirect (HTTP redirect hops). Result is "redirected" or "blocked"
// (on failure).
func (l *Logger) LogToolRedirect(ev ToolRedirectEvent) {
	e := newLogEntry(l.zl.Info(), EventToolRedirect).
		str("tool_name", ev.ToolName).
		str("args_digest", ev.ArgsDigest).
		str("redirect_profile", ev.RedirectProfile).
		str("redirect_reason", ev.RedirectReason).
		str("policy_rule", ev.PolicyRule).
		str("result", ev.Result).
		int64Field("latency_ms", ev.LatencyMs)
	// session_id is local-log only - not emitted to external sinks.
	if ev.SessionID != "" {
		e.event = e.event.Str("session_id", sanitizeString(ev.SessionID))
	}
	e.msg("tool call redirected")

	if l.emitter != nil {
		l.emitEvent(string(EventToolRedirect), e.fields)
	}
}
