// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

// AuthorityVerification carries non-secret facts about an external grant
// check. Reference is the verifier's validated public identifier, never the
// opaque carrier value supplied by the client.
type AuthorityVerification struct {
	Transport string
	Decision  string
	Reason    string
	Issuer    string
	Reference string
}

// NewAuthorityVerification constructs the shared audit representation of an
// external authority result. When a verifier or transport fails without a
// machine-readable reason, the error remains available as audit evidence.
func NewAuthorityVerification(transport, decision, reason, issuer, reference string, err error) AuthorityVerification {
	if err != nil && reason == "" {
		reason = err.Error()
	}
	return AuthorityVerification{
		Transport: transport,
		Decision:  decision,
		Reason:    reason,
		Issuer:    issuer,
		Reference: reference,
	}
}

// LogAuthorityVerification records each enabled authority check independently
// from ordinary allow/block receipts. Authority checks are audit-only on
// success and do not alter receipt or mediation-envelope schemas.
func (l *Logger) LogAuthorityVerification(ctx LogContext, verification AuthorityVerification) {
	level := l.zl.Warn()
	message := "authority verification denied"
	action := "block"
	if verification.Decision == "allow" {
		level = l.zl.Info()
		message = "authority verification allowed"
		action = "allow"
	}

	e := newLogEntry(level, EventAuthorityVerification).
		str("transport", verification.Transport).
		str("action", action).
		str("decision", verification.Decision).
		optStr("reason", verification.Reason).
		optStr("issuer", verification.Issuer).
		optStr("reference", verification.Reference).
		str("method", ctx.Method()).
		optStr("url", ctx.URL()).
		optStr("target", ctx.Target()).
		optStr("resource", ctx.Resource()).
		optStr("client_ip", ctx.ClientIP()).
		optStr("request_id", ctx.RequestID()).
		optStr("agent", ctx.Agent())
	e.msg(message)

	if l.emitter != nil {
		severity := emit.SeverityWarn
		if verification.Decision == "allow" {
			severity = emit.SeverityInfo
		}
		l.emitter.EmitWithSeverity(context.Background(), severity, string(EventAuthorityVerification), e.fields)
	}
}
