// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// requestCorrelation reads and vets the operator-configured
// emit.correlation_header from r. It returns the zero value when the feature
// is off or the value fails any hygiene check; it never blocks the request.
func requestCorrelation(r *http.Request, cfg *config.Config, sc *scanner.Scanner) audit.CorrelationID {
	if r == nil || cfg == nil {
		return audit.CorrelationID{}
	}
	return audit.CorrelationIDFromHeader(r.Context(), r.Header, cfg.Emit.CorrelationHeader, sc)
}

// withCorrelation attaches a vetted correlation tag to a context so every
// audit context built from it by newHTTPAuditContext/newConnectAuditContext
// carries the tag into emitted events. A zero id leaves parent unchanged.
func withCorrelation(parent context.Context, id audit.CorrelationID) context.Context {
	if id.IsZero() {
		return parent
	}
	return context.WithValue(parent, ctxKeyCorrelation, id)
}

// attachRequestCorrelation vets the configured header on r and, when it
// passes, returns r with the tag on its context alongside the tag itself.
func attachRequestCorrelation(r *http.Request, cfg *config.Config, sc *scanner.Scanner) (*http.Request, audit.CorrelationID) {
	id := requestCorrelation(r, cfg, sc)
	if id.IsZero() {
		return r, id
	}
	return r.WithContext(withCorrelation(r.Context(), id)), id
}

// correlationFromContext returns the tag attached by withCorrelation, if any.
func correlationFromContext(ctx context.Context) audit.CorrelationID {
	if ctx == nil {
		return audit.CorrelationID{}
	}
	id, _ := ctx.Value(ctxKeyCorrelation).(audit.CorrelationID)
	return id
}
