// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import "context"

// DLPWarnContext carries per-request metadata for DLP warn emission.
type DLPWarnContext struct {
	Method    string
	URL       string
	Target    string
	Resource  string
	ClientIP  string
	RequestID string
	Agent     string
	Transport string // "fetch", "forward", "connect", "intercept", "reverse", "websocket", "mcp_stdio", "mcp_http"
}

type dlpWarnCtxKey struct{}

// WithDLPWarnContext attaches DLP warn metadata to a context.
func WithDLPWarnContext(ctx context.Context, wc DLPWarnContext) context.Context {
	return context.WithValue(ctx, dlpWarnCtxKey{}, wc)
}

// DLPWarnContextFromCtx extracts DLP warn metadata from a context.
// Returns zero value if not set.
func DLPWarnContextFromCtx(ctx context.Context) DLPWarnContext {
	wc, _ := ctx.Value(dlpWarnCtxKey{}).(DLPWarnContext)
	return wc
}
