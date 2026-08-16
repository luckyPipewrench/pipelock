// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import "testing"

func TestMustMCPAuditContextFallsBackWithoutResource(t *testing.T) {
	t.Parallel()

	ctx := mustMCPAuditContext(nil, "tools/call", "")
	if ctx.Method() != "tools/call" {
		t.Fatalf("fallback method = %q", ctx.Method())
	}
	if ctx.Resource() != "" {
		t.Fatalf("fallback resource = %q, want empty method context", ctx.Resource())
	}

	ctx = mustMCPAuditContext(nil, "tools/call", "fetch_url")
	if ctx.Method() != "tools/call" || ctx.Resource() != "fetch_url" {
		t.Fatalf("valid context = method=%q resource=%q", ctx.Method(), ctx.Resource())
	}
}
