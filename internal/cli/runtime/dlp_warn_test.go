// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestDLPWarnLogContext_PrefersHTTPForInterceptedRequests(t *testing.T) {
	wc := scanner.DLPWarnContext{
		Method:    http.MethodPost,
		URL:       "https://api.example.com/v1/tools/call",
		Target:    "api.example.com:443",
		ClientIP:  "10.0.0.1",
		RequestID: "req-intercept",
		Agent:     "agent-1",
		Transport: "intercept",
	}

	ctx, err := dlpWarnLogContext(wc)
	if err != nil {
		t.Fatalf("dlpWarnLogContext: %v", err)
	}
	if got := ctx.Method(); got != http.MethodPost {
		t.Fatalf("method = %q, want %q", got, http.MethodPost)
	}
	if got := ctx.URL(); got != wc.URL {
		t.Fatalf("url = %q, want %q", got, wc.URL)
	}
	if got := ctx.Target(); got != "" {
		t.Fatalf("target = %q, want empty", got)
	}
	if got := ctx.RequestID(); got != wc.RequestID {
		t.Fatalf("requestID = %q, want %q", got, wc.RequestID)
	}
}

func TestDLPWarnLogContext_UsesConnectForConnectRequests(t *testing.T) {
	wc := scanner.DLPWarnContext{
		Method:    http.MethodConnect,
		URL:       "https://api.example.com/",
		Target:    "api.example.com:443",
		ClientIP:  "10.0.0.2",
		RequestID: "req-connect",
		Agent:     "agent-2",
		Transport: "connect",
	}

	ctx, err := dlpWarnLogContext(wc)
	if err != nil {
		t.Fatalf("dlpWarnLogContext: %v", err)
	}
	if got := ctx.Method(); got != http.MethodConnect {
		t.Fatalf("method = %q, want %q", got, http.MethodConnect)
	}
	if got := ctx.Target(); got != wc.Target {
		t.Fatalf("target = %q, want %q", got, wc.Target)
	}
	if got := ctx.URL(); got != "" {
		t.Fatalf("url = %q, want empty", got)
	}
	if got := ctx.ClientIP(); got != wc.ClientIP {
		t.Fatalf("clientIP = %q, want %q", got, wc.ClientIP)
	}
}

func TestDLPWarnLogContext_FallsBackWhenConstructorErrors(t *testing.T) {
	wc := scanner.DLPWarnContext{
		Method:    http.MethodGet,
		Transport: "fetch",
		RequestID: "req-fallback",
	}

	ctx, err := dlpWarnLogContext(wc)
	if err == nil {
		t.Fatal("expected constructor error for missing URL/client metadata")
	}
	if ctx != (audit.LogContext{}) {
		t.Fatalf("expected zero log context on constructor error, got %+v", ctx)
	}

	fallback := dlpWarnFallbackLogContext(wc)
	if got := fallback.RequestID(); got != wc.RequestID {
		t.Fatalf("fallback requestID = %q, want %q", got, wc.RequestID)
	}
}

func TestDLPWarnLogContext_UsesMCPForMCPTransport(t *testing.T) {
	wc := scanner.DLPWarnContext{
		Method:    "MCP",
		Resource:  "tools/call",
		Agent:     "agent-3",
		Transport: "mcp_http",
	}

	ctx, err := dlpWarnLogContext(wc)
	if err != nil {
		t.Fatalf("dlpWarnLogContext: %v", err)
	}
	if got := ctx.Method(); got != wc.Method {
		t.Fatalf("method = %q, want %q", got, wc.Method)
	}
	if got := ctx.Resource(); got != wc.Resource {
		t.Fatalf("resource = %q, want %q", got, wc.Resource)
	}
	if got := ctx.Target(); got != "" {
		t.Fatalf("target = %q, want empty", got)
	}
}
