// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const mcpToolsCallResource = "tools/call"

func TestEmitDLPWarnWritesReceiptAndMetric(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New(): %v", err)
	}
	t.Cleanup(func() {
		if closeErr := rec.Close(); closeErr != nil {
			t.Fatalf("rec.Close(): %v", closeErr)
		}
	})

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "cfg-hash",
		Actor:      "agent-1",
	})
	if emitter == nil {
		t.Fatal("receipt.NewEmitter() returned nil")
	}

	m := metrics.New()
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodGet,
		URL:       "https://example.com/api",
		ClientIP:  "10.0.0.1",
		RequestID: "req-warn-1",
		Agent:     "agent-1",
		Transport: "fetch",
	})

	emitDLPWarn(audit.NewNop(), m, emitter, ctx, "warn-url", "high")

	result, err := recorder.QuerySession(dir, "proxy", &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatalf("QuerySession(): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("receipt entry count = %d, want 1", len(result.Entries))
	}

	detailJSON, err := json.Marshal(result.Entries[0].Detail)
	if err != nil {
		t.Fatalf("jsonMarshal(detail): %v", err)
	}
	rcpt, err := receipt.Unmarshal(detailJSON)
	if err != nil {
		t.Fatalf("receipt.Unmarshal(): %v", err)
	}
	if rcpt.ActionRecord.Verdict != "warn" {
		t.Fatalf("receipt verdict = %q, want warn", rcpt.ActionRecord.Verdict)
	}
	if rcpt.ActionRecord.Layer != scanner.ScannerDLP {
		t.Fatalf("receipt layer = %q, want %q", rcpt.ActionRecord.Layer, scanner.ScannerDLP)
	}
	if rcpt.ActionRecord.Pattern != "warn-url" {
		t.Fatalf("receipt pattern = %q, want warn-url", rcpt.ActionRecord.Pattern)
	}
	if rcpt.ActionRecord.Severity != "high" {
		t.Fatalf("receipt severity = %q, want high", rcpt.ActionRecord.Severity)
	}
	if rcpt.ActionRecord.Target != "https://example.com/api" {
		t.Fatalf("receipt target = %q, want https://example.com/api", rcpt.ActionRecord.Target)
	}

	recorderBody := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(recorderBody, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(recorderBody.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(): %v", err)
	}
	if !strings.Contains(string(body), `pipelock_dlp_warn_matches_total{pattern="warn-url",transport="fetch"} 1`) {
		t.Fatalf("metrics missing warn counter:\n%s", string(body))
	}
}

func TestDLPWarnReceiptOptsUsesMCPMethod(t *testing.T) {
	opts := dlpWarnReceiptOpts(scanner.DLPWarnContext{
		Method:    "MCP",
		Resource:  mcpToolsCallResource,
		RequestID: "req-mcp-1",
		Agent:     "agent-mcp",
		Transport: "mcp_http",
	}, "warn-tool", "medium", "mcp_http")

	if opts.MCPMethod != mcpToolsCallResource {
		t.Fatalf("opts.MCPMethod = %q, want %s", opts.MCPMethod, mcpToolsCallResource)
	}
	if opts.Target != mcpToolsCallResource {
		t.Fatalf("opts.Target = %q, want %s", opts.Target, mcpToolsCallResource)
	}
}

func TestDLPWarnReceiptOptsTargetFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		wc         scanner.DLPWarnContext
		wantTarget string
		wantMethod string
	}{
		{
			name: "resource_takes_precedence",
			wc: scanner.DLPWarnContext{
				Resource: mcpToolsCallResource,
				URL:      "https://example.com",
				Target:   "explicit-target",
				Method:   "POST",
			},
			wantTarget: mcpToolsCallResource,
			wantMethod: "",
		},
		{
			name: "url_when_no_resource",
			wc: scanner.DLPWarnContext{
				URL:    "https://example.com/api",
				Target: "explicit-target",
				Method: http.MethodGet,
			},
			wantTarget: "https://example.com/api",
			wantMethod: http.MethodGet,
		},
		{
			name: "explicit_target_when_no_resource_or_url",
			wc: scanner.DLPWarnContext{
				Target: "some-target",
				Method: http.MethodPost,
			},
			wantTarget: "some-target",
			wantMethod: http.MethodPost,
		},
		{
			name:       "transport_fallback_when_nothing_set",
			wc:         scanner.DLPWarnContext{},
			wantTarget: "fetch",
			wantMethod: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := dlpWarnReceiptOpts(tt.wc, "test-pattern", "medium", "fetch")
			if opts.Target != tt.wantTarget {
				t.Errorf("Target = %q, want %q", opts.Target, tt.wantTarget)
			}
			if opts.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", opts.Method, tt.wantMethod)
			}
		})
	}
}

func TestEmitDLPWarnNilReceiptEmitter(t *testing.T) {
	m := metrics.New()
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodGet,
		URL:       "https://example.com/nil-emitter",
		ClientIP:  "10.0.0.2",
		RequestID: "req-nil-1",
		Agent:     "agent-nil",
		Transport: "fetch",
	})

	// nil receipt emitter must not panic; only metric + audit log emitted.
	emitDLPWarn(audit.NewNop(), m, nil, ctx, "warn-nil", "low")

	recorderBody := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(recorderBody, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(recorderBody.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(): %v", err)
	}
	if !strings.Contains(string(body), `pipelock_dlp_warn_matches_total{pattern="warn-nil",transport="fetch"} 1`) {
		t.Fatalf("metrics missing warn counter:\n%s", string(body))
	}
}

func TestEmitDLPWarnNilAuditLogger(t *testing.T) {
	// Passing nil metrics does not crash either (nil-safe counter method).
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodPost,
		URL:       "https://example.com/nil-logger",
		ClientIP:  "10.0.0.3",
		RequestID: "req-nil-2",
		Transport: "forward",
	})

	// The audit logger is a nop so nothing is written. The test verifies
	// that nil receiptEmitter + nop logger does not panic.
	emitDLPWarn(audit.NewNop(), nil, nil, ctx, "warn-nop", "low")
}

func TestEmitDLPWarnMissingTransport(t *testing.T) {
	m := metrics.New()
	// Context with no Transport field set; expect fallback to "unknown".
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodGet,
		URL:       "https://example.com/no-transport",
		ClientIP:  "10.0.0.4",
		RequestID: "req-no-transport",
	})

	emitDLPWarn(audit.NewNop(), m, nil, ctx, "warn-transport", "medium")

	recorderBody := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(recorderBody, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(recorderBody.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(): %v", err)
	}
	if !strings.Contains(string(body), `pipelock_dlp_warn_matches_total{pattern="warn-transport",transport="unknown"} 1`) {
		t.Fatalf("expected transport=unknown in metrics, got:\n%s", string(body))
	}
}
