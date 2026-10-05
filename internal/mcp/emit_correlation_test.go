// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

const (
	mcpCorrHeader = "X-Correlation-Id"
	mcpCorrTag    = "mcp-case-0042"
)

type mcpCorrelationSink struct {
	mu     sync.Mutex
	events []emit.Event
}

func (s *mcpCorrelationSink) Emit(_ context.Context, ev emit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *mcpCorrelationSink) Close() error { return nil }

func (s *mcpCorrelationSink) snapshot() []emit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]emit.Event(nil), s.events...)
}

func mcpCorrelationListener(t *testing.T, correlationHeader string) (string, *mcpCorrelationSink) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(toolPoisoningToolsListResponse))
	}))
	t.Cleanup(upstream.Close)

	sink := &mcpCorrelationSink{}
	emitter := emit.NewEmitter("mcp-correlation-test", sink)
	t.Cleanup(func() { _ = emitter.Close() })
	logger := audit.NewNop()
	logger.SetEmitter(emitter)

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:           testScannerForHTTP(t),
		ToolCfg:           &tools.ToolScanConfig{Action: config.ActionBlock, DetectDrift: true},
		AuditLogger:       logger,
		CorrelationHeader: correlationHeader,
	})
	return baseURL, sink
}

// postPoisonedToolsList sends tools/list to an upstream that answers with a poisoned
// tool description, so the listener blocks the response and emits a block
// event for this HTTP request.
func postPoisonedToolsList(t *testing.T, baseURL, tag string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tag != "" {
		req.Header.Set(mcpCorrHeader, tag)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(respBody), "-32000") {
		t.Fatalf("expected tool poisoning block, got: %s", respBody)
	}
}

func TestEmitCorrelation_MCPHTTPListener(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		tag    string
		want   string
	}{
		{name: "tag carried", header: mcpCorrHeader, tag: mcpCorrTag, want: mcpCorrTag},
		{name: "header absent", header: mcpCorrHeader, tag: "", want: ""},
		{name: "feature off", header: "", tag: mcpCorrTag, want: ""},
		{name: "oversized omitted", header: mcpCorrHeader, tag: strings.Repeat("t", audit.CorrelationIDMaxBytes+1), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			baseURL, sink := mcpCorrelationListener(t, tt.header)
			postPoisonedToolsList(t, baseURL, tt.tag)
			events := sink.snapshot()
			if len(events) == 0 {
				t.Fatal("listener block emitted no events")
			}
			for _, ev := range events {
				got, ok := ev.Fields[audit.FieldCorrelationID]
				if tt.want == "" {
					if ok {
						t.Fatalf("%s carries correlation_id %v, want absent", ev.Type, got)
					}
					continue
				}
				if got != tt.want {
					t.Fatalf("%s correlation_id = %v, want %q; fields=%v", ev.Type, got, tt.want, ev.Fields)
				}
			}
		})
	}
}

// Requests on one listener must not share a tag: the per-request logger copy
// is scoped to its own HTTP request.
func TestEmitCorrelation_MCPHTTPListenerPerRequest(t *testing.T) {
	t.Parallel()
	baseURL, sink := mcpCorrelationListener(t, mcpCorrHeader)
	postPoisonedToolsList(t, baseURL, mcpCorrTag)
	first := len(sink.snapshot())
	postPoisonedToolsList(t, baseURL, "")
	events := sink.snapshot()
	if first == 0 || len(events) <= first {
		t.Fatalf("event counts first=%d total=%d, want both requests to emit", first, len(events))
	}
	for _, ev := range events[first:] {
		if got, ok := ev.Fields[audit.FieldCorrelationID]; ok {
			t.Fatalf("second request inherited correlation_id %v from the first", got)
		}
	}
}
