// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

func TestMCPCEEFragmentPayloadsReportsFallbackReason(t *testing.T) {
	secret := "AKI" + "AIOSFODNN7EXAMPLE"
	longTool := strings.Repeat("t", 700) // overflows the tool-qualified stream key
	tests := []struct {
		name       string
		frame      MCPFrame
		wantReason string
	}{
		{
			name: "partitioned tools call reports no fallback",
			frame: MCPFrame{
				Method: methodToolsCall, ToolCallName: "integrity_checker",
				Args: json.RawMessage(`{"a":"` + secret + `"}`), Raw: []byte("raw"),
			},
			wantReason: "",
		},
		{
			name:       "non tools call reports no fallback",
			frame:      MCPFrame{Method: "tools/list", Raw: []byte("raw")},
			wantReason: "",
		},
		{
			name: "malformed arguments report malformed",
			frame: MCPFrame{
				Method: methodToolsCall, ToolCallName: "integrity_checker",
				Args: json.RawMessage(`{"a":"unterminated`), Raw: []byte("raw"),
			},
			wantReason: mcpCEEPartitionReasonMalformed,
		},
		{
			name: "oversize tool stream key reports limit",
			frame: MCPFrame{
				Method: methodToolsCall, ToolCallName: longTool,
				Args: json.RawMessage(`{"a":"` + secret + `"}`), Raw: []byte("raw"),
			},
			wantReason: mcpCEEPartitionReasonLimit,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, reason := mcpCEEFragmentPayloads(tt.frame)
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// ceeRecordMCP must emit the shared partition-fallback counter when a tools/call
// frame degrades to raw-frame scanning, and must not move it on a clean
// partition. Both directions are asserted so the counter is not vacuous.
func TestCeeRecordMCPRecordsPartitionFallback(t *testing.T) {
	secret := "AKI" + "AIOSFODNN7EXAMPLE"
	newDeps := func() (*CEEDeps, *metrics.Metrics) {
		m := metrics.New()
		cee := NewCEEDeps(config.CrossRequestDetection{
			Enabled: true,
			Action:  config.ActionBlock,
			FragmentReassembly: config.CrossRequestFragments{
				Enabled: true, MaxBufferBytes: 4096, WindowMinutes: 5,
			},
		}, m)
		t.Cleanup(cee.Close)
		return cee, m
	}
	sc := testMCPScanner()
	t.Cleanup(sc.Close)

	fallback := func(m *metrics.Metrics, reason string) float64 {
		return testutil.ToFloat64(m.CrossRequestJSONPartitionFallback.WithLabelValues(reason))
	}

	t.Run("malformed arguments increment malformed", func(t *testing.T) {
		cee, m := newDeps()
		frame := MCPFrame{
			Method: methodToolsCall, ToolCallName: "integrity_checker",
			Args: json.RawMessage(`{"a":"unterminated`), Raw: []byte(`{"a":"x"}`),
		}
		var logBuf bytes.Buffer
		ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, frame: frame, cee: cee, sc: sc, logW: &logBuf})
		if got := fallback(m, "malformed"); got != 1 {
			t.Fatalf("malformed fallback = %v, want 1", got)
		}
	})

	t.Run("oversize tool stream key increments other", func(t *testing.T) {
		cee, m := newDeps()
		frame := MCPFrame{
			Method: methodToolsCall, ToolCallName: strings.Repeat("t", 700),
			Args: json.RawMessage(`{"a":"` + secret + `"}`), Raw: []byte(`{"a":"x"}`),
		}
		var logBuf bytes.Buffer
		ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, frame: frame, cee: cee, sc: sc, logW: &logBuf})
		if got := fallback(m, "other"); got != 1 {
			t.Fatalf("limit fallback = %v, want 1", got)
		}
	})

	t.Run("clean partition does not move the counter", func(t *testing.T) {
		cee, m := newDeps()
		frame := MCPFrame{
			Method: methodToolsCall, ToolCallName: "integrity_checker",
			Args: json.RawMessage(`{"a":"harmless"}`), Raw: []byte(`{"a":"harmless"}`),
		}
		var logBuf bytes.Buffer
		ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, frame: frame, cee: cee, sc: sc, logW: &logBuf})
		for _, reason := range []string{"malformed", "incomplete", "unkeyed", "other"} {
			if got := fallback(m, reason); got != 0 {
				t.Fatalf("clean partition moved %q counter to %v, want 0", reason, got)
			}
		}
	})
}

// A single non-empty argument among exactly the maximum number of leaf streams
// qualifies for the tool-level singleton stream, and adding it would exceed the
// stream bound, so the frame degrades to the raw stream with the limit reason.
func TestMCPCEEFragmentPayloadsSingletonStreamLimit(t *testing.T) {
	secret := "AKI" + "AIOSFODNN7EXAMPLE"
	var b strings.Builder
	b.WriteString(`{"v":"` + secret + `"`)
	for i := 1; i < mcpCEEArgumentMaxStreams; i++ {
		b.WriteString(`,"e` + strconv.Itoa(i) + `":""`)
	}
	b.WriteString(`}`)
	frame := MCPFrame{Method: methodToolsCall, ToolCallName: "integrity_checker", Args: json.RawMessage(b.String()), Raw: []byte(`raw`)}
	payloads, reason := mcpCEEFragmentPayloads(frame)
	if reason != mcpCEEPartitionReasonLimit {
		t.Fatalf("reason = %q, want %q", reason, mcpCEEPartitionReasonLimit)
	}
	if got := string(payloads[""]); got != "raw" {
		t.Fatalf("payloads = %#v, want the raw frame only", payloads)
	}
}
