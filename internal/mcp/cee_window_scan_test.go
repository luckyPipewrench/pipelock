// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const ceeWindowMCPBodyBytes = 65536

func TestCEERequestBatch_MCPArguments(t *testing.T) {
	for _, suffix := range []string{"BBBBBBBB", "BBBBBBB7"} {
		t.Run(suffix, func(t *testing.T) {
			cfg := ceeWindowMCPConfig(t, config.ActionBlock, 64)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			cee := NewCEEDeps(cfg.CrossRequestDetection, metrics.New())
			t.Cleanup(cee.Close)
			opts := MCPProxyOpts{Scanner: sc, CEE: cee}
			call := func(args map[string]string) httpInputDecision {
				t.Helper()
				msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "transfer", "arguments": args}})
				if err != nil {
					t.Fatal(err)
				}
				return scanHTTPInputDecision(msg, io.Discard, "batch-session", "batch-session", opts)
			}
			if result := call(map[string]string{"z": "CTOKBBBB"}); result.Blocked != nil {
				t.Fatalf("clean first call blocked: %+v", result)
			}
			result := call(map[string]string{"a": strings.Repeat("x", 56), "z": suffix})
			if (result.Blocked != nil) != (suffix == "BBBBBBBB") {
				t.Fatalf("completing call blocked=%t for suffix %q", result.Blocked != nil, suffix)
			}
		})
	}
}

func TestCeeRecordMCP_ScansCompletingLeafBeforeRetention(t *testing.T) {
	secret := "CTOK" + strings.Repeat("B", 12)
	first := strings.Repeat("x", ceeWindowMCPBodyBytes-8) + secret[:8]
	second := secret[8:] + strings.Repeat("x", ceeWindowMCPBodyBytes-8)

	for _, tc := range []struct {
		name   string
		cap    int
		action string
		block  bool
	}{
		{name: "default cap blocks", action: config.ActionBlock, block: true},
		{name: "lower cap warns", cap: ceeWindowMCPBodyBytes / 2, action: config.ActionWarn},
		{name: "raised cap blocks", cap: ceeWindowMCPBodyBytes * 2, action: config.ActionBlock, block: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ceeWindowMCPConfig(t, tc.action, tc.cap)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			cee := NewCEEDeps(cfg.CrossRequestDetection, metrics.New())
			t.Cleanup(cee.Close)

			if reason, log := ceeWindowMCPRecord(cee, sc, first); reason != "" || strings.Contains(log, "cross-request fragment DLP match") {
				t.Fatalf("first individually clean MCP leaf blocked: %s", reason)
			}
			reason, log := ceeWindowMCPRecord(cee, sc, second)
			if tc.block && !strings.Contains(reason, "cross-request fragment DLP match") {
				t.Fatalf("completing MCP leaf reason = %q, want block", reason)
			}
			if !tc.block && reason != "" {
				t.Fatalf("warn-mode completing MCP leaf blocked: %q", reason)
			}
			if !strings.Contains(log, "cross-request fragment DLP match") {
				t.Fatalf("completing MCP leaf produced no CEE match evidence: %q", log)
			}
			_, buffer := cee.Components()
			if buffer == nil {
				t.Fatal("configured MCP fragment buffer is nil")
			}
			if retained := buffer.TotalBufferBytes(); retained > 2*cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes {
				t.Fatalf("retained MCP leaf bytes = %d, exceed two production leaf streams at cap %d", retained, cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes)
			}
		})
	}
}

func TestCeeRecordMCP_DoesNotMatchNearMissAcrossLeaves(t *testing.T) {
	cfg := ceeWindowMCPConfig(t, config.ActionBlock, 0)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	cee := NewCEEDeps(cfg.CrossRequestDetection, metrics.New())
	t.Cleanup(cee.Close)

	first := strings.Repeat("x", ceeWindowMCPBodyBytes-8) + "CTOKBBBB"
	second := "BBBBBBB7" + strings.Repeat("x", ceeWindowMCPBodyBytes-8)
	if reason, log := ceeWindowMCPRecord(cee, sc, first); reason != "" || strings.Contains(log, "cross-request fragment DLP match") {
		t.Fatalf("first near-miss MCP leaf blocked: %s", reason)
	}
	if reason, log := ceeWindowMCPRecord(cee, sc, second); reason != "" || strings.Contains(log, "cross-request fragment DLP match") {
		t.Fatalf("near-miss MCP leaves blocked: %s", reason)
	}
}

func ceeWindowMCPConfig(t *testing.T, action string, bufferLimit int) *config.Config {
	t.Helper()
	var maxBuffer string
	if bufferLimit > 0 {
		maxBuffer = "    max_buffer_bytes: " + strconv.Itoa(bufferLimit) + "\n"
	}
	cfg, err := config.LoadBytes([]byte("dlp:\n  patterns:\n    - name: Boundary token\n      regex: 'CTOK[A-Z]{12}'\n      severity: high\ncross_request_detection:\n  enabled: true\n  action: " + action + "\n  entropy_budget:\n    enabled: false\n  fragment_reassembly:\n    enabled: true\n" + maxBuffer))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if bufferLimit == 0 && cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes != ceeWindowMCPBodyBytes {
		t.Fatalf("default max_buffer_bytes = %d, want %d", cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes, ceeWindowMCPBodyBytes)
	}
	cfg.Internal = nil
	return cfg
}

func ceeWindowMCPRecord(cee *CEEDeps, sc *scanner.Scanner, payload string) (string, string) {
	var log bytes.Buffer
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: "window-session", entropyPayload: []byte(payload),
		fragmentPayloads: map[string][]byte{"@tool/transfer/args$/payload": []byte(payload)},
		cee:              cee, sc: sc, logW: &log,
	})
	return reason, log.String()
}
