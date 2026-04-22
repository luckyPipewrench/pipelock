// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestEmitResolveInfoLogs(t *testing.T) {
	t.Run("all branches fired", func(t *testing.T) {
		var buf bytes.Buffer
		emitResolveInfoLogs(&buf, config.ResolveRuntimeInfo{
			ResponseScanningFallback:    true,
			MCPInputScanningAutoEnabled: true,
			MCPToolScanningAutoEnabled:  true,
			MCPToolPolicyAutoEnabled:    true,
		}, "proxy")

		want := []string{
			"warning: response scanning was disabled in config, enabling with defaults",
			"pipelock: auto-enabling MCP input scanning for proxy mode",
			"pipelock: auto-enabling MCP tool scanning for proxy mode",
			"pipelock: auto-enabling MCP tool call policy for proxy mode",
		}
		got := buf.String()
		for _, line := range want {
			if !strings.Contains(got, line) {
				t.Errorf("missing log line %q in output:\n%s", line, got)
			}
		}
	})

	t.Run("no branches fired", func(t *testing.T) {
		var buf bytes.Buffer
		emitResolveInfoLogs(&buf, config.ResolveRuntimeInfo{}, "proxy")
		if buf.Len() != 0 {
			t.Errorf("expected empty output, got:\n%s", buf.String())
		}
	})

	t.Run("mode label interpolated", func(t *testing.T) {
		var buf bytes.Buffer
		emitResolveInfoLogs(&buf, config.ResolveRuntimeInfo{
			MCPInputScanningAutoEnabled: true,
		}, "listener")
		if !strings.Contains(buf.String(), "for listener mode") {
			t.Errorf("mode label not interpolated; got:\n%s", buf.String())
		}
	})

	t.Run("only response fallback fires", func(t *testing.T) {
		var buf bytes.Buffer
		emitResolveInfoLogs(&buf, config.ResolveRuntimeInfo{
			ResponseScanningFallback: true,
		}, "proxy")
		out := buf.String()
		if !strings.Contains(out, "warning: response scanning was disabled") {
			t.Errorf("expected response-fallback line, got:\n%s", out)
		}
		if strings.Contains(out, "auto-enabling MCP") {
			t.Errorf("unexpected auto-enable line when only fallback fired; got:\n%s", out)
		}
	})

	t.Run("only tool scanning fires", func(t *testing.T) {
		var buf bytes.Buffer
		emitResolveInfoLogs(&buf, config.ResolveRuntimeInfo{
			MCPToolScanningAutoEnabled: true,
		}, "proxy")
		out := buf.String()
		if !strings.Contains(out, "auto-enabling MCP tool scanning for proxy mode") {
			t.Errorf("expected tool-scanning line, got:\n%s", out)
		}
		if strings.Contains(out, "tool call policy") || strings.Contains(out, "input scanning") {
			t.Errorf("unexpected additional branches fired; got:\n%s", out)
		}
	})
}
