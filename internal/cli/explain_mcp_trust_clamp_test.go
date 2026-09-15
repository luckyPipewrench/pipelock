// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestBuildMCPExplainReport_ReasoningTrustDoesNotRelaxBlockSection pins the
// operator-facing path: a reasoning-class server under a block section must be
// reported as blocked, not allowed-with-a-warn note.
func TestBuildMCPExplainReport_ReasoningTrustDoesNotRelaxBlockSection(t *testing.T) {
	cfg := config.Defaults()
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{
		{Server: "code-assistant", Trust: config.ResponseTrustReasoning},
	}

	report, err := buildMCPExplainReport(cfg, "code-assistant", []byte(mcpSolicitation))
	if err != nil {
		t.Fatalf("buildMCPExplainReport: %v", err)
	}
	if report.Action != config.ActionBlock {
		t.Fatalf("report action = %q, want %q", report.Action, config.ActionBlock)
	}
	if report.Allowed {
		t.Fatalf("reasoning trust under a block section must not report allowed: %+v", report)
	}
	for _, note := range report.Notes {
		if note == "MCP response trust class "+config.ResponseTrustReasoning+" maps this finding to warn; runtime forwards the response and logs the match." {
			t.Fatal("explain must not claim the response is forwarded when the section action blocks")
		}
	}
}

// TestBuildMCPExplainReport_AgreesWithProxyScanPath is the divergence guard.
// It runs the same fixture through the explain report and through the scan
// path the runtime proxy uses, across the trust/section combinations that the
// clamp governs, and requires the two to report the same effective action. If
// explain and the proxy ever disagree, the command misleads the operator.
func TestBuildMCPExplainReport_AgreesWithProxyScanPath(t *testing.T) {
	tests := []struct {
		name          string
		trust         string
		sectionAction string
		want          string
	}{
		{"reasoning under block", config.ResponseTrustReasoning, config.ActionBlock, config.ActionBlock},
		{"reasoning under warn", config.ResponseTrustReasoning, config.ActionWarn, config.ActionWarn},
		{"untrusted under warn", config.ResponseTrustUntrusted, config.ActionWarn, config.ActionBlock},
		{"untrusted under block", config.ResponseTrustUntrusted, config.ActionBlock, config.ActionBlock},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newCfg := func() *config.Config {
				c := config.Defaults()
				c.Internal = nil
				c.ResponseScanning.Action = tc.sectionAction
				c.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{
					{Server: "code-assistant", Trust: tc.trust},
				}
				return c
			}

			report, err := buildMCPExplainReport(newCfg(), "code-assistant", []byte(mcpSolicitation))
			if err != nil {
				t.Fatalf("buildMCPExplainReport: %v", err)
			}

			proxyCfg := newCfg()
			sc := scanner.MustNew(proxyCfg)
			t.Cleanup(sc.Close)
			verdict := mcp.ScanResponseOpts([]byte(mcpSolicitation), sc, mcp.ResponseScanOptions{
				ActionOverride: proxyCfg.MCPResponseActionForServer("code-assistant"),
				TrustClass:     tc.trust,
			})

			if verdict.Clean {
				t.Fatal("fixture must produce a finding on the proxy path")
			}
			if verdict.Action != tc.want {
				t.Fatalf("proxy action = %q, want %q", verdict.Action, tc.want)
			}
			if report.Action != verdict.Action {
				t.Fatalf("explain reports %q but the proxy applies %q", report.Action, verdict.Action)
			}
		})
	}
}
