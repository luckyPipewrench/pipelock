// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func buildToolPolicyCfg(cfg *config.Config) *policy.Config {
	if cfg == nil || !cfg.MCPToolPolicy.Enabled {
		return nil
	}
	return policy.New(cfg.MCPToolPolicy)
}

func buildMCPInputCfg(cfg *config.Config) *mcp.InputScanConfig {
	if cfg == nil {
		return nil
	}
	if !cfg.MCPInputScanning.Enabled && cfg.MCPInputScanning.ResponseTimeoutSeconds <= 0 {
		return nil
	}
	return &mcp.InputScanConfig{
		Enabled:                cfg.MCPInputScanning.Enabled,
		Action:                 cfg.MCPInputScanning.Action,
		OnParseError:           cfg.MCPInputScanning.OnParseError,
		ResponseTimeoutSeconds: cfg.MCPInputScanning.ResponseTimeoutSeconds,
	}
}

func buildMCPToolCfg(
	cfg *config.Config,
	extraPoison []*tools.ExtraPoisonPattern,
	baseline *tools.ToolBaseline,
) *tools.ToolScanConfig {
	if cfg == nil || !cfg.MCPToolScanning.Enabled {
		return nil
	}
	toolCfg := &tools.ToolScanConfig{
		Baseline:    baseline,
		Action:      cfg.MCPToolScanning.Action,
		DetectDrift: cfg.MCPToolScanning.DetectDrift,
		ExtraPoison: extraPoison,
	}
	if cfg.MCPSessionBinding.Enabled {
		toolCfg.BindingUnknownAction = cfg.MCPSessionBinding.UnknownToolAction
		toolCfg.BindingNoBaselineAction = cfg.MCPSessionBinding.NoBaselineAction
	}
	return toolCfg
}

func buildMCPChainMatcher(cfg *config.Config, m *metrics.Metrics) *chains.Matcher {
	if cfg == nil || !cfg.ToolChainDetection.Enabled {
		return nil
	}
	return chains.New(&cfg.ToolChainDetection).WithMetrics(m)
}

func buildMCPCEE(cfg *config.Config, m *metrics.Metrics) *mcp.CEEDeps {
	if cfg == nil || !cfg.CrossRequestDetection.Enabled {
		return nil
	}
	ceeCfg := cfg.CrossRequestDetection
	deps := &mcp.CEEDeps{Config: &ceeCfg, Metrics: m}
	if ceeCfg.EntropyBudget.Enabled {
		deps.Tracker = scanner.NewEntropyTracker(
			ceeCfg.EntropyBudget.BitsPerWindow,
			ceeCfg.EntropyBudget.WindowMinutes*60,
		)
	}
	if ceeCfg.FragmentReassembly.Enabled {
		deps.Buffer = scanner.NewFragmentBuffer(
			ceeCfg.FragmentReassembly.MaxBufferBytes,
			10000,
			ceeCfg.FragmentReassembly.WindowMinutes*60,
		)
	}
	return deps
}
