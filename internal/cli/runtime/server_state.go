// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"reflect"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func (s *Server) currentConfig() *config.Config {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.cfg
}

func (s *Server) shouldSkipReload(hash string) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return hash == s.lastReloadHash && time.Since(s.lastReloadAt) < 2*time.Second
}

func (s *Server) recordReloadSuccess(hash string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lastReloadHash = hash
	s.lastReloadAt = time.Now()
}

func (s *Server) currentToolPolicyCfg() *policy.Config {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.toolPolicyCfg
}

func (s *Server) currentMCPChainMatcher() *chains.Matcher {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.mcpChainMatcher
}

func (s *Server) currentMCPCEE() *mcp.CEEDeps {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.mcpCEE
}

func (s *Server) currentMCPToolExtraPoison() []*tools.ExtraPoisonPattern {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if len(s.mcpToolExtraPoison) == 0 {
		return nil
	}
	return append([]*tools.ExtraPoisonPattern(nil), s.mcpToolExtraPoison...)
}

func (s *Server) refreshRuntimeState(
	oldCfg, newCfg *config.Config,
	bundleResult *rules.LoadResult,
	liveScanner *scanner.Scanner,
) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	s.cfg = newCfg
	if liveScanner != nil {
		s.scanner = liveScanner
	}
	s.bundleResult = bundleResult
	s.receiptEmitter = s.liveReceiptEmitter()
	s.envelopeEmitter = s.liveEnvelopeEmitter()
	s.toolPolicyCfg = buildToolPolicyCfg(newCfg)
	if bundleResult != nil {
		s.mcpToolExtraPoison = rules.ConvertToolPoison(bundleResult.ToolPoison)
	} else {
		s.mcpToolExtraPoison = nil
	}
	if oldCfg == nil || !reflect.DeepEqual(oldCfg.ToolChainDetection, newCfg.ToolChainDetection) {
		s.mcpChainMatcher = buildMCPChainMatcher(newCfg, s.metrics)
	}
	if oldCfg == nil || !reflect.DeepEqual(oldCfg.CrossRequestDetection, newCfg.CrossRequestDetection) {
		s.mcpCEE = buildMCPCEE(newCfg, s.metrics)
	}
}
