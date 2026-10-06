// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// enforcedBlock is the enforce-mode decision every transport shares. In
// enforce mode a block action blocks. In audit mode (enforce: false) configured
// policy is observed and forwarded, but the built-in core credential floor
// still blocks, so fetch, forward, CONNECT, intercept, reverse and WebSocket
// agree on what audit mode can release. A nil config fails closed.
func enforcedBlock(cfg *config.Config, action string, coreCredential bool) bool {
	if coreCredential {
		return true
	}
	return action == config.ActionBlock && (cfg == nil || cfg.EnforceEnabled())
}

// urlResultBlocks applies enforcedBlock to a URL scan result that was not
// allowed. A credential allowed at its declared audience stays allowed. The
// URL scan stops at its first failing stage, so when audit mode would release
// a finding that is not core, the core floor runs on rawURL on its own: an
// earlier stage such as the blocklist must not hide a core credential.
func urlResultBlocks(cfg *config.Config, sc *scanner.Scanner, rawURL string, result scanner.Result) bool {
	if result.Allowed {
		return false
	}
	if enforcedBlock(cfg, config.ActionBlock, scanner.IsCoreCriticalResult(result)) {
		return true
	}
	return sc == nil || !sc.ScanURLCoreFloor(rawURL).Allowed
}

// containsCoreFloorMatch reports whether any enforced (non-warn) match belongs
// to the core credential floor.
func containsCoreFloorMatch(matches []scanner.TextDLPMatch) bool {
	for _, match := range matches {
		if !match.Warn && scanner.IsCoreCriticalMatch(match) {
			return true
		}
	}
	return false
}

// a2aCoreFloor reports whether an A2A scan found a core credential in a text
// field or inside a URL.
func a2aCoreFloor(result mcp.A2AScanResult) bool {
	if containsCoreFloorMatch(result.DLPFindings) {
		return true
	}
	for _, finding := range result.URLFindings {
		if scanner.IsCoreCriticalResult(finding) {
			return true
		}
	}
	return false
}
