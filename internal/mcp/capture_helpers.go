// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// dlpMatchesToFindings converts scanner.TextDLPMatch slice to capture findings.
func dlpMatchesToFindings(matches []scanner.TextDLPMatch) []capture.Finding {
	if len(matches) == 0 {
		return nil
	}
	findings := make([]capture.Finding, len(matches))
	for i, m := range matches {
		findings[i] = capture.Finding{
			Kind:        capture.KindDLP,
			PatternName: m.PatternName,
			Severity:    m.Severity,
			Encoded:     m.Encoded,
			Action:      config.ActionBlock,
		}
	}
	return findings
}

// responseMatchesToFindings converts scanner.ResponseMatch slice to capture findings.
func responseMatchesToFindings(matches []scanner.ResponseMatch, action string) []capture.Finding {
	if len(matches) == 0 {
		return nil
	}
	findings := make([]capture.Finding, len(matches))
	for i, m := range matches {
		findings[i] = capture.Finding{
			Kind:        capture.KindInjection,
			PatternName: m.PatternName,
			MatchText:   m.MatchText,
			Action:      action,
		}
	}
	return findings
}

// addressFindingsToCapture converts addressprotect.Finding slice to capture findings.
func addressFindingsToCapture(findings []addressprotect.Finding) []capture.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]capture.Finding, len(findings))
	for i, f := range findings {
		out[i] = capture.Finding{
			Kind:        capture.KindAddressProtection,
			AddrVerdict: f.Explanation,
			Action:      f.Action,
		}
	}
	return out
}

// toolScanMatchesToFindings converts tools.ToolScanMatch slice to capture findings.
func toolScanMatchesToFindings(matches []tools.ToolScanMatch) []capture.Finding {
	if len(matches) == 0 {
		return nil
	}
	var findings []capture.Finding
	for _, m := range matches {
		for _, p := range m.ToolPoison {
			findings = append(findings, capture.Finding{
				Kind:         capture.KindToolPoison,
				ToolName:     m.ToolName,
				PoisonSignal: p,
			})
		}
		for _, inj := range m.Injection {
			findings = append(findings, capture.Finding{
				Kind:        capture.KindInjection,
				ToolName:    m.ToolName,
				PatternName: inj.PatternName,
				MatchText:   inj.MatchText,
			})
		}
		if m.DriftDetected {
			findings = append(findings, capture.Finding{
				Kind:      capture.KindToolDrift,
				ToolName:  m.ToolName,
				DriftType: m.DriftDetail,
			})
		}
	}
	return findings
}

// captureOutcome maps an effective action to a capture outcome constant.
func captureOutcome(effectiveAction string, clean bool) string {
	if clean {
		return capture.OutcomeClean
	}
	switch effectiveAction {
	case config.ActionBlock:
		return capture.OutcomeBlocked
	case config.ActionWarn:
		return capture.OutcomeWarned
	case config.ActionStrip:
		return capture.OutcomeStripped
	case config.ActionRedirect:
		return capture.OutcomeRedirected
	case config.ActionAllow, config.ActionForward:
		return capture.OutcomeClean
	default:
		return capture.OutcomeBlocked
	}
}
