// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// urlResultToFindings converts a scanner.Result (URL pipeline) to capture findings.
// Returns nil for allowed results to avoid allocating an empty slice.
func urlResultToFindings(r scanner.Result) []capture.Finding {
	if r.Allowed {
		return nil
	}
	return []capture.Finding{{
		Kind:        capture.KindDLP,
		PatternName: r.Scanner,
		Action:      config.ActionBlock,
	}}
}

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

// ceeResultToFindings converts a ceeResult to capture findings.
func ceeResultToFindings(res ceeResult) []capture.Finding {
	if !res.EntropyHit && !res.FragmentHit && !res.Blocked {
		return nil
	}
	var findings []capture.Finding
	if res.EntropyHit {
		findings = append(findings, capture.Finding{
			Kind:   capture.KindCEE,
			Action: config.ActionBlock,
		})
	}
	if res.FragmentHit {
		findings = append(findings, capture.Finding{
			Kind:   capture.KindCEE,
			Action: config.ActionBlock,
		})
	}
	return findings
}

// bodyScanToFindings converts a BodyScanResult to capture findings.
func bodyScanToFindings(r BodyScanResult) []capture.Finding {
	if r.Clean {
		return nil
	}
	var findings []capture.Finding
	for _, m := range r.DLPMatches {
		findings = append(findings, capture.Finding{
			Kind:        capture.KindDLP,
			PatternName: m.PatternName,
			Severity:    m.Severity,
			Encoded:     m.Encoded,
			Action:      config.ActionBlock,
		})
	}
	for _, f := range r.AddressFindings {
		findings = append(findings, capture.Finding{
			Kind:        capture.KindAddressProtection,
			AddrVerdict: f.Explanation,
			Action:      f.Action,
		})
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
