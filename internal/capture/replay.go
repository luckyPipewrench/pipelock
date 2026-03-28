// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"context"
	"encoding/json"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ReplayResult describes the outcome of replaying a single capture entry
// against a candidate configuration. Changed is true when the candidate
// config would have produced a different action than the original.
type ReplayResult struct {
	// OriginalAction is the action recorded in the capture summary.
	OriginalAction string
	// CandidateAction is the action the candidate scanner would produce.
	CandidateAction string
	// Changed is true when OriginalAction != CandidateAction.
	Changed bool
	// EvidenceOnly is true for stateful surfaces (CEE, tool_scan) that
	// cannot be replayed from a single entry in v1.
	EvidenceOnly bool
	// SummaryOnly is true when the capture has no scanner input and
	// therefore cannot be replayed.
	SummaryOnly bool
	// CandidateFindings holds findings produced by the candidate scanner.
	CandidateFindings []Finding
}

// ReplayEngine replays captured scan decisions against a candidate config.
// Stateless surfaces (URL, response, DLP, tool_policy) are replayed by
// re-running the scanner; stateful surfaces (CEE, tool_scan) are marked
// evidence-only.
type ReplayEngine struct {
	cfg *config.Config
	sc  *scanner.Scanner
}

// NewReplayEngine creates a ReplayEngine. sc may be nil when only tool
// policy replay is needed (tool policy uses the compiled policy evaluator,
// not the scanner).
func NewReplayEngine(cfg *config.Config, sc *scanner.Scanner) *ReplayEngine {
	return &ReplayEngine{cfg: cfg, sc: sc}
}

// ReplayRecord dispatches a capture summary to the appropriate surface
// replay function. scannerInput is the full scanner input text; for URL
// surfaces it may be empty (the URL from the summary is used instead).
func (re *ReplayEngine) ReplayRecord(summary CaptureSummary, scannerInput string) ReplayResult {
	switch summary.Surface {
	case SurfaceURL:
		return re.replayURL(summary, scannerInput)
	case SurfaceResponse:
		return re.replayResponse(summary, scannerInput)
	case SurfaceDLP:
		return re.replayDLP(summary, scannerInput)
	case SurfaceToolPolicy:
		return re.replayToolPolicy(summary)
	case SurfaceCEE, SurfaceToolScan:
		return ReplayResult{
			OriginalAction: summary.EffectiveAction,
			EvidenceOnly:   true,
		}
	default:
		return ReplayResult{
			OriginalAction: summary.EffectiveAction,
			EvidenceOnly:   true,
		}
	}
}

// replayURL replays a URL scan. Uses scannerInput if non-empty, otherwise
// falls back to the request URL from the summary.
func (re *ReplayEngine) replayURL(summary CaptureSummary, scannerInput string) ReplayResult {
	url := scannerInput
	if url == "" {
		url = summary.Request.URL
	}

	result := re.sc.Scan(context.Background(), url)
	return re.urlResultToReplay(summary.EffectiveAction, result)
}

// replayResponse replays a response injection scan. Returns summary-only
// if scannerInput is empty (response bodies are not stored in summaries).
func (re *ReplayEngine) replayResponse(summary CaptureSummary, scannerInput string) ReplayResult {
	if scannerInput == "" {
		return ReplayResult{
			OriginalAction: summary.EffectiveAction,
			SummaryOnly:    true,
		}
	}

	result := re.sc.ScanResponse(context.Background(), scannerInput)
	return re.responseResultToReplay(summary.EffectiveAction, result)
}

// replayDLP replays a DLP text scan. Returns summary-only if scannerInput
// is empty.
func (re *ReplayEngine) replayDLP(summary CaptureSummary, scannerInput string) ReplayResult {
	if scannerInput == "" {
		return ReplayResult{
			OriginalAction: summary.EffectiveAction,
			SummaryOnly:    true,
		}
	}

	result := re.sc.ScanTextForDLP(context.Background(), scannerInput)
	return re.dlpResultToReplay(summary.EffectiveAction, result)
}

// replayToolPolicy replays a tool policy evaluation using the compiled
// policy evaluator from the candidate config. No scanner is needed.
func (re *ReplayEngine) replayToolPolicy(summary CaptureSummary) ReplayResult {
	pc := policy.New(re.cfg.MCPToolPolicy)

	toolName := summary.Request.ToolName
	argsJSON := summary.Request.ToolArgsJSON

	var argStrings []string
	var rawArgs json.RawMessage
	if argsJSON != "" {
		rawArgs = json.RawMessage(argsJSON)
		argStrings = jsonrpc.ExtractStringsFromJSON(rawArgs)
	}

	verdict := pc.CheckToolCallWithArgs(toolName, argStrings, rawArgs)

	candidateAction := config.ActionAllow
	var findings []Finding
	if verdict.Matched {
		candidateAction = verdict.Action
		for _, ruleName := range verdict.Rules {
			findings = append(findings, Finding{
				Kind:       KindToolPolicy,
				Action:     verdict.Action,
				PolicyRule: ruleName,
				ToolName:   toolName,
			})
		}
	}

	return ReplayResult{
		OriginalAction:    summary.EffectiveAction,
		CandidateAction:   candidateAction,
		Changed:           summary.EffectiveAction != candidateAction,
		CandidateFindings: findings,
	}
}

// urlResultToReplay converts a scanner.Result to a ReplayResult.
func (re *ReplayEngine) urlResultToReplay(originalAction string, result scanner.Result) ReplayResult {
	candidateAction := config.ActionAllow
	var findings []Finding

	if !result.Allowed {
		candidateAction = config.ActionBlock
		findings = append(findings, Finding{
			Kind:        KindDLP,
			Action:      config.ActionBlock,
			PatternName: result.Scanner,
			MatchText:   result.Reason,
		})
	}

	return ReplayResult{
		OriginalAction:    originalAction,
		CandidateAction:   candidateAction,
		Changed:           originalAction != candidateAction,
		CandidateFindings: findings,
	}
}

// responseResultToReplay converts a scanner.ResponseScanResult to a ReplayResult.
func (re *ReplayEngine) responseResultToReplay(originalAction string, result scanner.ResponseScanResult) ReplayResult {
	candidateAction := config.ActionAllow
	var findings []Finding

	if !result.Clean {
		// Use the configured response scanning action, defaulting to block.
		candidateAction = re.cfg.ResponseScanning.Action
		if candidateAction == "" {
			candidateAction = config.ActionBlock
		}
		for _, m := range result.Matches {
			findings = append(findings, Finding{
				Kind:        KindInjection,
				Action:      candidateAction,
				PatternName: m.PatternName,
				MatchText:   m.MatchText,
			})
		}
	}

	return ReplayResult{
		OriginalAction:    originalAction,
		CandidateAction:   candidateAction,
		Changed:           originalAction != candidateAction,
		CandidateFindings: findings,
	}
}

// dlpResultToReplay converts a scanner.TextDLPResult to a ReplayResult.
func (re *ReplayEngine) dlpResultToReplay(originalAction string, result scanner.TextDLPResult) ReplayResult {
	candidateAction := config.ActionAllow
	var findings []Finding

	if !result.Clean {
		candidateAction = config.ActionBlock
		for _, m := range result.Matches {
			findings = append(findings, Finding{
				Kind:        KindDLP,
				Action:      config.ActionBlock,
				Severity:    m.Severity,
				PatternName: m.PatternName,
				Encoded:     m.Encoded,
			})
		}
	}

	return ReplayResult{
		OriginalAction:    originalAction,
		CandidateAction:   candidateAction,
		Changed:           originalAction != candidateAction,
		CandidateFindings: findings,
	}
}
