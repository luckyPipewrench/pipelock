// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/normalize"
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
	// CaptureGrade describes the fidelity of evidence available for this
	// replayed record.
	CaptureGrade string
	// SidecarDecrypted is true when scanner input came from an encrypted
	// payload sidecar.
	SidecarDecrypted bool
	// CandidateFindings holds findings produced by the candidate scanner.
	CandidateFindings []Finding
}

// ReplayEngine replays captured scan decisions against a candidate config.
// Stateless surfaces (URL, response, DLP, tool_policy) are replayed by
// re-running the scanner; stateful surfaces (CEE, tool_scan) are marked
// evidence-only.
type ReplayEngine struct {
	cfg      *config.Config
	sc       *scanner.Scanner
	contract *contract.Contract
}

// NewReplayEngine creates a ReplayEngine. sc may be nil when only tool
// policy replay is needed (tool policy uses the compiled policy evaluator,
// not the scanner).
func NewReplayEngine(cfg *config.Config, sc *scanner.Scanner) *ReplayEngine {
	return &ReplayEngine{cfg: cfg, sc: sc}
}

// NewContractReplayEngine creates a ReplayEngine that evaluates enforce-state
// contract rules for URL captures before falling back to candidate config replay
// for other surfaces.
func NewContractReplayEngine(cfg *config.Config, sc *scanner.Scanner, c contract.Contract) *ReplayEngine {
	return &ReplayEngine{cfg: cfg, sc: sc, contract: &c}
}

// ReplayRecord dispatches a capture summary to the appropriate surface
// replay function. scannerInput is the full scanner input text; for URL
// surfaces it may be empty (the URL from the summary is used instead).
func (re *ReplayEngine) ReplayRecord(summary CaptureSummary, scannerInput string) ReplayResult {
	var result ReplayResult
	switch summary.Surface {
	case SurfaceURL:
		if re.contract != nil {
			result = re.replayContractURL(summary, scannerInput)
		} else {
			result = re.replayURL(summary, scannerInput)
		}
	case SurfaceResponse:
		result = re.replayResponse(summary, scannerInput)
	case SurfaceDLP:
		result = re.replayDLP(summary, scannerInput)
	case SurfaceToolPolicy:
		result = re.replayToolPolicy(summary)
	case SurfaceCEE, SurfaceToolScan:
		result = ReplayResult{
			OriginalAction: summary.EffectiveAction,
			EvidenceOnly:   true,
		}
	default:
		result = ReplayResult{
			OriginalAction: summary.EffectiveAction,
			EvidenceOnly:   true,
		}
	}
	result.CaptureGrade = captureGradeForReplay(summary, scannerInput)
	return result
}

func (re *ReplayEngine) replayContractURL(summary CaptureSummary, scannerInput string) ReplayResult {
	target := scannerInput
	if target == "" {
		target = summary.Request.URL
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return re.replayURL(summary, scannerInput)
	}
	replayGrade := captureGradeForReplay(summary, scannerInput)

	hostHasEnforceRule := false
	hasComparableEvidence := false
	var hostRuleIDs []string
	seenHostRuleIDs := map[string]struct{}{}
	for _, rule := range re.contract.Rules {
		if rule.LifecycleState != EnforcementModeEnforce || (rule.RuleKind != "http_destination" && rule.RuleKind != "http_action") {
			continue
		}
		if !contractRuleHostMatches(rule, u.Hostname()) {
			continue
		}
		hostHasEnforceRule = true
		hostRuleIDs = appendContractRuleID(hostRuleIDs, seenHostRuleIDs, rule.RuleID)
		matches, canCompare := contractRuleMatchesURL(rule, u, summary)
		if !canCompare {
			return re.replayURL(summary, scannerInput)
		}
		if !captureGradeSatisfies(replayGrade, rule.RequiredCaptureGrade) {
			continue
		}
		hasComparableEvidence = true
		if matches {
			return ReplayResult{
				OriginalAction:  summary.EffectiveAction,
				CandidateAction: config.ActionAllow,
				Changed:         summary.EffectiveAction != config.ActionAllow,
				CandidateFindings: []Finding{{
					Kind:       KindContract,
					Action:     config.ActionAllow,
					PolicyRule: rule.RuleID,
					MatchText:  target,
				}},
			}
		}
	}
	if !hostHasEnforceRule {
		return re.replayURL(summary, scannerInput)
	}
	if !hasComparableEvidence {
		return re.replayURL(summary, scannerInput)
	}
	return ReplayResult{
		OriginalAction:    summary.EffectiveAction,
		CandidateAction:   config.ActionBlock,
		Changed:           summary.EffectiveAction != config.ActionBlock,
		CandidateFindings: contractDenyFindings(hostRuleIDs, target),
	}
}

func appendContractRuleID(ruleIDs []string, seen map[string]struct{}, ruleID string) []string {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return ruleIDs
	}
	if _, ok := seen[ruleID]; ok {
		return ruleIDs
	}
	seen[ruleID] = struct{}{}
	return append(ruleIDs, ruleID)
}

func contractDenyFindings(ruleIDs []string, target string) []Finding {
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		unique = appendContractRuleID(unique, seen, ruleID)
	}
	if len(unique) == 0 {
		return []Finding{{
			Kind:      KindContract,
			Action:    config.ActionBlock,
			MatchText: target,
		}}
	}
	out := make([]Finding, 0, len(unique))
	for _, ruleID := range unique {
		out = append(out, Finding{
			Kind:       KindContract,
			Action:     config.ActionBlock,
			PolicyRule: ruleID,
			MatchText:  target,
		})
	}
	return out
}

func contractRuleHostMatches(rule contract.Rule, host string) bool {
	ruleHost := normalizeHost(selectorString(rule.Selector, "host"))
	return ruleHost != "" && ruleHost == normalizeHost(host)
}

func contractRuleMatchesURL(rule contract.Rule, u *url.URL, summary CaptureSummary) (bool, bool) {
	matchedConstraint := selectorString(rule.Selector, "host") != ""
	if methodValues := selectorStringList(rule.Selector, "methods"); len(methodValues) > 0 {
		matchedConstraint = true
		if !containsFoldedMethod(methodValues, summary.Request.Method) {
			return false, true
		}
	}
	if pathValues := selectorPathValues(rule.Selector); len(pathValues) > 0 {
		matchedConstraint = true
		matches, canCompare := pathMatchesAny(u.EscapedPath(), pathValues)
		if !canCompare || !matches {
			return matches, canCompare
		}
	}
	if action := selectorRawString(rule.Selector, "effective_action"); action != "" {
		matchedConstraint = true
		if action != summary.EffectiveAction {
			return false, true
		}
	}
	return matchedConstraint, true
}

func selectorString(selector map[string]any, key string) string {
	value, ok := selector[key].(map[string]any)
	if !ok {
		return ""
	}
	raw, _ := value["value"].(string)
	return raw
}

func selectorRawString(selector map[string]any, key string) string {
	value, _ := selector[key].(string)
	return value
}

func selectorStringList(selector map[string]any, key string) []string {
	values, ok := selector[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if ok {
			out = append(out, text)
		}
	}
	return out
}

func selectorPathValues(selector map[string]any) []string {
	values, ok := selector["paths"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		text, ok := item["value"].(string)
		if ok {
			out = append(out, text)
		}
	}
	return out
}

func containsFoldedMethod(values []string, target string) bool {
	target = strings.ToUpper(strings.TrimSpace(target))
	for _, value := range values {
		if strings.ToUpper(strings.TrimSpace(value)) == target {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func pathMatchesAny(escapedPath string, values []string) (bool, bool) {
	if escapedPath == "" {
		escapedPath = "/"
	}
	canonicalPath, _, err := normalize.Canonicalize(escapedPath)
	if err != nil {
		return false, false
	}
	for _, value := range values {
		if value == canonicalPath {
			return true, true
		}
	}
	return false, true
}

func captureGradeSatisfies(actual, required string) bool {
	if required == "" {
		required = contract.CaptureGradeFull
	}
	return captureGradeRank(actual) >= captureGradeRank(required)
}

func captureGradeForReplay(summary CaptureSummary, scannerInput string) string {
	switch summary.Surface {
	case SurfaceURL, SurfaceToolPolicy:
		return CaptureGradeFull
	case SurfaceCEE:
		if scannerInput != "" {
			return CaptureGradeFull
		}
		return CaptureGradeNone
	case SurfaceResponse, SurfaceDLP, SurfaceToolScan:
		if scannerInput != "" {
			return CaptureGradeFull
		}
		return CaptureGradePartial
	default:
		if scannerInput != "" {
			return CaptureGradeFull
		}
		return CaptureGradeSummary
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
	var extractionTruncated bool
	if argsJSON != "" {
		rawArgs = json.RawMessage(argsJSON)
		extracted := jsonrpc.ExtractStringsFromJSONResult(rawArgs)
		extractionTruncated = extracted.Truncated
		argStrings = extracted.Strings
	}

	verdict := pc.CheckToolCallWithArgs(toolName, argStrings, rawArgs)

	candidateAction := ""
	var findings []Finding
	if extractionTruncated {
		candidateAction = config.ActionBlock
		findings = append(findings, Finding{
			Kind:       KindToolPolicy,
			Action:     config.ActionBlock,
			PolicyRule: "uninspectable_json_depth",
			ToolName:   toolName,
		})
	}
	if verdict.Matched {
		candidateAction = policy.StricterAction(candidateAction, verdict.Action)
		for _, ruleName := range verdict.Rules {
			findings = append(findings, Finding{
				Kind:       KindToolPolicy,
				Action:     verdict.Action,
				PolicyRule: ruleName,
				ToolName:   toolName,
			})
		}
	}
	if candidateAction == "" {
		candidateAction = config.ActionAllow
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
