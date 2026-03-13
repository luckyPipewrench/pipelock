// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// executeScan dispatches to the appropriate scanner for the requested kind.
// Returns both the response body and the HTTP status code.
// 200 = completed (allow or deny), 503 = retryable failure, 500 = internal error.
func (h *Handler) executeScan(ctx context.Context, req *Request) (Response, int) {
	switch req.Kind {
	case KindURL:
		return h.scanURL(ctx, req)
	case KindDLP:
		return h.scanDLP(ctx, req)
	case KindPromptInjection:
		return h.scanPromptInjection(ctx, req)
	case KindToolCall:
		return h.scanToolCall(ctx, req)
	default:
		// Should not reach here (validated in handler), but fail-closed.
		return errorResponse(req.Kind, "invalid_kind", "Unknown kind", false), http.StatusBadRequest
	}
}

func (h *Handler) scanURL(ctx context.Context, req *Request) (Response, int) {
	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	result := h.scanner.Scan(ctx, req.Input.URL)

	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	resp := Response{
		Status: StatusCompleted,
		Kind:   req.Kind,
		ScanID: generateScanID(),
	}
	if result.Allowed {
		resp.Decision = DecisionAllow
	} else {
		resp.Decision = DecisionDeny
		resp.Findings = urlFindings(result)
	}
	return resp, http.StatusOK
}

func (h *Handler) scanDLP(ctx context.Context, req *Request) (Response, int) {
	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	result := h.scanner.ScanTextForDLP(ctx, req.Input.Text)

	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	resp := Response{
		Status: StatusCompleted,
		Kind:   req.Kind,
		ScanID: generateScanID(),
	}
	if result.Clean {
		resp.Decision = DecisionAllow
	} else {
		resp.Decision = DecisionDeny
		resp.Findings = dlpFindings(result, req.Options)
	}
	return resp, http.StatusOK
}

func (h *Handler) scanPromptInjection(ctx context.Context, req *Request) (Response, int) {
	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	result := h.scanner.ScanResponse(ctx, req.Input.Content)

	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	resp := Response{
		Status: StatusCompleted,
		Kind:   req.Kind,
		ScanID: generateScanID(),
	}
	if result.Clean {
		resp.Decision = DecisionAllow
	} else {
		resp.Decision = DecisionDeny
		resp.Findings = injectionFindings(result, req.Options)
	}
	return resp, http.StatusOK
}

func (h *Handler) scanToolCall(ctx context.Context, req *Request) (Response, int) {
	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	resp := Response{
		Status:   StatusCompleted,
		Decision: DecisionAllow,
		Kind:     req.Kind,
		ScanID:   generateScanID(),
	}

	// Stage 1: Key+value extraction from arguments.
	// Uses extract.AllStringsFromJSON (keys AND values) because secrets
	// can be encoded as JSON object keys. See spec: tool_call wiring detail.
	var argStrings []string
	if len(req.Input.Arguments) > 0 && string(req.Input.Arguments) != "null" {
		argStrings = extract.AllStringsFromJSON(json.RawMessage(req.Input.Arguments))
	}
	scanText := strings.Join(argStrings, " ")

	// Stage 2: DLP + injection sub-scans (independent of tool policy).
	if scanText != "" && h.cfg.MCPInputScanning.Enabled {
		dlpResult := h.scanner.ScanTextForDLP(ctx, scanText)
		if err := ctx.Err(); err != nil {
			return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
		}
		if !dlpResult.Clean {
			resp.Decision = DecisionDeny
			resp.Findings = append(resp.Findings, dlpFindings(dlpResult, req.Options)...)
		}

		injResult := h.scanner.ScanResponse(ctx, scanText)
		if err := ctx.Err(); err != nil {
			return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
		}
		if !injResult.Clean {
			resp.Decision = DecisionDeny
			resp.Findings = append(resp.Findings, injectionFindings(injResult, req.Options)...)
		}
	}

	// Stage 3: Policy check.
	if h.policyCfg != nil {
		verdict := h.policyCfg.CheckToolCall(req.Input.ToolName, argStrings)
		if verdict.Matched {
			resp.Decision = DecisionDeny
			resp.Findings = append(resp.Findings, policyFindings(verdict)...)
		}
	}

	return resp, http.StatusOK
}

// contextErrorResponse builds a 503/500 error response for context failures.
func (h *Handler) contextErrorResponse(kind string, err error) Response {
	code := "internal_error"
	message := "Scan failed"
	retryable := false

	if errors.Is(err, context.DeadlineExceeded) {
		code = "scan_deadline_exceeded"
		message = "Scan timed out"
		retryable = true
	} else if errors.Is(err, context.Canceled) {
		code = "request_canceled"
		message = "Request canceled by client"
	}

	return Response{
		Status:        StatusError,
		Kind:          kind,
		ScanID:        generateScanID(),
		EngineVersion: h.version,
		Errors:        []APIError{{Code: code, Message: message, Retryable: retryable}},
	}
}

// contextErrorStatus maps context errors to HTTP status codes.
func (h *Handler) contextErrorStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusServiceUnavailable // 503: retryable timeout
	}
	return http.StatusInternalServerError // 500: client cancel or other
}

// Finding constructors: translate scanner results to API findings.
// Message fields use pattern names only, never raw matched content.

func urlFindings(result scanner.Result) []Finding {
	return []Finding{{
		Scanner:  "url",
		RuleID:   urlRuleID(result),
		Severity: urlSeverity(result),
		Message:  result.Reason,
	}}
}

func dlpFindings(result scanner.TextDLPResult, opts *RequestOptions) []Finding {
	findings := make([]Finding, 0, len(result.Matches))
	for _, m := range result.Matches {
		f := Finding{
			Scanner:  "dlp",
			RuleID:   "DLP-" + m.PatternName,
			Severity: m.Severity,
			Message:  "Secret-like token detected (" + m.PatternName + ")",
		}
		if opts != nil && opts.IncludeEvidence {
			encoding := m.Encoded
			if encoding == "" {
				encoding = "plaintext"
			}
			f.Evidence = &Evidence{Encoding: encoding}
		}
		findings = append(findings, f)
	}
	return findings
}

func injectionFindings(result scanner.ResponseScanResult, opts *RequestOptions) []Finding {
	findings := make([]Finding, 0, len(result.Matches))
	for _, m := range result.Matches {
		f := Finding{
			Scanner:  "prompt_injection",
			RuleID:   "INJ-" + m.PatternName,
			Severity: "high",
			Message:  "Prompt injection pattern matched: " + m.PatternName,
		}
		// No evidence for injection matches: Position is post-normalization
		// and does not reliably map to original input bytes.
		_ = opts // intentionally unused for injection evidence
		findings = append(findings, f)
	}
	return findings
}

func policyFindings(verdict policy.Verdict) []Finding {
	findings := make([]Finding, 0, len(verdict.Rules))
	for _, rule := range verdict.Rules {
		findings = append(findings, Finding{
			Scanner:  "tool_policy",
			RuleID:   "POLICY-" + rule,
			Severity: "high",
			Message:  "Tool call denied by policy rule: " + rule,
		})
	}
	if len(findings) == 0 {
		// Matched but no named rules (unnamed policy match).
		findings = append(findings, Finding{
			Scanner:  "tool_policy",
			RuleID:   "POLICY-DENY",
			Severity: "high",
			Message:  "Tool call denied by policy",
		})
	}
	return findings
}

func urlRuleID(r scanner.Result) string {
	switch r.Scanner {
	case scanner.ScannerSSRF:
		return "SSRF-Private-IP"
	case scanner.ScannerDLP:
		return "DLP-URL-Exfil"
	case scanner.ScannerBlocklist:
		return "BLOCK-Domain"
	default:
		return "URL-" + r.Scanner
	}
}

func urlSeverity(r scanner.Result) string {
	switch r.Scanner {
	case scanner.ScannerDLP:
		return "critical"
	case scanner.ScannerSSRF:
		return "high"
	default:
		return "medium"
	}
}

func errorResponse(kind, code, message string, retryable bool) Response {
	return Response{
		Status: StatusError,
		Kind:   kind,
		ScanID: generateScanID(),
		Errors: []APIError{
			{Code: code, Message: message, Retryable: retryable},
		},
	}
}
