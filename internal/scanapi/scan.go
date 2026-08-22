// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// jsonNull is the literal JSON null, used to detect nil-equivalent RawMessage values.
const jsonNull = "null"

var embeddedHTTPURLTokenRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>\\]+`)

const (
	maxEmbeddedURLDecodePasses = 6 // combined percent + HTML-entity decode passes
	maxEmbeddedURLScans        = 32
	maxEmbeddedURLTextViews    = 16
)

type embeddedURLScanResults struct {
	results   []scanner.Result
	truncated bool
}

// executeScan dispatches to the appropriate scanner for the requested kind.
// Returns both the response body and the HTTP status code.
// 200 = completed (allow or deny), 503 = retryable failure, 500 = internal error.
func (h *Handler) executeScan(ctx context.Context, req *Request) (Response, int) {
	cfg := h.currentConfig()
	sc := h.currentScanner()
	policyCfg := h.currentPolicyCfg()
	if cfg == nil || sc == nil {
		return errorResponse(req.Kind, "scan_unavailable", "Scan engine unavailable", true), http.StatusServiceUnavailable
	}

	switch req.Kind {
	case KindURL:
		return h.scanURL(ctx, sc, req)
	case KindDLP:
		return h.scanDLP(ctx, sc, req)
	case KindPromptInjection:
		return h.scanPromptInjection(ctx, sc, req)
	case KindToolCall:
		return h.scanToolCall(ctx, sc, policyCfg, req)
	default:
		// Should not reach here (validated in handler), but fail-closed.
		return errorResponse(req.Kind, "invalid_kind", "Unknown kind", false), http.StatusBadRequest
	}
}

func (h *Handler) scanURL(ctx context.Context, sc *scanner.Scanner, req *Request) (Response, int) {
	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	result := sc.Scan(ctx, req.Input.URL)

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

func (h *Handler) scanDLP(ctx context.Context, sc *scanner.Scanner, req *Request) (Response, int) {
	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	result := sc.ScanTextForDLP(ctx, req.Input.Text)
	urlResults := scanEmbeddedTextURLs(ctx, sc, req.Input.Text)

	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	resp := Response{
		Status: StatusCompleted,
		Kind:   req.Kind,
		ScanID: generateScanID(),
	}
	if result.Clean && len(urlResults.results) == 0 && !urlResults.truncated {
		resp.Decision = DecisionAllow
	} else {
		resp.Decision = DecisionDeny
		if !result.Clean {
			resp.Findings = append(resp.Findings, dlpFindings(result, req.Options)...)
		}
		for _, urlResult := range urlResults.results {
			resp.Findings = append(resp.Findings, urlFindings(urlResult)...)
		}
		if urlResults.truncated {
			resp.Findings = append(resp.Findings, embeddedURLTruncatedFinding())
		}
	}
	return resp, http.StatusOK
}

func scanEmbeddedTextURLs(ctx context.Context, sc *scanner.Scanner, text string) embeddedURLScanResults {
	tokens, truncated := embeddedHTTPURLTokens(text, maxEmbeddedURLScans)
	results := embeddedURLScanResults{truncated: truncated}
	seenFindings := make(map[string]struct{})
	for _, token := range tokens {
		result := sc.Scan(ctx, token)
		if err := ctx.Err(); err != nil {
			return embeddedURLScanResults{}
		}
		if result.Allowed || !embeddedURLResultIsFinding(result) {
			continue
		}
		key := result.Scanner + "\x00" + result.Reason + "\x00" + result.Hint
		if _, ok := seenFindings[key]; ok {
			continue
		}
		seenFindings[key] = struct{}{}
		results.results = append(results.results, result)
	}
	return results
}

func embeddedHTTPURLTokens(text string, limit int) ([]string, bool) {
	seen := make(map[string]struct{})
	tokens := make([]string, 0, limit)
	views, viewsTruncated := embeddedURLTextViews(text)
	for _, view := range views {
		for _, raw := range embeddedHTTPURLTokenRe.FindAllString(view, -1) {
			token := strings.TrimRight(raw, ".,;)]}")
			if token == "" {
				continue
			}
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			if len(tokens) >= limit {
				return tokens, true
			}
			tokens = append(tokens, token)
		}
	}
	// A view-building bound that stopped early means the token list may be
	// incomplete even when the token cap was never reached.
	return tokens, viewsTruncated
}

// embeddedURLTextViews builds the decoded views the URL token matcher reads.
// It returns truncated=true when either bound stopped it while more decoding
// was still productive: the view cap, or the decode-pass budget. Both were
// previously silent, so a URL wrapped past the ceiling yielded no token and the
// caller reported a clean allow on content it had not finished inspecting. The
// token-count cap already reported this way; these two now match it.
func embeddedURLTextViews(text string) ([]string, bool) {
	views := make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	truncated := false
	// addView records a view and, when that view carries escaped slashes, its
	// slash-decoded form. Both are decided in ONE capacity check: the cap could
	// otherwise fill between the two appends and drop the decoded form, which
	// may be the first form containing a literal scheme. A view the bound
	// refuses must set truncated rather than vanish, because the caller treats
	// truncation as "inspection did not finish" and denies.
	addView := func(view string) {
		if _, ok := seen[view]; ok {
			return
		}
		slashDecoded := ""
		if strings.Contains(view, `\/`) {
			if decoded := strings.ReplaceAll(view, `\/`, `/`); decoded != view {
				if _, dup := seen[decoded]; !dup {
					slashDecoded = decoded
				}
			}
		}
		needed := 1
		if slashDecoded != "" {
			needed = 2
		}
		if len(views)+needed > maxEmbeddedURLTextViews {
			truncated = true
			return
		}
		seen[view] = struct{}{}
		views = append(views, view)
		if slashDecoded != "" {
			seen[slashDecoded] = struct{}{}
			views = append(views, slashDecoded)
		}
	}
	addView(text)

	converged := false
	for range maxEmbeddedURLDecodePasses {
		startLen := len(views)
		for _, view := range views[:startLen] {
			if strings.Contains(view, "%") {
				decoded, err := url.PathUnescape(view)
				if err == nil && decoded != view {
					addView(decoded)
				}
			}
			if strings.Contains(view, "&") {
				decoded := html.UnescapeString(view)
				if decoded != view {
					addView(decoded)
				}
			}
		}
		if len(views) == startLen {
			// Nothing new decoded, so the payload is fully peeled. This is the
			// normal exit and the only one that proves inspection completed.
			converged = true
			break
		}
	}
	if !converged && anyViewDecodesFurther(views, seen) {
		// The pass budget ran out AND a further pass would still produce a view
		// nobody has seen, so a layer genuinely went unread. Exhausting the
		// budget alone is not evidence of that: a payload can converge exactly
		// on the final pass, having been fully decoded, and flagging that as
		// truncated denies content the scanner actually finished inspecting.
		truncated = true
	}
	return views, truncated
}

// anyViewDecodesFurther reports whether decoding the current views once more
// would yield a view not already collected. It is a read-only probe: it does not
// add views, so it answers "was inspection incomplete" without extending the
// bound the caller chose.
func anyViewDecodesFurther(views []string, seen map[string]struct{}) bool {
	for _, view := range views {
		if strings.Contains(view, "%") {
			if decoded, err := url.PathUnescape(view); err == nil && decoded != view {
				if _, ok := seen[decoded]; !ok {
					return true
				}
			}
		}
		if strings.Contains(view, "&") {
			if decoded := html.UnescapeString(view); decoded != view {
				if _, ok := seen[decoded]; !ok {
					return true
				}
			}
		}
	}
	return false
}

func embeddedURLResultIsFinding(result scanner.Result) bool {
	return !result.IsInfrastructureError()
}

func embeddedURLTruncatedFinding() Finding {
	return Finding{
		Scanner:  "url",
		RuleID:   "URL-embedded-url-scan-truncated",
		Severity: "medium",
		Message:  "Embedded URL scan stopped after bounded inspection limit",
	}
}

func (h *Handler) scanPromptInjection(ctx context.Context, sc *scanner.Scanner, req *Request) (Response, int) {
	if err := ctx.Err(); err != nil {
		return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
	}

	result := sc.ScanResponse(ctx, req.Input.Content)

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

func (h *Handler) scanToolCall(
	ctx context.Context,
	sc *scanner.Scanner,
	policyCfg *policy.Config,
	req *Request,
) (Response, int) {
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
	if len(req.Input.Arguments) > 0 && string(req.Input.Arguments) != jsonNull {
		extracted := extract.AllStringsFromJSONResult(json.RawMessage(req.Input.Arguments))
		if extracted.Truncated {
			resp.Decision = DecisionDeny
			resp.Findings = append(resp.Findings, Finding{
				Scanner:  "tool_call",
				RuleID:   "UNINSPECTABLE-json-depth",
				Severity: "critical",
				Message:  "Tool call arguments exceed maximum inspectable nesting depth",
			})
			return resp, http.StatusOK
		}
		argStrings = extracted.Strings
	}
	scanText := strings.Join(argStrings, " ")

	// Stage 2: DLP + injection sub-scans (independent of tool policy).
	//
	// These run whenever a tool_call scan is requested, NOT gated on
	// cfg.MCPInputScanning.Enabled. The scan API is an explicit on-demand
	// request surface: whether tool_call is offered at all is governed by
	// scan_api.kinds.tool_call (default true). Gating Stage 2 on the
	// inline-proxy MCPInputScanning toggle (default false) made a caller's
	// tool_call request return allow with zero findings - a fail-open where
	// the API silently declined to scan what it was asked to. The sibling
	// kinds (url / dlp / prompt_injection) all scan unconditionally; tool_call
	// now matches that contract.
	if scanText != "" {
		dlpResult := sc.ScanTextForDLP(ctx, scanText)
		if err := ctx.Err(); err != nil {
			return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
		}
		if !dlpResult.Clean {
			resp.Decision = DecisionDeny
			resp.Findings = append(resp.Findings, dlpFindings(dlpResult, req.Options)...)
		}

		injResult := sc.ScanResponse(ctx, scanText)
		if err := ctx.Err(); err != nil {
			return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
		}
		if !injResult.Clean {
			resp.Decision = DecisionDeny
			resp.Findings = append(resp.Findings, injectionFindings(injResult, req.Options)...)
		}
	}

	// Stage 3: Policy check.
	if policyCfg != nil {
		if err := ctx.Err(); err != nil {
			return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
		}
		var rawArgs json.RawMessage
		if len(req.Input.Arguments) > 0 && string(req.Input.Arguments) != jsonNull {
			rawArgs = json.RawMessage(req.Input.Arguments)
		}
		verdict := policyCfg.CheckToolCallWithArgs(req.Input.ToolName, argStrings, rawArgs)
		if err := ctx.Err(); err != nil {
			return h.contextErrorResponse(req.Kind, err), h.contextErrorStatus(err)
		}
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
		code = errorCodeScanDeadlineExceeded
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
