// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const uninspectableJSONDepthReason = "input exceeds maximum inspectable nesting depth"

const uninspectableSplitSecretFieldsReason = "input exceeds maximum inspectable split-secret fields"

// redactedDLPMarker is appended to an MCP input verdict's reasons when a
// finding survives only because redaction scrubbed it (RedactedDLPOnly). It
// tells an operator reading the warn log that the credential was removed before
// forwarding rather than leaked, distinguishing this warn from a raw residual.
const redactedDLPMarker = "redacted"

// restoreRedactedDLPEvidence repairs the evidence surface when argument
// redaction scrubbed a DLP finding out of an MCP input request. When the
// pre-redaction scan matched DLP patterns (preRedactionDLP), redaction actually
// rewrote content (the report applied at least one redaction), and the
// post-redaction rescan came back clean, the request still forwards scrubbed --
// but taking the all-clean path would credit the session a clean request and
// emit no warning, no capture verdict, and an allow receipt, silently dropping
// the original match from every evidence surface. This restores the
// pre-redaction findings on the verdict as the configured action so the
// downstream dirty path records them, matching the request-body floor's
// RedactedDLPOnly handling in internal/proxy/bodyscan.go.
//
// It never changes the block/forward decision. The immutable core floor already
// ran on the redacted payload (preRedactionBlock plus the post-redaction
// mcpInputVerdictAction), and this path is only reached when the configured
// action is non-blocking, so the retained findings carry that same non-blocking
// action -- evidence is repaired, enforcement is untouched.
func restoreRedactedDLPEvidence(verdict InputVerdict, preRedactionDLP []scanner.TextDLPMatch, report *redact.Report, configuredAction string) InputVerdict {
	if !verdict.Clean || len(preRedactionDLP) == 0 {
		return verdict
	}
	if report == nil || !report.Applied || report.TotalRedactions == 0 {
		return verdict
	}
	verdict.Clean = false
	verdict.Matches = preRedactionDLP
	verdict.RedactedDLPOnly = true
	verdict.Action = configuredAction
	return verdict
}

// extractToolCallName extracts the tool name from a tools/call JSON-RPC request.
// Returns "" if the message is not a tools/call or the name cannot be extracted.
func extractToolCallName(line []byte) string {
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(line, &req) != nil {
		return ""
	}
	if req.Method != methodToolsCall {
		return ""
	}
	return req.Params.Name
}

// extractToolCallArgs extracts the raw arguments JSON from a tools/call
// request for denial-of-wallet tracking. Returns empty string if not a
// tools/call or if arguments are absent.
func extractToolCallArgs(line []byte) string {
	var req struct {
		Method string `json:"method"`
		Params struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if json.Unmarshal(line, &req) != nil || req.Method != methodToolsCall {
		return ""
	}
	return string(req.Params.Arguments)
}

func withMCPRequestWarnContext(ctx context.Context, resource string) context.Context {
	if resource == "" {
		return ctx
	}
	wc := scanner.DLPWarnContextFromCtx(ctx)
	if wc.Transport == "" {
		return ctx
	}
	wc.Method = mcpWarnMethod
	wc.Resource = resource
	return scanner.WithDLPWarnContext(ctx, wc)
}

func mcpWarnResource(method string, line []byte) string {
	if method == methodToolsCall {
		if toolName := extractToolCallName(line); toolName != "" {
			return toolName
		}
	}
	return method
}

func mcpInputVerdictAction(action string, dlpMatches []scanner.TextDLPMatch, injMatches []scanner.ResponseMatch) string {
	// Immutable core credential floor: a core-critical credential (a class the
	// operator cannot suppress) hard-blocks regardless of the configured MCP
	// input action, matching the request-body floor. Fail direction: if the
	// floor predicate cannot classify a match it treats it as non-core and the
	// configured action still applies below, but a positive core match here can
	// only ever raise the action to block, never lower it. On the redaction
	// path the floor decision is deferred to the post-redaction rescan (see
	// preRedactionBlock), so this call sees the redacted bytes and blocks only a
	// core credential redaction failed to scrub.
	if scanner.ContainsCoreCriticalMatch(dlpMatches) {
		return config.ActionBlock
	}
	return mcpContentActionIgnoringCoreFloor(action, dlpMatches, injMatches)
}

// mcpContentActionIgnoringCoreFloor resolves the MCP input content action for a
// dirty verdict WITHOUT applying the immutable core credential floor. It still
// force-blocks the two other non-suppressible content reasons -- a
// hostname-exfil DLP match and an uninspectable split-secret verdict -- and
// otherwise follows the configured action for any DLP/injection finding. The
// pre-redaction gate uses this to ask "would this verdict block for a reason
// redaction cannot fix", treating a core credential as an ordinary finding that
// redaction may scrub.
func mcpContentActionIgnoringCoreFloor(action string, dlpMatches []scanner.TextDLPMatch, injMatches []scanner.ResponseMatch) string {
	if scanner.ContainsHostnameExfilMatch(dlpMatches) {
		return config.ActionBlock
	}
	for _, match := range dlpMatches {
		if match.PatternName == uninspectableSplitSecretFieldsReason {
			return config.ActionBlock
		}
	}
	if len(dlpMatches) > 0 || len(injMatches) > 0 {
		return action
	}
	return ""
}

// resolveInputVerdictAction merges the DLP/injection action, the strictest
// address-finding action, and resource-URL findings into a single effective
// verdict action, applying the precedence both dirty-verdict paths in
// scanRequestForAgent use: URL findings always force block, and an address
// block overrides a non-block content action.
func resolveInputVerdictAction(action string, dlpMatches []scanner.TextDLPMatch, injMatches []scanner.ResponseMatch, addrFindings []addressprotect.Finding, urlFindings []scanner.Result) string {
	return mergeInputVerdictAction(mcpInputVerdictAction(action, dlpMatches, injMatches), addrFindings, urlFindings)
}

// mergeInputVerdictAction folds the address-finding and resource-URL escalations
// into an already-resolved content action. URL findings always force block; an
// address block overrides a non-block content action.
func mergeInputVerdictAction(contentAction string, addrFindings []addressprotect.Finding, urlFindings []scanner.Result) string {
	verdictAction := contentAction
	if addrAction := addressprotect.StrictestAction(addrFindings); addrAction != "" {
		if verdictAction == "" || addrAction == config.ActionBlock {
			verdictAction = addrAction
		}
	}
	if len(urlFindings) > 0 {
		verdictAction = config.ActionBlock
	}
	return verdictAction
}

// preRedactionBlock reports whether the pre-redaction content scan must block a
// request outright, before argument redaction runs. It mirrors the request-body
// floor (internal/proxy shouldHardBlockBodyCriticalDLP): the immutable core
// credential floor is the one block reason redaction can remove, so when the
// core floor is the ONLY thing forcing the block, the decision is deferred to
// the post-redaction rescan, which re-applies the floor to the redacted bytes.
//
// The reduction treats a core-critical match as an ORDINARY finding that
// follows the configured action rather than force-blocking. So under a warn
// configured action a core-only verdict collapses to warn and defers to
// redaction; under a block configured action it stays block (the operator asked
// to block findings, and redaction rescue does not override that) exactly as a
// non-core critical would. Every other effective-block reason -- a parse or scan
// error, a resource URL finding, a hostname-exfil DLP match, an uninspectable
// split-secret verdict, or an address block -- is not something argument
// redaction rewrites, so it keeps the pre-redaction block.
//
// Fail direction: a warn-mode request whose block is core-floor-only forwards
// ONLY if redaction then scrubs the credential and the post-redaction rescan is
// clean; if redaction is absent, incomplete, or the rescan still finds a core
// match, the post-redaction path blocks. Any non-core block reason, and any
// block-mode finding, still short-circuits here.
func preRedactionBlock(verdict InputVerdict, configuredAction string) bool {
	if inputVerdictEffectiveAction(verdict, configuredAction) != config.ActionBlock {
		return false
	}
	reduced := verdict
	reduced.Action = mergeInputVerdictAction(
		mcpContentActionIgnoringCoreFloor(configuredAction, verdict.Matches, verdict.Inject),
		verdict.AddressFindings,
		verdict.URLFindings,
	)
	return inputVerdictEffectiveAction(reduced, configuredAction) == config.ActionBlock
}

func inputVerdictEffectiveAction(verdict InputVerdict, configuredAction string) string {
	if verdict.Error != "" {
		return config.ActionBlock
	}
	if len(verdict.URLFindings) > 0 {
		return config.ActionBlock
	}
	if verdict.Action != "" {
		return verdict.Action
	}
	contentAction := ""
	if len(verdict.Matches) > 0 || len(verdict.Inject) > 0 {
		contentAction = configuredAction
	}
	if len(verdict.AddressFindings) == 0 {
		return contentAction
	}
	addrAction := addressprotect.StrictestAction(verdict.AddressFindings)
	if addrAction == config.ActionBlock {
		return config.ActionBlock
	}
	if contentAction != "" {
		return contentAction
	}
	if addrAction != "" {
		return addrAction
	}
	return configuredAction
}

func scanMCPResourceURI(ctx context.Context, method string, params json.RawMessage, sc *scanner.Scanner) []scanner.Result {
	if sc == nil || method != methodResourcesRead {
		return nil
	}
	trimmed := bytes.TrimSpace(params)
	if len(trimmed) == 0 || string(trimmed) == jsonrpc.Null {
		return mcpResourceURIParserFinding("missing resources/read params")
	}
	if err := redact.NoDuplicateJSONKeys(trimmed); err != nil && redact.IsDuplicateKeyBlock(err) {
		return []scanner.Result{{
			Allowed: false,
			Reason:  fmt.Sprintf("duplicate resource URI key: %v", err),
			Scanner: scanner.ScannerParser,
		}}
	}
	var req struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return mcpResourceURIParserFinding(fmt.Sprintf("invalid resources/read params: %v", err))
	}
	uri := strings.TrimSpace(req.URI)
	if uri == "" {
		return mcpResourceURIParserFinding("missing resources/read uri")
	}
	lower := strings.ToLower(uri)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return nil
	}
	if result := sc.Scan(ctx, uri); !result.Allowed {
		return []scanner.Result{result}
	}
	return nil
}

func mcpResourceURIParserFinding(reason string) []scanner.Result {
	return []scanner.Result{{
		Allowed: false,
		Reason:  reason,
		Scanner: scanner.ScannerParser,
	}}
}

// ScanRequest parses a JSON-RPC 2.0 request and scans its params for
// DLP patterns, injection patterns, and env secret leaks. Fail-closed
// on parse errors (configurable via onParseError).
func ScanRequest(ctx context.Context, line []byte, sc *scanner.Scanner, action, onParseError string) InputVerdict {
	return scanRequestForAgent(ctx, line, sc, action, onParseError, "")
}

func scanRequestForAgent(ctx context.Context, line []byte, sc *scanner.Scanner, action, onParseError, agentID string) InputVerdict {
	// Detect batch request (JSON array).
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		ctx = withMCPRequestWarnContext(ctx, "batch")
		return scanRequestBatch(ctx, trimmed, sc, action, onParseError, agentID)
	}
	recoveredID := recoverTopLevelJSONRPCID(trimmed)

	// Fail closed on duplicate envelope keys before json.Unmarshal would
	// silently collapse them. A duplicate `method` or `params` lets an
	// attacker hide a tools/call with secret-bearing arguments behind a
	// benign sibling that wins last-wins, while upstream first-wins
	// parsers still see the real attack. external review C-1.
	//
	// Only block on actual duplicate-key matches; let malformed-JSON
	// errors flow through to the existing parse-error path below so
	// telemetry stays attributable to the right cause.
	if err := redact.NoDuplicateJSONKeys(trimmed); err != nil && redact.IsDuplicateKeyBlock(err) {
		return InputVerdict{ID: recoveredID, Clean: false, Error: fmt.Sprintf("duplicate JSON object key: %v", err)}
	}

	var rpc jsonrpc.RPCResponse // Reuse struct - has Method and Params fields.
	if err := json.Unmarshal(trimmed, &rpc); err != nil {
		if onParseError == config.ActionForward {
			// Still scan raw text for secrets/injection before forwarding.
			return scanRawBeforeForward(ctx, trimmed, sc, action)
		}
		return InputVerdict{ID: recoveredID, Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonrpc.Version {
		if onParseError == config.ActionForward {
			// Still scan raw text for secrets/injection before forwarding.
			return scanRawBeforeForward(ctx, trimmed, sc, action)
		}
		return InputVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 message: jsonrpc=%q", rpc.JSONRPC),
		}
	}

	ctx = withMCPRequestWarnContext(ctx, mcpWarnResource(rpc.Method, trimmed))

	// No params - but result/error/unknown fields may carry exfiltrable
	// content (e.g., a compromised agent sending response-shaped messages).
	// Extract individual string values and scan each one separately so that
	// encoded-secret detection (base64, hex) works on field values, not on
	// the whole JSON blob (which is never valid base64/hex as a unit).
	if len(rpc.Params) == 0 || string(rpc.Params) == jsonrpc.Null {
		raw := string(trimmed)

		// Extract individual strings for per-field encoded DLP checks.
		extracted := extract.AllStringsFromJSONResult(trimmed)
		if extracted.Truncated {
			return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: false, Action: config.ActionBlock, Error: uninspectableJSONDepthReason}
		}
		strs := extracted.Strings
		joined := joinStrings(strs)

		// Run DLP on joined strings first (catches raw patterns).
		dlpResult := sc.ScanTextForDLP(ctx, joined)

		// Catch secrets split across multiple JSON fields.
		dlpResult = scanSplitSecret(ctx, trimmed, joined, sc, dlpResult)

		// Scan each extracted string individually for encoded secrets
		// (base64, hex). The joined string is not valid base64/hex as a
		// unit, so encoding checks only work on individual field values.
		if dlpResult.Clean {
			for _, s := range strs {
				if r := sc.ScanTextForDLP(ctx, s); !r.Clean {
					dlpResult = r
					break
				}
			}
		}

		// Fall back to scanning full raw JSON for DLP patterns that span
		// across JSON structure (catches patterns split by JSON syntax).
		// Also unescape JSON \uXXXX sequences so DLP patterns match
		// secrets encoded with JSON unicode escapes (parser differential fix).
		if dlpResult.Clean {
			dlpResult = sc.ScanTextForDLP(ctx, raw)
		}
		if dlpResult.Clean {
			if unescaped := unescapeJSONUnicode(raw); unescaped != raw {
				dlpResult = sc.ScanTextForDLP(ctx, unescaped)
			}
		}

		// Run injection patterns on the full raw text (injection patterns
		// match phrases, not encoded blobs -- full text is appropriate).
		injResult := sc.ScanResponse(ctx, raw)

		// Also scan each extracted string individually for encoded injection
		// (e.g. base64-encoded phrases) that don't decode in the full blob.
		if injResult.Clean {
			for _, s := range strs {
				if r := sc.ScanResponse(ctx, s); !r.Clean {
					injResult = r
					break
				}
			}
		}

		if injResult.Failed() {
			return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: false, Action: config.ActionBlock, Error: "response scan incomplete: " + injResult.ScanError}
		}

		// Address poisoning detection. Empty agentID means global allowlist only.
		var addrFindings []addressprotect.Finding
		if checker := sc.AddressChecker(); checker != nil {
			addrResult := checker.CheckText(joined, agentID)
			if len(addrResult.Findings) > 0 {
				addrFindings = addrResult.Findings
			}
		}
		urlFindings := scanMCPResourceURI(ctx, rpc.Method, rpc.Params, sc)

		if dlpResult.Clean && injResult.Clean && len(addrFindings) == 0 && len(urlFindings) == 0 {
			return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: true}
		}
		var dlpMatches []scanner.TextDLPMatch
		var injMatches []scanner.ResponseMatch
		if !dlpResult.Clean {
			dlpMatches = dlpResult.Matches
		}
		if !injResult.Clean {
			injMatches = injResult.Matches
		}

		// Resolve strictest action: DLP/injection use MCP input action,
		// address findings carry their own per-verdict action.
		verdictAction := resolveInputVerdictAction(action, dlpMatches, injMatches, addrFindings, urlFindings)

		return InputVerdict{
			ID:              rpc.ID,
			Method:          rpc.Method,
			Clean:           false,
			Action:          verdictAction,
			Matches:         dlpMatches,
			Inject:          injMatches,
			URLFindings:     urlFindings,
			AddressFindings: addrFindings,
		}
	}

	// Extract all strings (keys + values) from params.
	extracted := extract.AllStringsFromJSONResult(rpc.Params)
	if extracted.Truncated {
		return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: false, Action: config.ActionBlock, Error: uninspectableJSONDepthReason}
	}
	strs := extracted.Strings
	if len(strs) == 0 {
		// Fallback: serialize params to string for non-string JSON values.
		strs = []string{string(rpc.Params)}
	}

	// Include method name and ID in DLP scan - agents can exfiltrate
	// secrets by encoding them into method names or request IDs.
	if rpc.Method != "" {
		strs = append(strs, rpc.Method)
	}
	if len(rpc.ID) > 0 && string(rpc.ID) != jsonrpc.Null {
		strs = append(strs, string(rpc.ID))
	}

	joined := joinStrings(strs)

	// Run DLP patterns + env leak checks.
	dlpResult := sc.ScanTextForDLP(ctx, joined)

	// Catch secrets split across multiple JSON fields.
	dlpResult = scanSplitSecret(ctx, rpc.Params, joined, sc, dlpResult)

	// Scan each extracted string individually for encoded secrets (base64,
	// hex). The joined string is not valid base64/hex as a unit, so encoding
	// checks only work on individual field values.
	if dlpResult.Clean {
		for _, s := range strs {
			if r := sc.ScanTextForDLP(ctx, s); !r.Clean {
				dlpResult = r
			}
		}
	}

	// Run injection patterns (reuses response scanning patterns).
	// First scan joined text for injection phrases that span fields.
	injResult := sc.ScanResponse(ctx, joined)

	// Also scan each extracted string individually for injection. Catches
	// encoded injection (e.g. base64) in a single field that doesn't decode
	// cleanly when concatenated with other fields.
	if injResult.Clean {
		for _, s := range strs {
			if r := sc.ScanResponse(ctx, s); !r.Clean {
				injResult = r
				break
			}
		}
	}

	if injResult.Failed() {
		return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: false, Action: config.ActionBlock, Error: "response scan incomplete: " + injResult.ScanError}
	}

	var dlpMatches []scanner.TextDLPMatch
	var injMatches []scanner.ResponseMatch

	if !dlpResult.Clean {
		dlpMatches = dlpResult.Matches
	}
	if !injResult.Clean {
		injMatches = injResult.Matches
	}

	// Run address poisoning detection alongside DLP.
	var addrFindings []addressprotect.Finding
	if checker := sc.AddressChecker(); checker != nil {
		addrResult := checker.CheckText(joined, agentID)
		if len(addrResult.Findings) > 0 {
			addrFindings = addrResult.Findings
		}
	}
	urlFindings := scanMCPResourceURI(ctx, rpc.Method, rpc.Params, sc)

	if len(dlpMatches) == 0 && len(injMatches) == 0 && len(addrFindings) == 0 && len(urlFindings) == 0 {
		return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: true}
	}

	// Resolve the strictest action: DLP/injection use the MCP input action,
	// address findings carry their own per-verdict action (block or warn).
	// The strictest across all finding types wins.
	verdictAction := resolveInputVerdictAction(action, dlpMatches, injMatches, addrFindings, urlFindings)

	return InputVerdict{
		ID:              rpc.ID,
		Method:          rpc.Method,
		Clean:           false,
		Action:          verdictAction,
		Matches:         dlpMatches,
		Inject:          injMatches,
		URLFindings:     urlFindings,
		AddressFindings: addrFindings,
	}
}

// scanRawBeforeForward scans the raw bytes of an unparseable request for
// DLP patterns and injection before forwarding in on_parse_error=forward mode.
// This prevents malformed JSON from being a trivial bypass for all scanning.
// Extracts individual strings for per-field encoded DLP checks (base64, hex).
func scanRawBeforeForward(ctx context.Context, raw []byte, sc *scanner.Scanner, action string) InputVerdict {
	text := string(raw)
	recoveredID := recoverTopLevelJSONRPCID(bytes.TrimSpace(raw))

	// Extract individual strings for encoded DLP checks.
	extracted := extract.AllStringsFromJSONResult(raw)
	if extracted.Truncated {
		return InputVerdict{ID: recoveredID, Clean: false, Action: config.ActionBlock, Error: uninspectableJSONDepthReason}
	}
	strs := extracted.Strings
	joined := joinStrings(strs)

	dlpResult := sc.ScanTextForDLP(ctx, joined)

	// Catch secrets split across multiple JSON fields.
	dlpResult = scanSplitSecret(ctx, raw, joined, sc, dlpResult)

	// Scan each extracted string individually for encoded secrets.
	if dlpResult.Clean {
		for _, s := range strs {
			if r := sc.ScanTextForDLP(ctx, s); !r.Clean {
				dlpResult = r
			}
		}
	}

	// Fall back to full raw text for cross-structure patterns.
	if dlpResult.Clean {
		dlpResult = sc.ScanTextForDLP(ctx, text)
	}
	// JSON unicode unescape: resolve \uXXXX sequences in raw text so DLP
	// patterns match secrets encoded with JSON unicode escapes.
	if dlpResult.Clean {
		if unescaped := unescapeJSONUnicode(text); unescaped != text {
			dlpResult = sc.ScanTextForDLP(ctx, unescaped)
		}
	}

	injResult := sc.ScanResponse(ctx, text)

	// JSON unicode unescape for injection scanning: same parser differential
	// fix as DLP above. \u0069gnore → "ignore" must be caught.
	if injResult.Clean {
		if unescaped := unescapeJSONUnicode(text); unescaped != text {
			injResult = sc.ScanResponse(ctx, unescaped)
		}
	}

	// Also scan each extracted string individually for encoded injection
	// (e.g. base64-encoded phrases) that don't decode in the full blob.
	if injResult.Clean {
		for _, s := range strs {
			if r := sc.ScanResponse(ctx, s); !r.Clean {
				injResult = r
				break
			}
		}
	}

	if injResult.Failed() {
		return InputVerdict{ID: recoveredID, Clean: false, Action: config.ActionBlock, Error: "response scan incomplete: " + injResult.ScanError}
	}

	var dlpMatches []scanner.TextDLPMatch
	var injMatches []scanner.ResponseMatch

	if !dlpResult.Clean {
		dlpMatches = dlpResult.Matches
	}
	if !injResult.Clean {
		injMatches = injResult.Matches
	}

	if len(dlpMatches) == 0 && len(injMatches) == 0 {
		return InputVerdict{ID: recoveredID, Clean: true}
	}

	return InputVerdict{
		ID:      recoveredID,
		Clean:   false,
		Action:  mcpInputVerdictAction(action, dlpMatches, injMatches),
		Matches: dlpMatches,
		Inject:  injMatches,
	}
}

// scanRequestBatch scans a JSON-RPC 2.0 batch request (array of requests).
func scanRequestBatch(ctx context.Context, line []byte, sc *scanner.Scanner, action, onParseError, agentID string) InputVerdict {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		if onParseError == config.ActionForward {
			return scanRawBeforeForward(ctx, line, sc, action)
		}
		return InputVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON batch: %v", err)}
	}

	if len(batch) == 0 {
		return InputVerdict{Clean: true}
	}

	var allDLP []scanner.TextDLPMatch
	var allInj []scanner.ResponseMatch
	var allURL []scanner.Result
	var allAddr []addressprotect.Finding
	var firstID json.RawMessage
	var hasError bool
	var firstError string
	var batchAction string // track strictest action across batch elements

	for _, elem := range batch {
		v := scanRequestForAgent(ctx, elem, sc, action, onParseError, agentID)
		if firstID == nil && len(v.ID) > 0 {
			firstID = v.ID
		}
		if v.Action != "" {
			if batchAction == "" {
				batchAction = v.Action
			} else if v.Action == config.ActionBlock {
				batchAction = config.ActionBlock
			}
		}
		if v.Error != "" {
			hasError = true
			if firstError == "" {
				firstError = v.Error
			}
		}
		if !v.Clean && v.Error == "" {
			allDLP = append(allDLP, v.Matches...)
			allInj = append(allInj, v.Inject...)
			allURL = append(allURL, v.URLFindings...)
			allAddr = append(allAddr, v.AddressFindings...)
		}
	}

	if len(allDLP) == 0 && len(allInj) == 0 && len(allURL) == 0 && len(allAddr) == 0 {
		if hasError {
			errText := "one or more batch elements failed to parse"
			if firstError == uninspectableJSONDepthReason {
				errText = uninspectableJSONDepthReason
			}
			return InputVerdict{ID: firstID, Clean: false, Action: batchAction, Error: errText}
		}
		return InputVerdict{ID: firstID, Clean: true}
	}
	if batchAction == "" {
		batchAction = action
	}
	v := InputVerdict{
		ID: firstID, Clean: false, Action: batchAction,
		Matches: allDLP, Inject: allInj, URLFindings: allURL, AddressFindings: allAddr,
	}
	if hasError {
		v.Error = "one or more batch elements also failed to parse"
	}
	return v
}

// maxPairwiseSplitFields caps exhaustive pairwise split-secret scanning.
// The pairwise strategy is O(n^2), so larger inputs cannot be safely inspected
// without a first-class denial. Sampling a subset would create an evasion gap.
const maxPairwiseSplitFields = 64

// scanSplitSecret checks for secrets split across multiple JSON fields.
// Two strategies:
//  1. Sorted-key concatenation (original): joins all values without separators.
//  2. Pairwise concatenation: tries both orderings (a+b, b+a) for every pair
//     of field values, catching splits where key names defeat alphabetical sort.
//
// Returns the original result if already dirty or if no new patterns found.
func scanSplitSecret(ctx context.Context, raw json.RawMessage, joined string, sc *scanner.Scanner, result scanner.TextDLPResult) scanner.TextDLPResult {
	if !result.Clean {
		return result
	}
	extracted := jsonrpc.ExtractStringsFromJSONResult(raw)
	if extracted.Truncated {
		return scanner.TextDLPResult{
			Clean: false,
			Matches: []scanner.TextDLPMatch{{
				PatternName: uninspectableJSONDepthReason,
				Severity:    config.SeverityCritical,
			}},
		}
	}
	vals := extracted.Strings
	if len(vals) <= 1 {
		return result
	}

	// Strategy 1: sorted-key concatenation (catches N-field splits in sorted order).
	concat := strings.Join(vals, "")
	if concat != joined {
		if r := sc.ScanTextForDLP(ctx, concat); !r.Clean {
			return r
		}
	}
	if len(vals) > maxPairwiseSplitFields {
		return scanner.TextDLPResult{
			Clean: false,
			Matches: []scanner.TextDLPMatch{{
				PatternName: uninspectableSplitSecretFieldsReason,
				Severity:    config.SeverityCritical,
			}},
		}
	}

	// Strategy 2: pairwise concatenation (catches 2-field splits regardless of key order).
	for i := 0; i < len(vals); i++ {
		if len(vals[i]) == 0 {
			continue
		}
		for j := i + 1; j < len(vals); j++ {
			if len(vals[j]) == 0 {
				continue
			}
			// Try both orderings: vals[i]+vals[j] and vals[j]+vals[i].
			if r := sc.ScanTextForDLP(ctx, vals[i]+vals[j]); !r.Clean {
				return r
			}
			if r := sc.ScanTextForDLP(ctx, vals[j]+vals[i]); !r.Clean {
				return r
			}
		}
	}

	return result
}
