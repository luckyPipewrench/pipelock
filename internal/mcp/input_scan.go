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
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

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

// ScanRequest parses a JSON-RPC 2.0 request and scans its params for
// DLP patterns, injection patterns, and env secret leaks. Fail-closed
// on parse errors (configurable via onParseError).
func ScanRequest(line []byte, sc *scanner.Scanner, action, onParseError string) InputVerdict {
	// Detect batch request (JSON array).
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return scanRequestBatch(trimmed, sc, action, onParseError)
	}

	var rpc jsonrpc.RPCResponse // Reuse struct — has Method and Params fields.
	if err := json.Unmarshal(trimmed, &rpc); err != nil {
		if onParseError == config.ActionForward {
			// Still scan raw text for secrets/injection before forwarding.
			return scanRawBeforeForward(trimmed, sc, action)
		}
		return InputVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonrpc.Version {
		if onParseError == config.ActionForward {
			// Still scan raw text for secrets/injection before forwarding.
			return scanRawBeforeForward(trimmed, sc, action)
		}
		return InputVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 message: jsonrpc=%q", rpc.JSONRPC),
		}
	}

	// No params — but result/error/unknown fields may carry exfiltrable
	// content (e.g., a compromised agent sending response-shaped messages).
	// Extract individual string values and scan each one separately so that
	// encoded-secret detection (base64, hex) works on field values, not on
	// the whole JSON blob (which is never valid base64/hex as a unit).
	if len(rpc.Params) == 0 || string(rpc.Params) == jsonrpc.Null {
		raw := string(trimmed)

		// Extract individual strings for per-field encoded DLP checks.
		strs := extract.AllStringsFromJSON(trimmed)
		joined := joinStrings(strs)

		// Run DLP on joined strings first (catches raw patterns).
		dlpResult := sc.ScanTextForDLP(context.Background(), joined)

		// Catch secrets split across multiple JSON fields.
		dlpResult = scanSplitSecret(trimmed, joined, sc, dlpResult)

		// Scan each extracted string individually for encoded secrets
		// (base64, hex). The joined string is not valid base64/hex as a
		// unit, so encoding checks only work on individual field values.
		if dlpResult.Clean {
			for _, s := range strs {
				if r := sc.ScanTextForDLP(context.Background(), s); !r.Clean {
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
			dlpResult = sc.ScanTextForDLP(context.Background(), raw)
		}
		if dlpResult.Clean {
			if unescaped := unescapeJSONUnicode(raw); unescaped != raw {
				dlpResult = sc.ScanTextForDLP(context.Background(), unescaped)
			}
		}

		// Run injection patterns on the full raw text (injection patterns
		// match phrases, not encoded blobs -- full text is appropriate).
		injResult := sc.ScanResponse(context.Background(), raw)

		// Also scan each extracted string individually for encoded injection
		// (e.g. base64-encoded phrases) that don't decode in the full blob.
		if injResult.Clean {
			for _, s := range strs {
				if r := sc.ScanResponse(context.Background(), s); !r.Clean {
					injResult = r
					break
				}
			}
		}

		// Address poisoning detection (agentID="" for stdio).
		var addrFindings []addressprotect.Finding
		if checker := sc.AddressChecker(); checker != nil {
			addrResult := checker.CheckText(joined, "")
			if len(addrResult.Findings) > 0 {
				addrFindings = addrResult.Findings
			}
		}

		if dlpResult.Clean && injResult.Clean && len(addrFindings) == 0 {
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
		verdictAction := ""
		if len(dlpMatches) > 0 || len(injMatches) > 0 {
			verdictAction = action
		}
		if addrAction := addressprotect.StrictestAction(addrFindings); addrAction != "" {
			if verdictAction == "" || addrAction == config.ActionBlock {
				verdictAction = addrAction
			}
		}

		return InputVerdict{
			ID:              rpc.ID,
			Method:          rpc.Method,
			Clean:           false,
			Action:          verdictAction,
			Matches:         dlpMatches,
			Inject:          injMatches,
			AddressFindings: addrFindings,
		}
	}

	// Extract all strings (keys + values) from params.
	strs := extract.AllStringsFromJSON(rpc.Params)
	if len(strs) == 0 {
		// Fallback: serialize params to string for non-string JSON values.
		strs = []string{string(rpc.Params)}
	}

	// Include method name and ID in DLP scan — agents can exfiltrate
	// secrets by encoding them into method names or request IDs.
	if rpc.Method != "" {
		strs = append(strs, rpc.Method)
	}
	if len(rpc.ID) > 0 && string(rpc.ID) != jsonrpc.Null {
		strs = append(strs, string(rpc.ID))
	}

	joined := joinStrings(strs)

	// Run DLP patterns + env leak checks.
	dlpResult := sc.ScanTextForDLP(context.Background(), joined)

	// Catch secrets split across multiple JSON fields.
	dlpResult = scanSplitSecret(rpc.Params, joined, sc, dlpResult)

	// Scan each extracted string individually for encoded secrets (base64,
	// hex). The joined string is not valid base64/hex as a unit, so encoding
	// checks only work on individual field values.
	if dlpResult.Clean {
		for _, s := range strs {
			if r := sc.ScanTextForDLP(context.Background(), s); !r.Clean {
				dlpResult = r
			}
		}
	}

	// Run injection patterns (reuses response scanning patterns).
	// First scan joined text for injection phrases that span fields.
	injResult := sc.ScanResponse(context.Background(), joined)

	// Also scan each extracted string individually for injection. Catches
	// encoded injection (e.g. base64) in a single field that doesn't decode
	// cleanly when concatenated with other fields.
	if injResult.Clean {
		for _, s := range strs {
			if r := sc.ScanResponse(context.Background(), s); !r.Clean {
				injResult = r
				break
			}
		}
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
	// agentID="" for MCP stdio (one agent per process, global allowlist only).
	var addrFindings []addressprotect.Finding
	if checker := sc.AddressChecker(); checker != nil {
		addrResult := checker.CheckText(joined, "")
		if len(addrResult.Findings) > 0 {
			addrFindings = addrResult.Findings
		}
	}

	if len(dlpMatches) == 0 && len(injMatches) == 0 && len(addrFindings) == 0 {
		return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: true}
	}

	// Resolve the strictest action: DLP/injection use the MCP input action,
	// address findings carry their own per-verdict action (block or warn).
	// The strictest across all finding types wins.
	verdictAction := ""
	if len(dlpMatches) > 0 || len(injMatches) > 0 {
		verdictAction = action
	}
	if addrAction := addressprotect.StrictestAction(addrFindings); addrAction != "" {
		if verdictAction == "" || addrAction == config.ActionBlock {
			verdictAction = addrAction
		}
	}

	return InputVerdict{
		ID:              rpc.ID,
		Method:          rpc.Method,
		Clean:           false,
		Action:          verdictAction,
		Matches:         dlpMatches,
		Inject:          injMatches,
		AddressFindings: addrFindings,
	}
}

// scanRawBeforeForward scans the raw bytes of an unparseable request for
// DLP patterns and injection before forwarding in on_parse_error=forward mode.
// This prevents malformed JSON from being a trivial bypass for all scanning.
// Extracts individual strings for per-field encoded DLP checks (base64, hex).
func scanRawBeforeForward(raw []byte, sc *scanner.Scanner, action string) InputVerdict {
	text := string(raw)

	// Extract individual strings for encoded DLP checks.
	strs := extract.AllStringsFromJSON(raw)
	joined := joinStrings(strs)

	dlpResult := sc.ScanTextForDLP(context.Background(), joined)

	// Catch secrets split across multiple JSON fields.
	dlpResult = scanSplitSecret(raw, joined, sc, dlpResult)

	// Scan each extracted string individually for encoded secrets.
	if dlpResult.Clean {
		for _, s := range strs {
			if r := sc.ScanTextForDLP(context.Background(), s); !r.Clean {
				dlpResult = r
			}
		}
	}

	// Fall back to full raw text for cross-structure patterns.
	if dlpResult.Clean {
		dlpResult = sc.ScanTextForDLP(context.Background(), text)
	}
	// JSON unicode unescape: resolve \uXXXX sequences in raw text so DLP
	// patterns match secrets encoded with JSON unicode escapes.
	if dlpResult.Clean {
		if unescaped := unescapeJSONUnicode(text); unescaped != text {
			dlpResult = sc.ScanTextForDLP(context.Background(), unescaped)
		}
	}

	injResult := sc.ScanResponse(context.Background(), text)

	// JSON unicode unescape for injection scanning: same parser differential
	// fix as DLP above. \u0069gnore → "ignore" must be caught.
	if injResult.Clean {
		if unescaped := unescapeJSONUnicode(text); unescaped != text {
			injResult = sc.ScanResponse(context.Background(), unescaped)
		}
	}

	// Also scan each extracted string individually for encoded injection
	// (e.g. base64-encoded phrases) that don't decode in the full blob.
	if injResult.Clean {
		for _, s := range strs {
			if r := sc.ScanResponse(context.Background(), s); !r.Clean {
				injResult = r
				break
			}
		}
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
		return InputVerdict{Clean: true}
	}

	return InputVerdict{
		Clean:   false,
		Action:  action,
		Matches: dlpMatches,
		Inject:  injMatches,
	}
}

// scanRequestBatch scans a JSON-RPC 2.0 batch request (array of requests).
func scanRequestBatch(line []byte, sc *scanner.Scanner, action, onParseError string) InputVerdict {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		if onParseError == config.ActionForward {
			return scanRawBeforeForward(line, sc, action)
		}
		return InputVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON batch: %v", err)}
	}

	if len(batch) == 0 {
		return InputVerdict{Clean: true}
	}

	var allDLP []scanner.TextDLPMatch
	var allInj []scanner.ResponseMatch
	var allAddr []addressprotect.Finding
	var firstID json.RawMessage
	var hasError bool
	var batchAction string // track strictest action across batch elements

	for _, elem := range batch {
		v := ScanRequest(elem, sc, action, onParseError)
		if firstID == nil && len(v.ID) > 0 {
			firstID = v.ID
		}
		if v.Error != "" {
			hasError = true
		}
		if !v.Clean && v.Error == "" {
			allDLP = append(allDLP, v.Matches...)
			allInj = append(allInj, v.Inject...)
			allAddr = append(allAddr, v.AddressFindings...)
			if v.Action != "" {
				if batchAction == "" {
					batchAction = v.Action
				} else if v.Action == config.ActionBlock {
					batchAction = config.ActionBlock
				}
			}
		}
	}

	if len(allDLP) == 0 && len(allInj) == 0 && len(allAddr) == 0 {
		if hasError {
			return InputVerdict{ID: firstID, Clean: false, Error: "one or more batch elements failed to parse"}
		}
		return InputVerdict{ID: firstID, Clean: true}
	}
	if batchAction == "" {
		batchAction = action
	}
	v := InputVerdict{
		ID: firstID, Clean: false, Action: batchAction,
		Matches: allDLP, Inject: allInj, AddressFindings: allAddr,
	}
	if hasError {
		v.Error = "one or more batch elements also failed to parse"
	}
	return v
}

// maxPairwiseSplitFields caps the number of field values considered for
// pairwise split-secret scanning. O(n^2) pairs, but each DLP scan is fast.
// When field count exceeds this cap, edge sampling takes the first and last
// half (32 each) so the effective pairwise coverage is 64 fields.
const maxPairwiseSplitFields = 64

// scanSplitSecret checks for secrets split across multiple JSON fields.
// Two strategies:
//  1. Sorted-key concatenation (original): joins all values without separators.
//  2. Pairwise concatenation: tries both orderings (a+b, b+a) for every pair
//     of field values, catching splits where key names defeat alphabetical sort.
//
// Returns the original result if already dirty or if no new patterns found.
func scanSplitSecret(raw json.RawMessage, joined string, sc *scanner.Scanner, result scanner.TextDLPResult) scanner.TextDLPResult {
	if !result.Clean {
		return result
	}
	vals := jsonrpc.ExtractStringsFromJSON(raw)
	if len(vals) <= 1 {
		return result
	}

	// Strategy 1: sorted-key concatenation (catches N-field splits in sorted order).
	concat := strings.Join(vals, "")
	if concat != joined {
		if r := sc.ScanTextForDLP(context.Background(), concat); !r.Clean {
			return r
		}
	}

	// Strategy 2: pairwise concatenation (catches 2-field splits regardless of key order).
	// When field count exceeds the cap, scan edges (first + last N/2 fields)
	// rather than truncating. Attackers padding with filler fields likely place
	// the secret halves near the edges of the sorted key space.
	pairVals := vals
	if len(pairVals) > maxPairwiseSplitFields {
		half := maxPairwiseSplitFields / 2
		edge := make([]string, 0, maxPairwiseSplitFields)
		edge = append(edge, vals[:half]...)
		edge = append(edge, vals[len(vals)-half:]...)
		pairVals = edge
	}
	for i := 0; i < len(pairVals); i++ {
		if len(pairVals[i]) == 0 {
			continue
		}
		for j := i + 1; j < len(pairVals); j++ {
			if len(pairVals[j]) == 0 {
				continue
			}
			// Try both orderings: vals[i]+vals[j] and vals[j]+vals[i].
			if r := sc.ScanTextForDLP(context.Background(), pairVals[i]+pairVals[j]); !r.Clean {
				return r
			}
			if r := sc.ScanTextForDLP(context.Background(), pairVals[j]+pairVals[i]); !r.Clean {
				return r
			}
		}
	}

	return result
}
