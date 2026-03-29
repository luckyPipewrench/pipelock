// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package mcp provides scanning of MCP (Model Context Protocol) JSON-RPC 2.0
// responses for prompt injection. It extracts text content from tool result
// blocks and runs them through scanner.ScanResponse for pattern matching.
package mcp

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/provenance"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ScanResponse parses a single JSON-RPC 2.0 response and scans its text
// content for prompt injection. Parse errors produce a verdict with Clean=false
// and the Error field set. Both result content and error messages are scanned.
// Server notifications (method+params, no id) are also scanned.
// Batch responses (JSON arrays) are detected and each element scanned individually.
func ScanResponse(line []byte, sc *scanner.Scanner) jsonrpc.ScanVerdict {
	// Detect batch response (JSON-RPC 2.0 batch = JSON array).
	if len(line) > 0 && line[0] == '[' {
		return scanBatch(line, sc)
	}

	var rpc jsonrpc.RPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonrpc.Version {
		return jsonrpc.ScanVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 response: jsonrpc=%q", rpc.JSONRPC),
		}
	}

	// Extract text from result (handles standard ToolResult and arbitrary shapes).
	text := jsonrpc.ExtractText(rpc.Result)

	// Also scan error messages for prompt injection.
	// Attackers can inject via error.message and error.data returned by malicious
	// tool servers. Falls back to recursive string extraction for non-standard
	// error shapes (e.g., plain string error), matching the Result field pattern.
	if len(rpc.Error) > 0 && string(rpc.Error) != jsonrpc.Null {
		var rpcErr jsonrpc.RPCError
		if err := json.Unmarshal(rpc.Error, &rpcErr); err == nil && rpcErr.Message != "" {
			if text != "" {
				text += "\n"
			}
			text += rpcErr.Message
			// Also scan error.data if present.
			if errData := jsonrpc.ExtractText(rpcErr.Data); errData != "" {
				text += "\n" + errData
			}
		} else {
			// Fallback: extract all strings from non-standard error shapes.
			if errText := jsonrpc.ExtractText(rpc.Error); errText != "" {
				if text != "" {
					text += "\n"
				}
				text += errText
			}
		}
	}

	// Scan notification params for injection content.
	// MCP server notifications (method+params, no id) can carry payloads.
	if len(rpc.Params) > 0 && string(rpc.Params) != jsonrpc.Null {
		if paramsText := jsonrpc.ExtractText(rpc.Params); paramsText != "" {
			if text != "" {
				text += "\n"
			}
			text += paramsText
		}
	}

	if text == "" {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}
	}

	result := sc.ScanResponse(context.Background(), text)
	if result.Clean {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}
	}

	return jsonrpc.ScanVerdict{
		ID:      rpc.ID,
		Clean:   false,
		Action:  sc.ResponseAction(),
		Matches: result.Matches,
	}
}

// scanToolsListNonToolFields scans a tools/list response for injection in
// non-tool fields (error, params, and any sibling keys in result besides "tools").
// Tool descriptions are scanned separately by the dedicated tool scanning
// subsystem (internal/mcp/tools), so we skip result.tools to avoid FPs from
// instructional text. However, a malicious server can inject into sibling fields
// like result.note or result.cursor, so those must be scanned.
func scanToolsListNonToolFields(line []byte, sc *scanner.Scanner) jsonrpc.ScanVerdict {
	var rpc jsonrpc.RPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonrpc.Version {
		return jsonrpc.ScanVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 response: jsonrpc=%q", rpc.JSONRPC),
		}
	}

	var text string

	// Scan non-"tools" sibling fields in the result object.
	// A malicious server can include extra fields alongside tools[].
	// Keys are sorted for deterministic concatenation order.
	if len(rpc.Result) > 0 && string(rpc.Result) != jsonrpc.Null {
		var resultMap map[string]json.RawMessage
		if json.Unmarshal(rpc.Result, &resultMap) == nil {
			keys := make([]string, 0, len(resultMap))
			for k := range resultMap {
				if k != "tools" {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, key := range keys {
				if siblingText := jsonrpc.ExtractText(resultMap[key]); siblingText != "" {
					if text != "" {
						text += "\n"
					}
					text += siblingText
				}
			}
		}
	}

	// Scan error field (injection can hide in error messages).
	if len(rpc.Error) > 0 && string(rpc.Error) != jsonrpc.Null {
		var rpcErr jsonrpc.RPCError
		if err := json.Unmarshal(rpc.Error, &rpcErr); err == nil && rpcErr.Message != "" {
			if text != "" {
				text += "\n"
			}
			text += rpcErr.Message
			if errData := jsonrpc.ExtractText(rpcErr.Data); errData != "" {
				text += "\n" + errData
			}
		} else if errText := jsonrpc.ExtractText(rpc.Error); errText != "" {
			if text != "" {
				text += "\n"
			}
			text += errText
		}
	}

	// Scan params (server notifications can carry payloads).
	if len(rpc.Params) > 0 && string(rpc.Params) != jsonrpc.Null {
		if paramsText := jsonrpc.ExtractText(rpc.Params); paramsText != "" {
			if text != "" {
				text += "\n"
			}
			text += paramsText
		}
	}

	if text == "" {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}
	}

	result := sc.ScanResponse(context.Background(), text)
	if result.Clean {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}
	}

	return jsonrpc.ScanVerdict{
		ID:      rpc.ID,
		Clean:   false,
		Action:  sc.ResponseAction(),
		Matches: result.Matches,
	}
}

// scanBatch scans a JSON-RPC 2.0 batch response (array of responses).
// Returns a combined verdict aggregating matches from all elements.
func scanBatch(line []byte, sc *scanner.Scanner) jsonrpc.ScanVerdict {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON batch: %v", err)}
	}

	if len(batch) == 0 {
		return jsonrpc.ScanVerdict{Clean: true}
	}

	var allMatches []scanner.ResponseMatch
	var firstID json.RawMessage
	var action string
	var hasError bool

	for _, elem := range batch {
		v := ScanResponse(elem, sc)
		if firstID == nil && len(v.ID) > 0 {
			firstID = v.ID
		}
		if v.Error != "" {
			hasError = true
		}
		if !v.Clean && v.Error == "" {
			allMatches = append(allMatches, v.Matches...)
			if action == "" {
				action = v.Action
			}
		}
	}

	if len(allMatches) == 0 {
		if hasError {
			return jsonrpc.ScanVerdict{ID: firstID, Clean: false, Error: "one or more batch elements failed to parse"}
		}
		return jsonrpc.ScanVerdict{ID: firstID, Clean: true}
	}
	return jsonrpc.ScanVerdict{
		ID: firstID, Clean: false, Action: action, Matches: allMatches,
	}
}

// ScanStream reads newline-delimited JSON-RPC 2.0 responses from r, scans
// each for prompt injection, and writes results to w. In text mode, only
// errors and detections are written (clean lines are silent). In JSON mode,
// every scanned line produces an output object. Returns true if any injection
// was detected. Parse errors are reported but do not count as injection.
func ScanStream(r io.Reader, w io.Writer, sc *scanner.Scanner, jsonOutput bool) (bool, error) {
	lineScanner := bufio.NewScanner(r)
	lineScanner.Buffer(make([]byte, 0, 64*1024), transport.MaxLineSize)

	foundInjection := false
	lineNum := 0

	for lineScanner.Scan() {
		lineNum++
		line := strings.TrimSpace(lineScanner.Text())
		if line == "" {
			continue
		}

		verdict := ScanResponse([]byte(line), sc)
		verdict.Line = lineNum

		if !verdict.Clean && verdict.Error == "" {
			foundInjection = true
		}

		if jsonOutput {
			data, err := json.Marshal(verdict)
			if err != nil {
				return foundInjection, fmt.Errorf("marshaling verdict: %w", err)
			}
			data = append(data, '\n')
			if _, err := w.Write(data); err != nil {
				return foundInjection, fmt.Errorf("writing verdict: %w", err)
			}
		} else {
			if err := writeTextVerdict(w, verdict); err != nil {
				return foundInjection, err
			}
		}
	}

	if err := lineScanner.Err(); err != nil {
		return foundInjection, fmt.Errorf("reading input: %w", err)
	}

	return foundInjection, nil
}

// A2AResponseOpts groups A2A-specific dependencies for response scanning.
// All fields are nil-safe: when nil, A2A response scanning is skipped.
type A2AResponseOpts struct {
	Cfg      *config.A2AScanning
	Baseline *CardBaseline
	// CardKey identifies the Agent Card origin for drift detection.
	// Only used for GetExtendedAgentCard responses.
	CardKey cardCacheKey
	// Method is the JSON-RPC method from the corresponding request.
	// When non-empty, allows precise A2A response routing without
	// relying on response shape heuristics.
	Method string
}

// methodGetExtendedAgentCard is the A2A method that returns an Agent Card.
const methodGetExtendedAgentCard = "GetExtendedAgentCard"

// ScanResponseA2A scans a JSON-RPC 2.0 response with optional A2A-aware
// routing. When a2aOpts is non-nil and the response matches an A2A method
// (by tracked method name or response shape), field-aware A2A scanning runs
// instead of generic text extraction. Falls back to ScanResponse for
// non-A2A traffic or when A2A scanning is disabled.
func ScanResponseA2A(line []byte, sc *scanner.Scanner, a2aOpts *A2AResponseOpts) jsonrpc.ScanVerdict {
	// Nil-safe: no A2A config means standard MCP scanning.
	if a2aOpts == nil || a2aOpts.Cfg == nil || !a2aOpts.Cfg.Enabled {
		return ScanResponse(line, sc)
	}

	// Route by tracked method name when available (most precise).
	if a2aOpts.Method != "" && IsA2AMethod(a2aOpts.Method) {
		return scanA2AResponseDispatch(line, sc, a2aOpts)
	}

	// Fallback: detect A2A response shape from result structure.
	if isA2AResponseShape(line) {
		return scanA2AResponseDispatch(line, sc, a2aOpts)
	}

	return ScanResponse(line, sc)
}

// scanA2AResponseDispatch routes an A2A response through the appropriate
// scanner based on method type.
func scanA2AResponseDispatch(line []byte, sc *scanner.Scanner, a2aOpts *A2AResponseOpts) jsonrpc.ScanVerdict {
	rpcID := extractRPCID(line)

	// GetExtendedAgentCard: route through Agent Card scanner.
	if a2aOpts.Method == methodGetExtendedAgentCard {
		// Extract result body for card scanning.
		var rpc jsonrpc.RPCResponse
		if err := json.Unmarshal(line, &rpc); err != nil {
			return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
		}
		// Scan error payloads: a malicious server can inject content via
		// error.message and error.data. Don't skip scanning just because
		// the response is an error instead of a result.
		if len(rpc.Error) > 0 && string(rpc.Error) != jsonrpc.Null {
			errResult := ScanA2AResponseBody(context.Background(), line, sc, a2aOpts.Cfg)
			return a2aScanToVerdict(rpcID, errResult)
		}
		if len(rpc.Result) == 0 || string(rpc.Result) == jsonrpc.Null {
			return jsonrpc.ScanVerdict{ID: rpcID, Clean: true}
		}
		cardResult := ScanAgentCard(
			context.Background(), rpc.Result, sc,
			a2aOpts.Baseline, a2aOpts.CardKey, a2aOpts.Cfg,
		)
		return agentCardToVerdict(rpcID, cardResult, a2aOpts.Cfg)
	}

	// All other A2A methods: field-aware body scanning.
	result := ScanA2AResponseBody(context.Background(), line, sc, a2aOpts.Cfg)
	return a2aScanToVerdict(rpcID, result)
}

// isA2AResponseShape returns true if the JSON-RPC result object has fields
// characteristic of A2A protocol responses (task with status/artifacts/history,
// or an Agent Card shape with skills/supportedInterfaces).
func isA2AResponseShape(line []byte) bool {
	var probe struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(line, &probe) != nil || len(probe.Result) == 0 {
		return false
	}

	// Check for A2A task shape: presence of status + (artifacts OR history).
	var resultFields map[string]json.RawMessage
	if json.Unmarshal(probe.Result, &resultFields) != nil {
		return false
	}

	_, hasStatus := resultFields["status"]
	_, hasArtifacts := resultFields["artifacts"]
	_, hasHistory := resultFields["history"]
	if hasStatus && (hasArtifacts || hasHistory) {
		return true
	}

	// Check for Agent Card shape: skills + supportedInterfaces.
	_, hasSkills := resultFields["skills"]
	_, hasInterfaces := resultFields["supportedInterfaces"]
	if hasSkills && hasInterfaces {
		return true
	}

	return false
}

// a2aScanToVerdict converts an A2AScanResult into a jsonrpc.ScanVerdict
// for use in the standard response forwarding pipeline.
func a2aScanToVerdict(rpcID json.RawMessage, result A2AScanResult) jsonrpc.ScanVerdict {
	if result.Clean {
		return jsonrpc.ScanVerdict{ID: rpcID, Clean: true}
	}

	var matches []scanner.ResponseMatch
	// Promote injection findings directly.
	matches = append(matches, result.InjectFindings...)
	// Wrap URL findings as ResponseMatch for the verdict.
	for _, u := range result.URLFindings {
		matches = append(matches, scanner.ResponseMatch{
			PatternName: u.Reason,
		})
	}
	// Wrap DLP findings as ResponseMatch for the verdict.
	for _, d := range result.DLPFindings {
		matches = append(matches, scanner.ResponseMatch{
			PatternName: d.PatternName,
		})
	}

	return jsonrpc.ScanVerdict{
		ID:      rpcID,
		Clean:   false,
		Action:  result.Action,
		Matches: matches,
	}
}

// agentCardToVerdict converts an AgentCardScanResult into a jsonrpc.ScanVerdict.
func agentCardToVerdict(rpcID json.RawMessage, result AgentCardScanResult, cfg *config.A2AScanning) jsonrpc.ScanVerdict {
	if result.Clean {
		return jsonrpc.ScanVerdict{ID: rpcID, Clean: true}
	}

	action := result.Action
	if action == "" && cfg != nil {
		action = cfg.Action
	}

	var matches []scanner.ResponseMatch
	if result.DriftDetected {
		matches = append(matches, scanner.ResponseMatch{
			PatternName: "a2a_card_drift",
		})
	}
	// Include field-level findings from the card scan.
	verdict := a2aScanToVerdict(rpcID, result.Findings)
	matches = append(matches, verdict.Matches...)

	return jsonrpc.ScanVerdict{
		ID:      rpcID,
		Clean:   false,
		Action:  action,
		Matches: matches,
	}
}

// writeTextVerdict writes a human-readable verdict to w.
// Clean lines produce no output; only findings are reported.
func writeTextVerdict(w io.Writer, v jsonrpc.ScanVerdict) error {
	if v.Clean {
		return nil
	}

	if v.Error != "" {
		_, err := fmt.Fprintf(w, "line %d: [ERROR] %s\n", v.Line, v.Error) //nolint:gosec // G705: CLI output, not web
		return err
	}

	names := make([]string, 0, len(v.Matches))
	for _, m := range v.Matches {
		names = append(names, m.PatternName)
	}
	_, err := fmt.Fprintf(w, "line %d: [INJECTION] %s (action: %s)\n", v.Line, strings.Join(names, ", "), v.Action) //nolint:gosec // G705: CLI output, not web
	return err
}

// ProvenanceVerdict holds the outcome of provenance verification on a
// tools/list response, including per-tool results for logging in warn mode.
type ProvenanceVerdict struct {
	// Block is true when the response should be blocked.
	Block bool
	// Action is the configured provenance action ("block" or "warn").
	Action string
	// Results contains per-tool verification outcomes.
	Results []provenance.VerificationResult
	// Error describes why blocking was triggered (empty when clean or warn-only).
	Error string
}

// VerifyToolsListProvenance runs cryptographic provenance verification on a
// tools/list response. It maps config.MCPToolProvenance to provenance.VerifyConfig,
// calls provenance.VerifyToolsList, and returns a ProvenanceVerdict.
//
// Returns a clean verdict (Block=false, nil Results) when cfg is nil or disabled.
// Parse errors and verification failures follow fail-closed semantics.
func VerifyToolsListProvenance(response []byte, cfg *config.MCPToolProvenance) ProvenanceVerdict {
	if cfg == nil || !cfg.Enabled {
		return ProvenanceVerdict{}
	}

	vcfg, err := mapProvenanceConfig(cfg)
	if err != nil {
		return ProvenanceVerdict{
			Block:  true,
			Action: cfg.Action,
			Error:  fmt.Sprintf("provenance config error: %v", err),
		}
	}

	results, err := provenance.VerifyToolsList(response, vcfg)
	if err != nil {
		// Fail closed: unparseable tools/list response blocks.
		return ProvenanceVerdict{
			Block:  true,
			Action: cfg.Action,
			Error:  fmt.Sprintf("provenance verification error: %v", err),
		}
	}

	if len(results) == 0 {
		// No tools in response — nothing to verify.
		return ProvenanceVerdict{
			Action:  cfg.Action,
			Results: results,
		}
	}

	shouldBlock, blockErr := provenance.ShouldBlock(results, cfg.Action)
	verdict := ProvenanceVerdict{
		Block:   shouldBlock,
		Action:  cfg.Action,
		Results: results,
	}
	if blockErr != nil {
		verdict.Error = blockErr.Error()
	}
	return verdict
}

// provenancePatternName is the pattern name used in ScanVerdict matches
// for provenance verification failures.
const provenancePatternName = "mcp_tool_provenance"

// ProvenanceVerdictToScanVerdict converts a ProvenanceVerdict into a
// jsonrpc.ScanVerdict for use in the standard response forwarding pipeline.
// The rpcID is extracted from the original response for correlation.
func ProvenanceVerdictToScanVerdict(pv ProvenanceVerdict, rpcID json.RawMessage) jsonrpc.ScanVerdict {
	if !pv.Block {
		return jsonrpc.ScanVerdict{ID: rpcID, Clean: true}
	}

	var matches []scanner.ResponseMatch
	for _, r := range pv.Results {
		if r.Status == provenance.StatusFailed || r.Status == provenance.StatusError ||
			(r.Status == provenance.StatusUnsigned && pv.Action == config.ActionBlock) {
			matches = append(matches, scanner.ResponseMatch{
				PatternName: provenancePatternName,
				MatchText:   fmt.Sprintf("%s: %s (%s)", r.ToolName, r.Status, r.Detail),
			})
		}
	}

	return jsonrpc.ScanVerdict{
		ID:      rpcID,
		Clean:   false,
		Action:  pv.Action,
		Matches: matches,
	}
}

// mapProvenanceConfig converts config.MCPToolProvenance to provenance.VerifyConfig.
// TrustedKeys are hex-encoded Ed25519 public keys; each is used as both the
// key ID and the decoded key value.
func mapProvenanceConfig(cfg *config.MCPToolProvenance) (provenance.VerifyConfig, error) {
	vcfg := provenance.VerifyConfig{
		Mode:        cfg.Mode,
		OfflineOnly: cfg.OfflineOnly,
	}

	if len(cfg.TrustedKeys) > 0 {
		vcfg.TrustedKeys = make(map[string]ed25519.PublicKey, len(cfg.TrustedKeys))
		for _, hexKey := range cfg.TrustedKeys {
			raw, err := hex.DecodeString(hexKey)
			if err != nil {
				return provenance.VerifyConfig{}, fmt.Errorf("decoding trusted key %q: %w", hexKey, err)
			}
			if len(raw) != ed25519.PublicKeySize {
				return provenance.VerifyConfig{}, fmt.Errorf(
					"trusted key %q: invalid length %d, want %d",
					hexKey, len(raw), ed25519.PublicKeySize,
				)
			}
			vcfg.TrustedKeys[hexKey] = ed25519.PublicKey(raw)
		}
	}

	return vcfg, nil
}
