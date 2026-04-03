// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package tools provides MCP tool description scanning for poisoning detection,
// rug-pull (drift) detection, and session binding (tool inventory validation).
package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ToolDef represents a single tool definition in an MCP tools/list response.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// toolsListResult is the result payload of an MCP tools/list response.
type toolsListResult struct {
	Tools []ToolDef `json:"tools"`
}

// ToolScanMatch describes a finding in a specific tool definition.
type ToolScanMatch struct {
	ToolName      string                  `json:"tool_name"`
	Injection     []scanner.ResponseMatch `json:"injection,omitempty"`
	ToolPoison    []string                `json:"tool_poison,omitempty"`
	DriftDetected bool                    `json:"drift_detected,omitempty"`
	PreviousHash  string                  `json:"previous_hash,omitempty"`
	CurrentHash   string                  `json:"current_hash,omitempty"`
	DriftDetail   string                  `json:"drift_detail,omitempty"`
}

// ToolScanResult describes the outcome of scanning a tools/list response.
type ToolScanResult struct {
	IsToolsList bool            `json:"is_tools_list"`
	Clean       bool            `json:"clean"`
	Matches     []ToolScanMatch `json:"matches,omitempty"`
	RPCID       json.RawMessage `json:"-"` // parsed ID for block responses (avoids re-parse)
	ToolNames   []string        `json:"-"` // tool names from tools/list (for session binding)
}

// ExtraPoisonPattern is a tool-poison pattern from a community rule bundle.
type ExtraPoisonPattern struct {
	Name          string
	RuleID        string // namespaced rule ID
	Re            *regexp.Regexp
	ScanField     string // "description" or "name"
	Bundle        string
	BundleVersion string
}

// ToolScanConfig holds configuration for MCP tool description scanning.
// A nil ToolScanConfig disables tool scanning entirely.
// Session binding fields are optional: when BindingUnknownAction is non-empty,
// tools/call requests are validated against the baseline captured from tools/list.
type ToolScanConfig struct {
	Baseline    *ToolBaseline
	Action      string // warn, block
	DetectDrift bool

	// Session binding (optional). When BindingUnknownAction is non-empty,
	// RunProxy wires tools/call validation into the input scanner.
	BindingUnknownAction    string // warn, block — action for unknown tool calls
	BindingNoBaselineAction string // warn, block — action before baseline established

	// ExtraPoison holds tool-poison patterns from community rule bundles.
	ExtraPoison []*ExtraPoisonPattern
}

// ToolBaseline tracks SHA256 hashes of tool definitions for rug pull detection
// and session binding (known tool inventory). Safe for concurrent use.
type ToolBaseline struct {
	mu          sync.Mutex
	hashes      map[string]string   // tool name → SHA256(description + inputSchema)
	descs       map[string]string   // tool name → last known description text
	params      map[string][]string // tool name → last known parameter names (sorted)
	knownTools  map[string]bool     // session binding: tool name set from first tools/list
	hasBaseline bool                // true after first SetKnownTools call
}

// NewToolBaseline creates a new empty tool baseline.
func NewToolBaseline() *ToolBaseline {
	return &ToolBaseline{
		hashes: make(map[string]string),
		descs:  make(map[string]string),
		params: make(map[string][]string),
	}
}

// maxBaselineTools caps the number of tracked tools to prevent unbounded
// memory growth from a malicious server sending unlimited unique tool names.
const maxBaselineTools = 10000

// ShouldSkip returns true if the tool name is unknown and the baseline is at
// capacity. Callers should skip expensive hash computation in this case to
// prevent CPU exhaustion from malicious servers flooding with unique tool names.
func (tb *ToolBaseline) ShouldSkip(name string) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	_, exists := tb.hashes[name]
	return !exists && len(tb.hashes) >= maxBaselineTools
}

// CheckAndUpdate stores a tool's hash and reports whether it changed.
// Returns (driftDetected, previousHash). On first insertion returns (false, "").
// New tools are silently dropped when the baseline exceeds maxBaselineTools.
func (tb *ToolBaseline) CheckAndUpdate(name, hash string) (bool, string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	prev, exists := tb.hashes[name]

	if !exists && len(tb.hashes) >= maxBaselineTools {
		return false, ""
	}

	tb.hashes[name] = hash

	if !exists {
		return false, ""
	}
	if prev != hash {
		return true, prev
	}
	return false, ""
}

// StoreDesc saves a tool's description text for later diff generation.
// Called alongside CheckAndUpdate. Respects maxBaselineTools capacity.
func (tb *ToolBaseline) StoreDesc(name, desc string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if _, exists := tb.descs[name]; !exists && len(tb.descs) >= maxBaselineTools {
		return
	}
	tb.descs[name] = desc
}

// StoreParams saves a tool's parameter names for later diff generation.
// Called alongside CheckAndUpdate. Respects maxBaselineTools capacity.
// Names should be pre-sorted for deterministic comparison.
func (tb *ToolBaseline) StoreParams(name string, paramNames []string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if _, exists := tb.params[name]; !exists && len(tb.params) >= maxBaselineTools {
		return
	}
	// Store a copy to prevent mutation.
	cp := make([]string, len(paramNames))
	copy(cp, paramNames)
	tb.params[name] = cp
}

// DiffSummary returns a human-readable summary of what changed between the
// stored description/params and the new ones. Returns "" if no previous data.
func (tb *ToolBaseline) DiffSummary(name, newDesc string, newParams []string) string {
	tb.mu.Lock()
	prevDesc, hasDesc := tb.descs[name]
	prevParams, hasParams := tb.params[name]
	tb.mu.Unlock()

	if !hasDesc && !hasParams {
		return ""
	}

	var parts []string

	// Description diff.
	if hasDesc {
		prevLen := len([]rune(prevDesc))
		newLen := len([]rune(newDesc))

		if prevDesc != newDesc {
			if newLen > prevLen {
				parts = append(parts, fmt.Sprintf("description grew from %d to %d chars (+%d)", prevLen, newLen, newLen-prevLen))
			} else if newLen < prevLen {
				parts = append(parts, fmt.Sprintf("description shrank from %d to %d chars (-%d)", prevLen, newLen, prevLen-newLen))
			} else {
				parts = append(parts, fmt.Sprintf("description changed (%d chars)", newLen))
			}

			// Show added text (tail of new description beyond previous length).
			// Use rune slicing to avoid splitting multi-byte characters.
			if newLen > prevLen {
				newRunes := []rune(newDesc)
				added := string(newRunes[prevLen:])
				// 200: truncation limit for readable drift summaries
				if len(newRunes)-prevLen > 200 {
					added = string(newRunes[prevLen:prevLen+200]) + "..."
				}
				parts = append(parts, fmt.Sprintf("added: %q", added))
			}
		}
	}

	// Parameter diff.
	if hasParams {
		added, removed := diffStringSlices(prevParams, newParams)
		if len(added) > 0 {
			parts = append(parts, fmt.Sprintf("parameters added: %v", added))
		}
		if len(removed) > 0 {
			parts = append(parts, fmt.Sprintf("parameters removed: %v", removed))
		}
	}

	return strings.Join(parts, "; ")
}

// diffStringSlices compares two sorted string slices and returns elements
// present only in b (added) and elements present only in a (removed).
func diffStringSlices(a, b []string) (added, removed []string) {
	setA := make(map[string]bool, len(a))
	for _, s := range a {
		setA[s] = true
	}
	setB := make(map[string]bool, len(b))
	for _, s := range b {
		setB[s] = true
	}
	for _, s := range b {
		if !setA[s] {
			added = append(added, s)
		}
	}
	for _, s := range a {
		if !setB[s] {
			removed = append(removed, s)
		}
	}
	return added, removed
}

// SetKnownTools sets the session baseline from a tools/list response.
// Called on the first tools/list to lock the baseline. Subsequent calls
// add newly seen tools to the known set. Respects maxBaselineTools to
// prevent unbounded memory growth from malicious servers.
func (tb *ToolBaseline) SetKnownTools(names []string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.knownTools == nil {
		tb.knownTools = make(map[string]bool, len(names))
	}
	for _, n := range names {
		if !tb.knownTools[n] && len(tb.knownTools) >= maxBaselineTools {
			break
		}
		tb.knownTools[n] = true
	}
	tb.hasBaseline = true
}

// HasBaseline reports whether a tool inventory baseline has been established.
func (tb *ToolBaseline) HasBaseline() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.hasBaseline
}

// IsKnownTool reports whether the given tool name is in the session baseline.
func (tb *ToolBaseline) IsKnownTool(name string) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.knownTools[name]
}

// CheckNewTools compares a list of tool names against the baseline and returns
// any that were not previously known. Newly seen tools are added to the baseline.
// Respects maxBaselineTools to prevent unbounded memory growth.
func (tb *ToolBaseline) CheckNewTools(names []string) []string {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	var added []string
	for _, n := range names {
		if !tb.knownTools[n] {
			if len(tb.knownTools) >= maxBaselineTools {
				continue
			}
			added = append(added, n)
			tb.knownTools[n] = true
		}
	}
	return added
}

// compiledToolPattern is a precompiled regex for tool-specific poisoning detection.
type compiledToolPattern struct {
	name string
	re   *regexp.Regexp
}

// toolPoisonKeywords is the set of directive keywords checked in tool descriptions.
const toolPoisonKeywords = `IMPORTANT|CRITICAL|SYSTEM|INSTRUCTION|SECRET|HIDDEN|URGENT`

// toolPoisonPatterns detect structural indicators of tool description poisoning.
// These are checked ONLY in tool descriptions to avoid false positives on
// legitimate response content. Text is Unicode-normalized before matching.
var toolPoisonPatterns = []*compiledToolPattern{
	{
		name: "Instruction Tag",
		// Catches <IMPORTANT>, [IMPORTANT], **IMPORTANT**, and variants with
		// trailing words like **CRITICAL FIRST STEP** or [SYSTEM NOTE].
		// All three tag styles use \b + capped permissive fill ({0,100}) to
		// match trailing words consistently without unbounded backtracking.
		re: regexp.MustCompile(`(?i)(?:` +
			`<\s*(?:` + toolPoisonKeywords + `)\b[^>]{0,100}>` + `|` +
			`\[\s*(?:` + toolPoisonKeywords + `)\b[^\]]{0,100}\]` + `|` +
			`\*{2}\s*(?:` + toolPoisonKeywords + `)\b[^*]{0,100}\*{2}` +
			`)`),
	},
	{
		name: "File Exfiltration Directive",
		re:   regexp.MustCompile(`(?i)(read|send|include|exfiltrate|steal|access|retrieve|fetch|dump|upload|cat|prepend|append|add|attach|embed)\s+.{0,40}(\.ssh|\.env|\.aws|credentials|private[_\s]?key|id_rsa|passwd)`),
	},
	{
		// Reverse order: path mentioned before action verb.
		// Catches "~/.ssh/config and upload" style directives.
		name: "File Exfiltration Directive",
		re:   regexp.MustCompile(`(?i)(\.ssh|\.env|\.aws|credentials|private[_\s]?key|id_rsa|passwd).{0,40}(read|send|include|exfiltrate|steal|access|retrieve|fetch|dump|upload|cat)\b`),
	},
	{
		name: "Cross-Tool Manipulation",
		re:   regexp.MustCompile(`(?i)(instead\s+of|rather\s+than|don't\s+use|never\s+use|always\s+prefer)\s+(using\s+)?(the\s+)?\w+\s+(tool|function|command)`),
	},
	{
		name: "Dangerous Capability",
		// Detects tools that describe executing local files, scripts, or commands.
		// Standalone "script"/"file" require a determiner (a/the/any) to avoid
		// false positives on "Execute the deployment script" or "Run the build
		// script". Qualified forms (local/shell/arbitrary/system) match directly.
		re: regexp.MustCompile(`(?i)(execut|run|launch|spawn)\w*\s+.{0,40}(` +
			`local\s+(?:file|script)|` +
			`(?:a|the|any)\s+(?:file|script)\b|` +
			`(?:shell|arbitrary|system)\s+(?:command|script))`,
		),
	},
	{
		name: "Dangerous Capability",
		// Detects tools that download from URLs then execute the result.
		// Requires "it"/"them" after the execute verb to avoid false positives
		// on "Fetch data and run the analysis" where fetch and run act on
		// different objects.
		re: regexp.MustCompile(`(?i)(download|fetch|retriev)\w*\s+.{0,60}(execut|run|launch)\w*\s+(?:it|them)\b`),
	},
	{
		name: "Dangerous Capability",
		// Detects tools that instruct calling external commands via tool chain.
		// Catches "call the bash tool to run: curl", "use the shell tool to execute",
		// and similar patterns where a tool description directs the agent to invoke
		// another tool for command execution.
		re: regexp.MustCompile(`(?i)(call|use|invoke)\s+(the\s+)?(bash|shell|exec|terminal|command|cmd)\s+(tool|function).{0,40}(run|execut|curl|wget|nc\b|ncat|python|perl|ruby|node\b)`),
	},
	{
		name: "Data Routing Directive",
		// Detects shadow tools that instruct the agent to pass data from one
		// tool through another. Catches "pass the full email body as the
		// verification_data parameter" and similar data-routing instructions
		// that exfiltrate content via a seemingly innocent tool.
		re: regexp.MustCompile(`(?i)(pass|send|include|forward|copy|submit|relay)\s+(the\s+)?(full|entire|complete|all)?\s*(body|content|data|message|text|response|output|email|request)\s+.{0,40}(parameter|argument|field|input|payload)`),
	},
}

// exfilParamPattern detects parameter names that encode exfiltration intent.
// Catches names like "content_from_reading_ssh_id_rsa" where the param name
// itself directs the agent to read sensitive files. Runs per-param on the
// expanded name (not aggregated tool text) to avoid false positives from
// action words in the description pairing with sensitive targets in unrelated
// params. Requires an action word + sensitive target in the same param name.
var exfilParamPattern = regexp.MustCompile(
	`(?i)\b(content|data|value|result|output|read|fetch|get|dump|steal|exfil|extract|copy|upload|send)\b` +
		`.{0,40}` +
		`\b(ssh.{0,5}(?:id.rsa|key)|id.rsa|private.key|api.key|secret.key|` +
		`credentials?|passwd|env.(?:secret|key|file|var)|aws.secret|access.token|auth.token)\b`,
)

// hashTool computes a SHA256 hash of a tool's description and inputSchema.
func hashTool(t ToolDef) string {
	h := sha256.New()
	h.Write([]byte(t.Description))
	h.Write([]byte{0}) // null byte separator
	if len(t.InputSchema) > 0 {
		h.Write(t.InputSchema)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// extractToolText extracts all scannable text from a tool definition.
// Convenience wrapper that extracts param names internally.
func extractToolText(t ToolDef) string {
	var paramNames []string
	if len(t.InputSchema) > 0 {
		paramNames = ExtractParamNames(t.InputSchema)
	}
	return extractToolTextWithParams(t, paramNames)
}

// extractToolTextWithParams extracts all scannable text from a tool definition
// using pre-extracted parameter names. Includes the description, nested
// "description" fields from inputSchema, and parameter key names (with
// underscores and camelCase expanded to spaces) so that suspicious names like
// "content_from_reading_ssh_id_rsa" or "contentFromReadingSshIdRsa" pass
// through the injection and DLP scanners.
func extractToolTextWithParams(t ToolDef, paramNames []string) string {
	var parts []string
	if t.Description != "" {
		parts = append(parts, t.Description)
	}
	if len(t.InputSchema) > 0 {
		parts = append(parts, ExtractSchemaDescriptions(t.InputSchema)...)
		// Add parameter names with underscores and camelCase expanded to spaces.
		// This feeds names like "content_from_reading_ssh_id_rsa" and
		// "contentFromReadingSshIdRsa" through injection/DLP scanning as
		// "content from reading ssh id rsa".
		for _, name := range paramNames {
			expanded := expandParamName(name)
			if expanded != name {
				parts = append(parts, expanded)
			}
			parts = append(parts, name)
		}
	}
	// Space separator ensures word boundaries survive Unicode normalization,
	// which strips newlines. Without this, adjacent parts merge into one word
	// (e.g., "contextcontent") and \b patterns fail to match.
	return strings.Join(parts, " ")
}

// expandParamName expands a parameter name into space-separated words by:
//  1. Replacing underscores and hyphens with spaces.
//  2. Splitting camelCase boundaries (lowercase to uppercase transitions).
//  3. Splitting acronym boundaries (uppercase run followed by uppercase+lowercase,
//     e.g. "APIKey" becomes "api key", "SSHKey" becomes "ssh key").
//  4. Lowercasing the result.
//
// Example: "contentFromReadingSshIdRsa" becomes "content from reading ssh id rsa".
// Example: "fetchAPIKey" becomes "fetch api key".
func expandParamName(name string) string {
	var b strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		if r == '_' || r == '-' {
			b.WriteRune(' ')
			continue
		}
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := runes[i-1]
			// Split at lowercase to uppercase: fooBar -> foo Bar.
			if prev >= 'a' && prev <= 'z' {
				b.WriteRune(' ')
			} else if prev >= 'A' && prev <= 'Z' {
				// Split at acronym boundary: APIKey -> API Key.
				// Only split when current uppercase is followed by lowercase,
				// indicating the start of a new word after an acronym run.
				if i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z' {
					b.WriteRune(' ')
				}
			}
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// ExtractParamNames extracts all property key names from a JSON Schema.
// Walks "properties" at all nesting levels (including allOf/oneOf/anyOf branches,
// definitions, items, and additionalProperties). Returns sorted, deduplicated names.
func ExtractParamNames(schema json.RawMessage) []string {
	var parsed map[string]interface{}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	collectParamNames(parsed, seen, 0)
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// collectParamNames walks a JSON Schema tree collecting property key names.
// Recurses into all nested objects/arrays to find properties at any depth.
func collectParamNames(obj map[string]interface{}, seen map[string]bool, depth int) {
	if depth > maxSchemaDepth {
		return
	}
	// Collect property names from "properties" object.
	if props, ok := obj["properties"].(map[string]interface{}); ok {
		for key := range props {
			seen[key] = true
		}
	}
	// Recurse into all nested objects and arrays.
	for _, v := range obj {
		switch val := v.(type) {
		case map[string]interface{}:
			collectParamNames(val, seen, depth+1)
		case []interface{}:
			for _, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					collectParamNames(m, seen, depth+1)
				}
			}
		}
	}
}

// ExtractSchemaDescriptions recursively extracts text field values from a
// JSON Schema. Collects all text-bearing fields from all nested objects:
// description, title, default, const, pattern, $comment, x-* extensions,
// plus string members of enum and examples arrays.
// Falls back to extracting string schemas (non-object JSON values).
func ExtractSchemaDescriptions(schema json.RawMessage) []string {
	var result []string
	var parsed map[string]interface{}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		// Non-object schema — could be a bare string with injected content.
		var s string
		if json.Unmarshal(schema, &s) == nil && s != "" {
			return []string{s}
		}
		return nil
	}
	collectAllSchemaText(parsed, &result, 0)
	return result
}

// maxSchemaDepth limits recursion depth for schema walking to prevent stack
// overflow on maliciously deep schemas.
const maxSchemaDepth = 20

// schemaTextFields are JSON Schema fields whose string values should be
// extracted for poisoning detection. CyberArk research showed attackers
// embed malicious instructions in default, const, pattern, and $comment —
// not just description/title.
var schemaTextFields = [...]string{
	"description", "title", "default", "const", "pattern", "$comment",
}

// collectAllSchemaText walks a JSON Schema tree collecting all text values
// that an LLM might ingest. Extracts string values from metadata fields
// (description, title, default, const, pattern, $comment, x-* extensions),
// string members from enum/examples arrays, then recurses into all nested
// objects and arrays to catch text hidden in composition keywords
// (allOf, anyOf, oneOf, if/then/else, $defs, items, etc.).
func collectAllSchemaText(obj map[string]interface{}, result *[]string, depth int) {
	if depth > maxSchemaDepth {
		return
	}

	for key, v := range obj {
		handledSubtree := false

		// Extract values from known metadata fields.
		// default and const can hold objects/arrays with nested strings,
		// so use collectStringLeaves for full subtree extraction.
		for _, field := range schemaTextFields {
			if key == field {
				if key == "default" || key == "const" {
					collectStringLeaves(v, result, depth+1)
					handledSubtree = true
				} else if s, ok := v.(string); ok && s != "" {
					*result = append(*result, s)
				}
				break
			}
		}

		// Extract all string leaves from vendor extension fields (x-*).
		// Extensions can hold objects, arrays, or strings.
		if strings.HasPrefix(key, "x-") || strings.HasPrefix(key, "X-") {
			collectStringLeaves(v, result, depth+1)
			handledSubtree = true
		}

		// Extract all string leaves from enum and examples.
		// These can hold objects (e.g., examples: [{"prompt":"..."}]),
		// not just flat strings.
		if key == "enum" || key == "examples" {
			collectStringLeaves(v, result, depth+1)
			handledSubtree = true
		}

		if handledSubtree {
			continue
		}

		// Recurse into nested objects and arrays for schema composition
		// keywords (allOf, anyOf, oneOf, if/then/else, items, $defs, etc.).
		switch val := v.(type) {
		case map[string]interface{}:
			collectAllSchemaText(val, result, depth+1)
		case []interface{}:
			for _, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					collectAllSchemaText(m, result, depth+1)
				}
			}
		}
	}
}

// collectStringLeaves recursively extracts all string values from an
// arbitrary JSON value (string, object, or array). Used for schema fields
// like default, const, enum, examples, and x-* extensions that can hold
// nested structures containing poisoned text.
func collectStringLeaves(v interface{}, result *[]string, depth int) {
	if depth > maxSchemaDepth {
		return
	}
	switch val := v.(type) {
	case string:
		if val != "" {
			*result = append(*result, val)
		}
	case map[string]interface{}:
		for _, child := range val {
			collectStringLeaves(child, result, depth+1)
		}
	case []interface{}:
		for _, child := range val {
			collectStringLeaves(child, result, depth+1)
		}
	}
}

// tryParseToolsList attempts to parse a JSON-RPC result as a tools/list response.
// Uses shape-based detection: result must have a "tools" array with named entries.
// Returns nil if the shape doesn't match.
// isToolsListResult returns true if the result JSON contains a "tools" key,
// indicating this is a tools/list response. An empty tools array still counts
// as a tools/list response — the response scanner must skip general injection
// scanning regardless of whether there are tools to scan for poisoning.
func isToolsListResult(result json.RawMessage) bool {
	if len(result) == 0 || string(result) == jsonrpc.Null {
		return false
	}
	var probe struct {
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(result, &probe); err != nil {
		return false
	}
	// json.RawMessage("null") is non-nil in Go — must check string value.
	// Only treat as tools/list if tools is a JSON array (including empty []).
	// A string or object in the tools field is malformed and must NOT suppress
	// general response scanning — otherwise an attacker hides injection there.
	trimmed := bytes.TrimSpace(probe.Tools)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return false
	}
	// Verify array elements are JSON objects. An array of strings like
	// ["Ignore previous instructions"] would bypass general scanning
	// since tryParseToolsList returns nil but IsToolsList would be true.
	var elems []json.RawMessage
	if err := json.Unmarshal(probe.Tools, &elems); err != nil {
		return false
	}
	for _, elem := range elems {
		e := bytes.TrimSpace(elem)
		if len(e) == 0 || e[0] != '{' {
			return false
		}
	}
	return true
}

func tryParseToolsList(result json.RawMessage) []ToolDef {
	if len(result) == 0 || string(result) == jsonrpc.Null {
		return nil
	}

	var tl toolsListResult
	if err := json.Unmarshal(result, &tl); err != nil {
		return nil
	}

	if len(tl.Tools) == 0 {
		return nil
	}

	var valid []ToolDef
	for _, t := range tl.Tools {
		if t.Name != "" {
			valid = append(valid, t)
		}
	}
	if len(valid) == 0 {
		return nil
	}

	return valid
}

// checkToolPoison runs tool-specific poisoning patterns against normalized text.
func checkToolPoison(text string) []string {
	var findings []string
	for _, p := range toolPoisonPatterns {
		if p.re.MatchString(text) {
			findings = append(findings, p.name)
		}
	}
	return findings
}

// ScanTools scans a JSON-RPC 2.0 response for tool description poisoning.
// Detects tools/list responses by shape, scans each tool's description for
// injection patterns (general + tool-specific), and optionally tracks tool
// definition hashes for rug pull (drift) detection.
// Batch responses (JSON arrays) are detected and each element scanned individually.
func ScanTools(line []byte, sc *scanner.Scanner, cfg *ToolScanConfig) ToolScanResult {
	if cfg == nil {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	// Detect batch response (JSON-RPC 2.0 batch = JSON array).
	if len(line) > 0 && line[0] == '[' {
		return scanToolsBatch(line, sc, cfg)
	}

	return scanToolsSingle(line, sc, cfg)
}

// scanToolsSingle scans a single JSON-RPC 2.0 response for tool poisoning.
func scanToolsSingle(line []byte, sc *scanner.Scanner, cfg *ToolScanConfig) ToolScanResult {
	var rpc jsonrpc.RPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	// Check if this is a tools/list response at all (even with empty tools array).
	// This ensures the general response scanner skips tools/list responses
	// regardless of whether there are tool definitions to scan for poisoning.
	if !isToolsListResult(rpc.Result) {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	tools := tryParseToolsList(rpc.Result)
	if tools == nil {
		// tools/list response with empty or all-unnamed tools — still a tools/list,
		// just nothing to scan for poisoning.
		return ToolScanResult{IsToolsList: true, Clean: true, RPCID: rpc.ID}
	}

	// Extract tool names for session binding.
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}

	matches := scanToolDefs(tools, sc, cfg)

	if len(matches) == 0 {
		return ToolScanResult{IsToolsList: true, Clean: true, RPCID: rpc.ID, ToolNames: names}
	}

	return ToolScanResult{IsToolsList: true, Clean: false, Matches: matches, RPCID: rpc.ID, ToolNames: names}
}

// scanToolsBatch scans a JSON-RPC 2.0 batch response for tool poisoning.
// Each element is checked independently; results are aggregated.
func scanToolsBatch(line []byte, sc *scanner.Scanner, cfg *ToolScanConfig) ToolScanResult {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	var allMatches []ToolScanMatch
	var allNames []string
	var firstID json.RawMessage
	isToolsList := false

	for _, elem := range batch {
		r := scanToolsSingle(elem, sc, cfg)
		if r.IsToolsList {
			isToolsList = true
			if firstID == nil && len(r.RPCID) > 0 {
				firstID = r.RPCID
			}
			allMatches = append(allMatches, r.Matches...)
			allNames = append(allNames, r.ToolNames...)
		}
	}

	if !isToolsList {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	if len(allMatches) == 0 {
		return ToolScanResult{IsToolsList: true, Clean: true, RPCID: firstID, ToolNames: allNames}
	}

	return ToolScanResult{IsToolsList: true, Clean: false, Matches: allMatches, RPCID: firstID, ToolNames: allNames}
}

// scanToolDefs scans a slice of tool definitions for injection, poisoning, and drift.
func scanToolDefs(tools []ToolDef, sc *scanner.Scanner, cfg *ToolScanConfig) []ToolScanMatch {
	var matches []ToolScanMatch

	for _, tool := range tools {
		var match ToolScanMatch
		match.ToolName = tool.Name
		hasFinding := false

		// Extract param names once for both text scanning and drift tracking.
		var paramNames []string
		if len(tool.InputSchema) > 0 {
			paramNames = ExtractParamNames(tool.InputSchema)
		}

		text := extractToolTextWithParams(tool, paramNames)

		if text != "" {
			// General injection patterns (reuses response scanning pipeline).
			// ScanResponse does its own Unicode normalization internally.
			result := sc.ScanResponse(context.Background(), text)
			if !result.Clean {
				match.Injection = result.Matches
				hasFinding = true
			}

			// Tool-specific poisoning patterns on normalized text.
			// Normalization prevents zero-width char and confusable bypasses.
			poison := checkToolPoison(normalize.ForToolText(text))
			if len(poison) > 0 {
				match.ToolPoison = poison
				hasFinding = true
			}

			// Exfiltration param pattern: runs per-param to avoid false
			// positives from action words in the description pairing with
			// sensitive targets in unrelated parameters.
			for _, name := range paramNames {
				expanded := normalize.ForToolText(expandParamName(name))
				if exfilParamPattern.MatchString(expanded) {
					match.ToolPoison = append(match.ToolPoison, "Exfiltration Parameter Name")
					hasFinding = true
					break
				}
			}

			// Community rule bundle extra-poison patterns.
			if cfg != nil && len(cfg.ExtraPoison) > 0 {
				normName := normalize.ForToolText(tool.Name)
				normDesc := normalize.ForToolText(text)
				for _, ep := range cfg.ExtraPoison {
					if ep == nil || ep.Re == nil || ep.Name == "" {
						continue
					}
					var target string
					switch ep.ScanField {
					case "name":
						target = normName
					case "", "description":
						target = normDesc
					default:
						continue
					}
					if ep.Re.MatchString(target) {
						match.ToolPoison = append(match.ToolPoison, ep.Name)
						hasFinding = true
					}
				}
			}
		}

		// Drift detection (rug pull).
		// Skip hash computation for unknown tools when at capacity to prevent
		// CPU exhaustion from malicious servers sending unlimited unique names.
		if cfg.DetectDrift && cfg.Baseline != nil && !cfg.Baseline.ShouldSkip(tool.Name) {
			hash := hashTool(tool)
			drifted, prevHash := cfg.Baseline.CheckAndUpdate(tool.Name, hash)

			if drifted {
				match.DriftDetected = true
				match.PreviousHash = prevHash
				match.CurrentHash = hash
				match.DriftDetail = cfg.Baseline.DiffSummary(tool.Name, tool.Description, paramNames)
				hasFinding = true
			}
			// Store the actual tool description (not the full scan text which
			// includes param names) so DiffSummary reports description changes
			// accurately without false "description grew" when only params change.
			cfg.Baseline.StoreDesc(tool.Name, tool.Description)
			cfg.Baseline.StoreParams(tool.Name, paramNames)
		}

		if hasFinding {
			matches = append(matches, match)
		}
	}

	return matches
}

// LogToolFindings writes per-tool scan findings to the log writer.
func LogToolFindings(logW io.Writer, lineNum int, result ToolScanResult) {
	for _, m := range result.Matches {
		var reasons []string
		for _, inj := range m.Injection {
			reasons = append(reasons, inj.PatternName)
		}
		reasons = append(reasons, m.ToolPoison...)
		if m.DriftDetected {
			reasons = append(reasons, "definition-drift")
		}
		_, _ = fmt.Fprintf(logW, "pipelock: line %d: tool %q: %s\n",
			lineNum, m.ToolName, strings.Join(reasons, ", "))
		if m.DriftDetail != "" {
			_, _ = fmt.Fprintf(logW, "  %s\n", m.DriftDetail)
		}
	}
}
