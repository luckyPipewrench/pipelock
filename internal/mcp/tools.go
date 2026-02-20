package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/text/unicode/norm"

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
}

// ToolScanConfig holds configuration for MCP tool description scanning.
// A nil ToolScanConfig disables tool scanning entirely.
type ToolScanConfig struct {
	Baseline    *ToolBaseline
	Action      string // warn, block
	DetectDrift bool
}

// ToolBaseline tracks SHA256 hashes of tool definitions for rug pull detection.
// Safe for concurrent use.
type ToolBaseline struct {
	mu     sync.Mutex
	hashes map[string]string // tool name → SHA256(description + inputSchema)
	descs  map[string]string // tool name → last known description text
}

// NewToolBaseline creates a new empty tool baseline.
func NewToolBaseline() *ToolBaseline {
	return &ToolBaseline{
		hashes: make(map[string]string),
		descs:  make(map[string]string),
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

// DiffSummary returns a human-readable summary of what changed between the
// stored description and the new one. Returns "" if no previous description.
func (tb *ToolBaseline) DiffSummary(name, newDesc string) string {
	tb.mu.Lock()
	prev, exists := tb.descs[name]
	tb.mu.Unlock()

	if !exists {
		return ""
	}

	prevLen := len([]rune(prev))
	newLen := len([]rune(newDesc))

	var parts []string
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
		if len(newRunes)-prevLen > 200 {
			added = string(newRunes[prevLen:prevLen+200]) + "..."
		}
		parts = append(parts, fmt.Sprintf("added: %q", added))
	}

	return strings.Join(parts, "; ")
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
		re:   regexp.MustCompile(`(?i)(read|send|include|exfiltrate|steal|access|retrieve|fetch|dump|upload|cat)\s+.{0,40}(\.ssh|\.env|\.aws|credentials|private[_\s]?key|id_rsa|passwd)`),
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
}

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
// Includes the description and any nested "description" fields from inputSchema.
func extractToolText(t ToolDef) string {
	var parts []string
	if t.Description != "" {
		parts = append(parts, t.Description)
	}
	if len(t.InputSchema) > 0 {
		parts = append(parts, extractSchemaDescriptions(t.InputSchema)...)
	}
	return strings.Join(parts, "\n")
}

// extractSchemaDescriptions recursively extracts text field values from a
// JSON Schema. Collects "description" and "title" from all nested objects.
// Falls back to extracting string schemas (non-object JSON values).
func extractSchemaDescriptions(schema json.RawMessage) []string {
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
	collectDescriptions(parsed, &result, 0)
	return result
}

// maxSchemaDepth limits recursion depth for schema walking to prevent stack
// overflow on maliciously deep schemas.
const maxSchemaDepth = 20

// collectDescriptions walks a JSON Schema tree collecting text values.
// Extracts "description" and "title" fields, then recurses into all nested
// objects and arrays to catch text hidden in composition keywords.
func collectDescriptions(obj map[string]interface{}, result *[]string, depth int) {
	if depth > maxSchemaDepth {
		return
	}
	if desc, ok := obj["description"].(string); ok && desc != "" {
		*result = append(*result, desc)
	}
	if title, ok := obj["title"].(string); ok && title != "" {
		*result = append(*result, title)
	}
	for _, v := range obj {
		switch val := v.(type) {
		case map[string]interface{}:
			collectDescriptions(val, result, depth+1)
		case []interface{}:
			for _, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					collectDescriptions(m, result, depth+1)
				}
			}
		}
	}
}

// tryParseToolsList attempts to parse a JSON-RPC result as a tools/list response.
// Uses shape-based detection: result must have a "tools" array with named entries.
// Returns nil if the shape doesn't match.
func tryParseToolsList(result json.RawMessage) []ToolDef {
	if len(result) == 0 || string(result) == jsonNull {
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

// normalizeToolText applies Unicode normalization before poison pattern matching.
// Strips ALL control chars (C0 including \t\n\r, C1 U+0080-009F, DEL) + Unicode
// invisibles, then NFKC-normalizes + confusable mapping. Unlike response scanning
// (which preserves whitespace for \s+ injection patterns), tool descriptions have
// no legitimate control chars — any present are evasion attempts (e.g., tab splitting
// "IMPORTANT" into "IMPOR\tTANT", or C1 NEL splitting into "IMPOR\u0085TANT").
func normalizeToolText(s string) string {
	s = strings.Map(func(r rune) rune {
		// Drop C0 controls (U+0000-001F), DEL (U+007F), and C1 controls (U+0080-009F).
		if r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			return -1
		}
		if unicode.Is(scanner.InvisibleRanges, r) {
			return -1
		}
		return r
	}, s)
	s = norm.NFKC.String(s)
	// Map cross-script confusables (Cyrillic/Greek lookalikes) to Latin equivalents.
	// NFKC does NOT handle these — Cyrillic о (U+043E) stays as о without this step.
	s = scanner.ConfusableToASCII(s)
	// Strip combining marks that survive NFKC (e.g., i+\u0307 → "i̇" breaks "ignore").
	s = scanner.StripCombiningMarks(s)
	// Normalize leetspeak substitutions (1→i, 0→o, 3→e, etc.) to catch
	// L1B3RT4S-style evasion in tool descriptions (e.g., <1MP0RT4NT>).
	s = scanner.NormalizeLeetspeak(s)
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u1680', '\u180E', '\u2028', '\u2029':
			return ' '
		}
		return r
	}, s)
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
	var rpc RPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	tools := tryParseToolsList(rpc.Result)
	if tools == nil {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	matches := scanToolDefs(tools, sc, cfg)

	if len(matches) == 0 {
		return ToolScanResult{IsToolsList: true, Clean: true, RPCID: rpc.ID}
	}

	return ToolScanResult{IsToolsList: true, Clean: false, Matches: matches, RPCID: rpc.ID}
}

// scanToolsBatch scans a JSON-RPC 2.0 batch response for tool poisoning.
// Each element is checked independently; results are aggregated.
func scanToolsBatch(line []byte, sc *scanner.Scanner, cfg *ToolScanConfig) ToolScanResult {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	var allMatches []ToolScanMatch
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
		}
	}

	if !isToolsList {
		return ToolScanResult{IsToolsList: false, Clean: true}
	}

	if len(allMatches) == 0 {
		return ToolScanResult{IsToolsList: true, Clean: true, RPCID: firstID}
	}

	return ToolScanResult{IsToolsList: true, Clean: false, Matches: allMatches, RPCID: firstID}
}

// scanToolDefs scans a slice of tool definitions for injection, poisoning, and drift.
func scanToolDefs(tools []ToolDef, sc *scanner.Scanner, cfg *ToolScanConfig) []ToolScanMatch {
	var matches []ToolScanMatch

	for _, tool := range tools {
		var match ToolScanMatch
		match.ToolName = tool.Name
		hasFinding := false

		text := extractToolText(tool)

		if text != "" {
			// General injection patterns (reuses response scanning pipeline).
			// ScanResponse does its own Unicode normalization internally.
			result := sc.ScanResponse(text)
			if !result.Clean {
				match.Injection = result.Matches
				hasFinding = true
			}

			// Tool-specific poisoning patterns on normalized text.
			// Normalization prevents zero-width char and confusable bypasses.
			poison := checkToolPoison(normalizeToolText(text))
			if len(poison) > 0 {
				match.ToolPoison = poison
				hasFinding = true
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
				match.DriftDetail = cfg.Baseline.DiffSummary(tool.Name, text)
				hasFinding = true
			}
			// Store description AFTER diff so next drift compares against current.
			cfg.Baseline.StoreDesc(tool.Name, text)
		}

		if hasFinding {
			matches = append(matches, match)
		}
	}

	return matches
}

// logToolFindings writes per-tool scan findings to the log writer.
func logToolFindings(logW io.Writer, lineNum int, result ToolScanResult) {
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
