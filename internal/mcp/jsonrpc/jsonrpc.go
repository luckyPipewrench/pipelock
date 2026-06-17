// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package jsonrpc provides shared JSON-RPC 2.0 types used across the mcp
// sub-packages. Extracting these into a dedicated package breaks circular
// imports between tools/, policy/, and the parent mcp package.
package jsonrpc

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Version is the JSON-RPC protocol version used by MCP.
const Version = "2.0"

// Null is the JSON literal "null", used to detect nil-equivalent
// json.RawMessage values that are non-nil Go slices.
const Null = "null"

// ContentBlock represents a single content block in an MCP tool result.
type ContentBlock struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	Data      string `json:"data,omitempty"`
	Blob      string `json:"blob,omitempty"`
	Raw       string `json:"raw,omitempty"`
	MimeType  string `json:"mimeType,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
}

// ToolResult represents the result field of an MCP tool response.
type ToolResult struct {
	Content []ContentBlock `json:"content"`
}

// RPCError represents a JSON-RPC 2.0 error object.
// Data is optional per JSON-RPC 2.0 but can carry arbitrary content,
// so it must be scanned for injection like any other text field.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// RPCResponse represents a JSON-RPC 2.0 response envelope.
// Result is json.RawMessage (not *ToolResult) to handle non-standard result
// shapes without failing the entire parse - a typed *ToolResult would cause
// json.Unmarshal to error on string/array/non-object results, allowing bypass.
// Method and Params are included to scan server notifications for injection.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// ScanVerdict describes the outcome of scanning a single MCP response.
//
// Three states:
//   - Clean:     Clean=true, other fields zero/empty.
//   - Error:     Clean=false, Error set (parse/protocol failure). Not injection.
//   - Injection: Clean=false, Error empty, Matches and Action set.
type ScanVerdict struct {
	Line    int                     `json:"line"`
	ID      json.RawMessage         `json:"id"`
	Clean   bool                    `json:"clean"`
	Action  string                  `json:"action,omitempty"`
	Matches []scanner.ResponseMatch `json:"matches,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// ExtractStringsResult is the bounded recursive extraction result. Truncated is
// true when the JSON contains content beyond maxExtractDepth and a caller should
// fail closed rather than make a decision from partial strings.
type ExtractStringsResult struct {
	Strings   []string
	Truncated bool
}

// TextResult is the bounded text extraction result.
type TextResult struct {
	Text      string
	Truncated bool
}

// ExtractText extracts all text content from an MCP tool result.
// First tries to parse as a standard ToolResult with content blocks (extracting
// text from ALL block types, not just "text" - prevents bypass via image blocks).
// Falls back to recursively extracting all string values from arbitrary JSON,
// preventing bypass via non-standard result shapes.
//
// Content blocks are joined with a single space to preserve word boundaries.
// Between-word splits ("previous" + "instructions") produce intact injections
// the agent will act on - scanner must detect these. Mid-word splits
// ("Igno" + "re" → "Igno re") don't match, but the injection is also broken
// for the agent, so this is not exploitable.
func ExtractText(raw json.RawMessage) string {
	return ExtractTextResult(raw).Text
}

// ExtractTextResult extracts text content and reports uninspectable depth in
// the complete JSON value.
func ExtractTextResult(raw json.RawMessage) TextResult {
	if len(raw) == 0 || string(raw) == Null {
		return TextResult{}
	}
	if jsonDepthTruncated(raw) {
		return TextResult{Truncated: true}
	}

	// Try standard ToolResult structure first.
	var tr ToolResult
	if err := json.Unmarshal(raw, &tr); err == nil && len(tr.Content) > 0 {
		var texts []string
		for _, block := range tr.Content {
			// Extract text from ALL content blocks, not just type=="text".
			// Non-text blocks (image, resource) may carry prompt injection
			// in their text field.
			if block.Text != "" {
				texts = append(texts, block.Text)
			}
		}
		// Always return after a successful ToolResult parse, even when
		// texts is empty. Falling through to ExtractStringsFromJSON would
		// feed base64 media in data/blob/raw fields into prompt scanning.
		return TextResult{Text: strings.Join(texts, " ")}
	}

	// Fallback: recursively extract all string values from arbitrary JSON.
	// Catches non-standard result shapes (plain string, nested objects, etc).
	extracted := ExtractStringsFromJSONResult(raw)
	if len(extracted.Strings) > 0 {
		return TextResult{Text: strings.Join(extracted.Strings, "\n"), Truncated: extracted.Truncated}
	}

	return TextResult{Truncated: extracted.Truncated}
}

// jsonDepthTruncated reports whether raw JSON exceeds the recursive extraction
// depth cap without returning any extracted strings.
func jsonDepthTruncated(raw json.RawMessage) bool {
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	return valueDepthTruncated(parsed, 0)
}

// valueDepthTruncated walks arbitrary decoded JSON and stops when depth exceeds
// maxExtractDepth.
func valueDepthTruncated(v interface{}, depth int) bool {
	if depth > maxExtractDepth {
		return true
	}
	switch val := v.(type) {
	case []interface{}:
		for _, item := range val {
			if valueDepthTruncated(item, depth+1) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range val {
			if valueDepthTruncated(item, depth+1) {
				return true
			}
		}
	}
	return false
}

// SortedKeys returns the keys of a map in sorted order. Used by JSON extraction
// functions to ensure deterministic iteration - Go map order is random, so
// split-secret concat scanning would miss secrets nondeterministically without
// stable ordering.
func SortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// maxExtractDepth limits recursion in ExtractStringsFromJSON to prevent stack
// overflow from maliciously deeply-nested JSON.
const maxExtractDepth = 64

// ExtractStringsForKeys extracts string values only from top-level keys
// matching the keyPattern regex. Values under non-matching keys are excluded.
// Nested values under matching keys are extracted recursively.
// Returns nil if keyPattern is nil (callers must provide a compiled pattern).
func ExtractStringsForKeys(raw json.RawMessage, keyPattern *regexp.Regexp) []string {
	return ExtractStringsForKeysResult(raw, keyPattern).Strings
}

// ExtractStringsForKeysResult extracts string values from matching top-level
// keys and reports whether recursive extraction hit the depth cap.
func ExtractStringsForKeysResult(raw json.RawMessage, keyPattern *regexp.Regexp) ExtractStringsResult {
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ExtractStringsResult{}
	}
	m, ok := parsed.(map[string]interface{})
	if !ok {
		return ExtractStringsResult{} // arguments must be an object
	}
	var result []string
	truncated := false
	var extract func(v interface{}, depth int)
	extract = func(v interface{}, depth int) {
		if depth > maxExtractDepth {
			truncated = true
			return
		}
		switch val := v.(type) {
		case string:
			result = append(result, val)
		case []interface{}:
			for _, item := range val {
				extract(item, depth+1)
			}
		case map[string]interface{}:
			for _, k := range SortedKeys(val) {
				extract(val[k], depth+1)
			}
		}
	}
	if keyPattern == nil {
		return ExtractStringsResult{}
	}
	for _, k := range SortedKeys(m) {
		if keyPattern != nil && keyPattern.MatchString(k) {
			extract(m[k], 0)
		}
	}
	return ExtractStringsResult{Strings: result, Truncated: truncated}
}

// ExtractStringsFromJSON recursively extracts all string values from arbitrary JSON.
// Only extracts values (not keys) to avoid false positives from field names.
// Recursion is bounded by maxExtractDepth to prevent stack overflow.
func ExtractStringsFromJSON(raw json.RawMessage) []string {
	return ExtractStringsFromJSONResult(raw).Strings
}

// ExtractStringsFromJSONResult recursively extracts all string values from
// arbitrary JSON and reports whether extraction hit the nesting cap.
func ExtractStringsFromJSONResult(raw json.RawMessage) ExtractStringsResult {
	var result []string
	truncated := false
	var extract func(v interface{}, depth int)
	extract = func(v interface{}, depth int) {
		if depth > maxExtractDepth {
			truncated = true
			return
		}
		switch val := v.(type) {
		case string:
			result = append(result, val)
		case []interface{}:
			for _, item := range val {
				extract(item, depth+1)
			}
		case map[string]interface{}:
			for _, k := range SortedKeys(val) {
				extract(val[k], depth+1)
			}
		}
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		extract(parsed, 0)
	}
	return ExtractStringsResult{Strings: result, Truncated: truncated}
}
