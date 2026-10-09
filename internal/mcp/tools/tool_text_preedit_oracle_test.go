// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

// The six functions below are the tool text extraction functions exactly as
// they stood at 7616d601b, before toolTextSink, renamed with a pre prefix.
// They are the independent oracle for the controlled-order equivalence tests.
// The only change is the declared iterator adaptation: each Go map range reads
// its key order from preKeyOrder instead. TestPreEditOracleIsVerbatim reverses
// exactly that adaptation and checks every function against its original
// SHA-256, so this file must never be edited to follow later changes.
//
// preKeyOrder is set only by the non-parallel controlled-order tests, for the
// duration of one oracle call, and reset to nil afterwards.
var preKeyOrder schemaKeyOrder

func preCollectSchemaValueText(value interface{}, result *[]string, depth int) {
	if depth > maxSchemaDepth {
		return
	}
	switch v := value.(type) {
	case map[string]interface{}:
		preCollectAllSchemaText(v, result, depth)
	case []interface{}:
		for _, item := range v {
			preCollectSchemaValueText(item, result, depth+1)
		}
	case string:
		if v != "" {
			*result = append(*result, v)
		}
	}
}

func preCollectAllSchemaText(obj map[string]interface{}, result *[]string, depth int) {
	if depth > maxSchemaDepth {
		return
	}

	for _, key := range preKeyOrder(obj) {
		v := obj[key]
		handledSubtree := false

		// Extract values from known metadata fields.
		// default and const can hold objects/arrays with nested strings,
		// so use collectStringLeaves for full subtree extraction.
		for _, field := range schemaTextFields {
			if key == field {
				if key == "default" || key == "const" {
					preCollectStringLeaves(v, result, depth+1)
					handledSubtree = true
				} else if s, ok := v.(string); ok && s != "" {
					*result = append(*result, s)
					// Consumed here. Without this the value is appended
					// again by the string case in the walk below, which
					// doubles the scanner input for every modelled field.
					handledSubtree = true
				}
				break
			}
		}

		// Extract all string leaves from vendor extension fields (x-*).
		// Extensions can hold objects, arrays, or strings.
		if strings.HasPrefix(key, "x-") || strings.HasPrefix(key, "X-") {
			preCollectStringLeaves(v, result, depth+1)
			handledSubtree = true
		}

		// Extract all string leaves from enum and examples.
		// These can hold objects (e.g., examples: [{"prompt":"..."}]),
		// not just flat strings.
		if key == "enum" || key == "examples" {
			preCollectStringLeaves(v, result, depth+1)
			handledSubtree = true
		}

		if handledSubtree {
			continue
		}

		// Recurse into nested objects and arrays for schema composition
		// keywords (allOf, anyOf, oneOf, if/then/else, items, $defs, etc.),
		// and take string values under keys this walk does not model.
		//
		// Only the modelled field names were being read here, so a string
		// under any other key was dropped: a schema carrying
		// "instructions":"Ignore all previous instructions" reached the agent
		// having never been scanned, because the tools/list response is
		// excluded from general response scanning once ScanTools calls it
		// clean. The agent reads whatever the schema contains, so the walk
		// takes every string it contains rather than only the ones named in
		// the specification.
		switch val := v.(type) {
		case map[string]interface{}:
			preCollectAllSchemaText(val, result, depth+1)
		case []interface{}:
			// Every element, not only the objects. A bare string sitting
			// directly in a composition array is agent-visible text and was
			// being dropped by an object-only walk.
			for _, item := range val {
				preCollectSchemaValueText(item, result, depth+1)
			}
		case string:
			if isAgentReadableSchemaText(val) {
				*result = append(*result, val)
			}
		}
	}
}

func preCollectStringLeaves(v interface{}, result *[]string, depth int) {
	if depth > maxSchemaDepth {
		return
	}
	switch val := v.(type) {
	case string:
		if val != "" {
			*result = append(*result, val)
		}
	case map[string]interface{}:
		for _, key := range preKeyOrder(val) {
			child := val[key]
			preCollectStringLeaves(child, result, depth+1)
		}
	case []interface{}:
		for _, child := range val {
			preCollectStringLeaves(child, result, depth+1)
		}
	}
}

func preExtractSchemaDescriptions(schema json.RawMessage) []string {
	var parsed interface{}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		return nil
	}
	var result []string
	preCollectSchemaValueText(parsed, &result, 0)
	return result
}

func preExtractToolText(t ToolDef) string {
	var parts []string
	if t.Description != "" {
		parts = append(parts, t.Description)
	}
	if len(t.InputSchema) > 0 {
		parts = append(parts, preExtractSchemaDescriptions(t.InputSchema)...)
	}
	// A sentence boundary keeps word boundaries intact after Unicode
	// normalization without letting a negated capability in one tool field
	// suppress an exfiltration directive in a later schema field.
	return strings.Join(parts, ". ")
}

func preExtractToolGeneralText(t ToolDef) string {
	var parts []string
	// Dropping a truncated key set is only safe because
	// uninspectableToolDefinition has already refused the definition
	// by the time this runs. That pre-scan checks key-extraction truncation
	// directly, through toolKeyExtractionTruncated, on every field this
	// function reads. It has to: key extraction truncates on breadth as well as
	// depth, and a string-extraction or schema-depth check cannot see a field
	// that is shallow and merely enormous. If the pre-scan ever stops running
	// first, or drops that check, this silent drop becomes a scan gap rather
	// than a fail-closed one, and padding keys past the bound becomes a way to
	// hide one.
	appendJSONKeys := func(field json.RawMessage) {
		if extracted := jsonrpc.ExtractKeysFromJSONResult(field); !extracted.Truncated {
			for _, key := range extracted.Keys {
				if !isIdentifierToken(key) {
					parts = append(parts, key)
				}
			}
		}
	}
	for _, field := range []string{t.Name, t.Title} {
		if field != "" {
			parts = append(parts, field)
		}
	}
	// extractToolText already contributes every input-schema value. Keep its
	// keys here, but do not make every downstream scanner process those values
	// a second time. Output-schema values are unique to this extractor.
	if len(t.InputSchema) > 0 {
		appendJSONKeys(t.InputSchema)
	}
	if len(t.OutputSchema) > 0 {
		parts = append(parts, preExtractSchemaDescriptions(t.OutputSchema)...)
		appendJSONKeys(t.OutputSchema)
	}
	// Metadata is extensible and agent-visible. Its readable strings use the
	// generic bounded extractor; actual opaque media is rejected before this
	// function is called rather than skipped as though it were harmless.
	for _, metadata := range []json.RawMessage{t.Annotations, t.Meta} {
		if extracted := jsonrpc.ExtractStringsFromJSONResult(metadata); !extracted.Truncated {
			parts = append(parts, extracted.Strings...)
		}
		appendJSONKeys(metadata)
	}
	unknownKeys := make([]string, 0, len(t.unknown))
	for key := range t.unknown {
		unknownKeys = append(unknownKeys, key)
	}
	sort.Strings(unknownKeys)
	for _, key := range unknownKeys {
		if !isIdentifierToken(key) {
			parts = append(parts, key)
		}
		if extracted := jsonrpc.ExtractStringsFromJSONResult(t.unknown[key]); !extracted.Truncated {
			parts = append(parts, extracted.Strings...)
		}
		appendJSONKeys(t.unknown[key])
	}
	return strings.Join(parts, ". ")
}
