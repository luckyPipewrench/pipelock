// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package decide implements a shared decision engine for evaluating agent
// actions (shell commands, MCP tool calls, file reads) against pipelock's
// scanning pipeline. It is the core logic behind IDE hook integrations.
package decide

import (
	"encoding/json"
	"sort"
)

const (
	// maxExtractDepth prevents stack overflow on deeply nested JSON.
	maxExtractDepth = 64
	// maxExtractStrings caps the number of extracted strings to bound memory.
	maxExtractStrings = 2048
	// maxExtractBytes caps the total extracted text to 1 MiB.
	maxExtractBytes = 1 << 20
)

// ExtractAllStringsFromJSON recursively extracts all string keys and values
// from arbitrary JSON. Unlike jsonrpc.ExtractStringsFromJSON (values-only),
// this includes map keys because secrets can be encoded as JSON keys
// (e.g., {"sk-ant-api03-xxx": "value"}).
func ExtractAllStringsFromJSON(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var result []string
	var totalBytes int
	capped := false

	var extract func(v interface{}, depth int)
	extract = func(v interface{}, depth int) {
		if capped || depth > maxExtractDepth {
			return
		}
		switch val := v.(type) {
		case string:
			if len(result) >= maxExtractStrings || totalBytes+len(val) > maxExtractBytes {
				capped = true
				return
			}
			result = append(result, val)
			totalBytes += len(val)
		case []interface{}:
			for _, item := range val {
				extract(item, depth+1)
			}
		case map[string]interface{}:
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if len(result) >= maxExtractStrings || totalBytes+len(k) > maxExtractBytes {
					capped = true
					return
				}
				result = append(result, k)
				totalBytes += len(k)
				extract(val[k], depth+1)
			}
		}
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		extract(parsed, 0)
	}
	return result
}
