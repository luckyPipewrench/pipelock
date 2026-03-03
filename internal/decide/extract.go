// Package decide implements a shared decision engine for evaluating agent
// actions (shell commands, MCP tool calls, file reads) against pipelock's
// scanning pipeline. It is the core logic behind IDE hook integrations.
package decide

import (
	"encoding/json"
	"sort"
)

// maxExtractDepth prevents stack overflow on deeply nested JSON.
const maxExtractDepth = 64

// ExtractAllStringsFromJSON recursively extracts all string keys and values
// from arbitrary JSON. Unlike jsonrpc.ExtractStringsFromJSON (values-only),
// this includes map keys because secrets can be encoded as JSON keys
// (e.g., {"sk-ant-api03-xxx": "value"}).
func ExtractAllStringsFromJSON(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var result []string
	var extract func(v interface{}, depth int)
	extract = func(v interface{}, depth int) {
		if depth > maxExtractDepth {
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
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				result = append(result, k)
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
