// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package extract provides shared text extraction utilities used by both the
// HTTP proxy body scanner and the MCP input scanner.
package extract

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strconv"
)

// maxExtractDepth bounds recursion depth when extracting strings from JSON.
// Matches the limit used by jsonrpc.ExtractStringsFromJSON. Prevents stack
// overflow from deeply-nested payloads crafted by malicious agents.
const maxExtractDepth = 64

// JSONStringsResult is the bounded extraction result. Truncated is true when
// the JSON contains content beyond maxExtractDepth, meaning callers that make
// allow/block decisions must fail closed instead of trusting partial strings.
type JSONStringsResult struct {
	Strings   []string
	Truncated bool
}

// AllStringsFromJSON recursively extracts all string values AND keys from
// arbitrary JSON. Unlike jsonrpc.ExtractStringsFromJSON (values only), this
// version also extracts map keys because an agent can exfiltrate secrets by
// encoding them as JSON object keys. Numeric and boolean values are
// stringified so DLP patterns can match them.
func AllStringsFromJSON(raw json.RawMessage) []string {
	return AllStringsFromJSONResult(raw).Strings
}

// AllStringsFromJSONResult recursively extracts all string values AND keys from
// arbitrary JSON and reports whether extraction hit the nesting cap.
func AllStringsFromJSONResult(raw json.RawMessage) JSONStringsResult {
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
		case float64:
			result = append(result, strconv.FormatFloat(val, 'f', -1, 64))
		case bool:
			result = append(result, strconv.FormatBool(val))
		case []interface{}:
			for _, item := range val {
				extract(item, depth+1)
			}
		case map[string]interface{}:
			// Sort keys for deterministic output. Without this, split-secret
			// detection via joined-string DLP becomes order-dependent because
			// Go map iteration is randomized.
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
	return JSONStringsResult{Strings: result, Truncated: truncated}
}

// AllStringsFromJSONOrdered extracts string-ish JSON tokens in source order,
// including object keys. It is intentionally separate from AllStringsFromJSON:
// split-secret DLP wants deterministic sorted traversal, while prompt
// injection phrase reconstruction benefits from the sender's original order.
func AllStringsFromJSONOrdered(raw json.RawMessage) []string {
	return AllStringsFromJSONOrderedResult(raw).Strings
}

// AllStringsFromJSONOrderedResult extracts string-ish JSON tokens in source
// order and reports whether any token was skipped past the depth cap.
func AllStringsFromJSONOrderedResult(raw json.RawMessage) JSONStringsResult {
	if len(raw) == 0 {
		return JSONStringsResult{}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var result []string
	depth := 0
	truncated := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return JSONStringsResult{}
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
				if depth > maxExtractDepth {
					truncated = true
				}
			case '}', ']':
				if depth > 0 {
					depth--
				}
			}
		case string:
			if depth <= maxExtractDepth {
				result = append(result, v)
			}
		case json.Number:
			if depth <= maxExtractDepth {
				result = append(result, v.String())
			}
		case bool:
			if depth <= maxExtractDepth {
				result = append(result, strconv.FormatBool(v))
			}
		}
	}
	return JSONStringsResult{Strings: result, Truncated: truncated}
}
