// Package extract provides shared text extraction utilities used by both the
// HTTP proxy body scanner and the MCP input scanner.
package extract

import (
	"encoding/json"
	"sort"
	"strconv"
)

// maxExtractDepth bounds recursion depth when extracting strings from JSON.
// Matches the limit used by jsonrpc.ExtractStringsFromJSON. Prevents stack
// overflow from deeply-nested payloads crafted by malicious agents.
const maxExtractDepth = 64

// AllStringsFromJSON recursively extracts all string values AND keys from
// arbitrary JSON. Unlike jsonrpc.ExtractStringsFromJSON (values only), this
// version also extracts map keys because an agent can exfiltrate secrets by
// encoding them as JSON object keys. Numeric and boolean values are
// stringified so DLP patterns can match them.
func AllStringsFromJSON(raw json.RawMessage) []string {
	var result []string
	var extract func(v interface{}, depth int)
	extract = func(v interface{}, depth int) {
		if depth > maxExtractDepth {
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
	return result
}
