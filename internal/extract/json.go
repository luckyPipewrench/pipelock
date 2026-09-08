// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package extract provides shared text extraction utilities used by both the
// HTTP proxy body scanner and the MCP input scanner.
package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
)

// maxExtractDepth bounds recursion depth when extracting strings from JSON.
// Matches the limit used by jsonrpc.ExtractStringsFromJSON. Prevents stack
// overflow from deeply-nested payloads crafted by malicious agents.
const maxExtractDepth = 64

// DefaultJSONLeaf limits are the shared CEE bounds for JSON value partitioning.
// Transport-specific stream names may add tighter limits, but they must not
// independently redefine the parser's resource ceilings.
const (
	DefaultJSONLeafMaxDepth     = 64
	DefaultJSONLeafMaxStreams   = 128
	DefaultJSONLeafMaxPathBytes = 512
)

// JSONLeafLimits bounds JSON leaf partitioning for cross-request detection.
// Every bound is attacker-controlled input defense: callers must retain and
// scan the raw payload when Complete is false rather than trusting partial
// leaf streams.
type JSONLeafLimits struct {
	MaxDepth     int
	MaxStreams   int
	MaxPathBytes int
}

// JSONLeafPayloads returns scalar JSON values grouped by their JSON-pointer
// path. Object keys identify streams but are not concatenated with values:
// unrelated sibling fields must not interrupt a value split across requests.
// Complete is false for malformed, oversized, or unrepresentable inputs; that
// is the caller's signal to fall back to its complete raw payload.
func JSONLeafPayloads(raw json.RawMessage, limits JSONLeafLimits) (payloads map[string][]byte, complete bool) {
	if len(raw) == 0 || limits.MaxDepth < 0 || limits.MaxStreams <= 0 || limits.MaxPathBytes <= 0 {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	payloads = make(map[string][]byte)
	if !appendJSONLeafPayload(decoder, payloads, []byte("$"), 0, limits) || len(payloads) == 0 {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return payloads, true
}

// JSONLeafPayloadsPartial returns every representable scalar leaf from a valid
// JSON document. Unlike JSONLeafPayloads, input resource limits omit only the
// affected leaf: callers retain the original payload for their raw fallback.
// A false return means parsing failed and no leaf result is trustworthy.
func JSONLeafPayloadsPartial(raw json.RawMessage, limits JSONLeafLimits) (payloads map[string][]byte, valid bool) {
	if len(raw) == 0 || limits.MaxDepth < 0 || limits.MaxStreams <= 0 || limits.MaxPathBytes <= 0 {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	state := jsonLeafPartialState{payloads: make(map[string][]byte)}
	if !appendJSONLeafPayloadPartial(decoder, &state, []byte("$"), 0, limits) {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return state.payloads, true
}

type jsonLeafPartialState struct {
	payloads map[string][]byte
	order    []string
}

func appendJSONLeafPayload(decoder *json.Decoder, payloads map[string][]byte, path []byte, depth int, limits JSONLeafLimits) bool {
	if depth > limits.MaxDepth {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return false
				}
				keyString, ok := key.(string)
				if !ok {
					return false
				}
				pathLen := len(path)
				path, ok = appendJSONLeafPathPart(path, keyString, limits.MaxPathBytes)
				if !ok || !appendJSONLeafPayload(decoder, payloads, path, depth+1, limits) {
					return false
				}
				path = path[:pathLen]
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for index := 0; decoder.More(); index++ {
				pathLen := len(path)
				var ok bool
				path, ok = appendJSONLeafPathPart(path, strconv.Itoa(index), limits.MaxPathBytes)
				if !ok || !appendJSONLeafPayload(decoder, payloads, path, depth+1, limits) {
					return false
				}
				path = path[:pathLen]
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	case nil:
		return true
	case string:
		return appendJSONLeafValue(payloads, path, value, limits.MaxStreams)
	case json.Number:
		return appendJSONLeafValue(payloads, path, value.String(), limits.MaxStreams)
	case bool:
		return appendJSONLeafValue(payloads, path, strconv.FormatBool(value), limits.MaxStreams)
	default:
		return false
	}
}

func appendJSONLeafPayloadPartial(decoder *json.Decoder, state *jsonLeafPartialState, path []byte, depth int, limits JSONLeafLimits) bool {
	if depth > limits.MaxDepth {
		return skipJSONValue(decoder)
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return false
				}
				keyString, ok := key.(string)
				if !ok {
					return false
				}
				nextPath := appendJSONLeafPathPartPartial(path, keyString, limits.MaxPathBytes)
				if !appendJSONLeafPayloadPartial(decoder, state, nextPath, depth+1, limits) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for index := 0; decoder.More(); index++ {
				nextPath := appendJSONLeafPathPartPartial(path, strconv.Itoa(index), limits.MaxPathBytes)
				if !appendJSONLeafPayloadPartial(decoder, state, nextPath, depth+1, limits) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	case nil:
		return true
	case string:
		appendJSONLeafValuePartial(state, path, value, limits.MaxStreams)
		return true
	case json.Number:
		appendJSONLeafValuePartial(state, path, value.String(), limits.MaxStreams)
		return true
	case bool:
		appendJSONLeafValuePartial(state, path, strconv.FormatBool(value), limits.MaxStreams)
		return true
	default:
		return false
	}
}

func skipJSONValue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil || !skipJSONValue(decoder) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !skipJSONValue(decoder) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}

func appendJSONLeafPathPart(path []byte, part string, maxPathBytes int) ([]byte, bool) {
	pathBytes := len(path) + 1 + len(part) + strings.Count(part, "~") + strings.Count(part, "/")
	if pathBytes > maxPathBytes {
		return nil, false
	}
	path = append(path, '/')
	for i := 0; i < len(part); i++ {
		switch part[i] {
		case '~':
			path = append(path, '~', '0')
		case '/':
			path = append(path, '~', '1')
		default:
			path = append(path, part[i])
		}
	}
	return path, true
}

func appendJSONLeafPathPartPartial(path []byte, part string, maxPathBytes int) []byte {
	next, ok := appendJSONLeafPathPart(path, part, maxPathBytes)
	if ok {
		return next
	}
	fullPath := append(append([]byte(nil), path...), '/')
	fullPath = append(fullPath, part...)
	digest := sha256.Sum256(fullPath)
	return append([]byte("$#"), []byte(hex.EncodeToString(digest[:]))...)
}

func appendJSONLeafValue(payloads map[string][]byte, path []byte, value string, maxStreams int) bool {
	stream := string(path)
	if _, exists := payloads[stream]; !exists && len(payloads) >= maxStreams {
		return false
	}
	payloads[stream] = append(payloads[stream], value...)
	return true
}

func appendJSONLeafValuePartial(state *jsonLeafPartialState, path []byte, value string, maxStreams int) {
	stream := string(path)
	if _, exists := state.payloads[stream]; !exists {
		if len(state.payloads) >= maxStreams {
			delete(state.payloads, state.order[0])
			state.order = state.order[1:]
		}
		state.order = append(state.order, stream)
	}
	state.payloads[stream] = append(state.payloads[stream], value...)
}

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
