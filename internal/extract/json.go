// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package extract provides shared text extraction utilities used by both the
// HTTP proxy body scanner and the MCP input scanner.
package extract

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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

// JSONLeafPayloads returns scalar JSON values grouped by their JSON-pointer-like
// path. The path uses RFC 6901 segment escaping (~0, ~1) but roots at a "$"
// sentinel of our own, so it is not a literal JSON Pointer. Object keys identify
// streams but are not concatenated with values:
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

// JSONLeafBucketPayloads groups every scalar JSON leaf into one of bucketCount
// buckets. Unlike JSONLeafPayloadsPartial, it never discards a leaf to enforce
// a path-count ceiling: the fixed bucket count is the resource bound. Deep
// paths are reduced to a truncated-plus-digest representation before bucket
// selection, so a depth limit does not omit their content.
//
// Bucket selection is a keyed digest of the normalized path. The same path
// stays in the same bucket for one key; a different key is a different map.
// Callers must pass a secret that lives at least as long as the fragment
// streams those buckets feed. An empty key declines to partition: a public
// digest would let an attacker grind a colliding path offline.
//
// valid is true only for a complete JSON document. A parse error still
// returns every leaf that was already represented; omitting those leaves
// would drop partitioned evidence and leave only the raw concatenated
// stream, which cannot reconstruct a split separated by unrelated padding.
//
// Truncation (an unexpected EOF, as when a caller caps the body it reads) is
// exactly this partial case: every leaf whose value completed before the cut
// is returned with valid=false, and content after the last complete leaf is
// left to the caller's raw stream. The contract is therefore that a partial
// payload map is trustworthy for the leaves it contains but is NOT a complete
// inspection; callers keyed on valid=false must still scan their raw fallback.
func JSONLeafBucketPayloads(raw json.RawMessage, limits JSONLeafLimits, bucketCount int, key []byte) (payloads map[string][]byte, valid bool) {
	if len(raw) == 0 || limits.MaxDepth < 0 || limits.MaxPathBytes <= 0 || bucketCount <= 0 || bucketCount > maxJSONLeafBuckets || len(key) == 0 {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	state := jsonLeafBucketState{payloads: make(map[string][]byte), bucketCount: bucketCount, key: key}
	if !appendJSONLeafBucketPayload(decoder, &state, []byte("$"), 0, limits) {
		return jsonLeafBucketResult(state.payloads), false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return jsonLeafBucketResult(state.payloads), false
	}
	return jsonLeafBucketResult(state.payloads), true
}

func jsonLeafBucketResult(payloads map[string][]byte) map[string][]byte {
	if len(payloads) == 0 {
		return nil
	}
	return payloads
}

type jsonLeafBucketState struct {
	payloads    map[string][]byte
	bucketCount int
	key         []byte
}

func appendJSONLeafBucketPayload(decoder *json.Decoder, state *jsonLeafBucketState, path []byte, depth int, limits JSONLeafLimits) bool {
	// Past MaxDepth, stop recursing and fold the whole subtree's scalar leaves
	// into path's truncated-plus-digest bucket. Without this head check the
	// bucket walker (unlike its JSONLeafPayloads/Partial siblings) recursed once
	// per nesting level, so a deeply nested body could exhaust the goroutine
	// stack. jsonLeafBucketIndex already reduces an over-depth path to a
	// digest, so no leaf is discarded; it is bucketed rather than descended.
	if depth > limits.MaxDepth {
		return bucketOverDepthValue(decoder, state, path, depth, limits.MaxDepth)
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
				// json.Decoder guarantees an object member name arrives as a
				// string token; a non-string key is a decoder error handled
				// above. The check is retained as fail-closed defense.
				keyString, ok := key.(string)
				if !ok {
					return false
				}
				nextPath := appendJSONLeafPathPartPartial(path, keyString, limits.MaxPathBytes)
				if !appendJSONLeafBucketPayload(decoder, state, nextPath, depth+1, limits) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for index := 0; decoder.More(); index++ {
				nextPath := appendJSONLeafPathPartPartial(path, strconv.Itoa(index), limits.MaxPathBytes)
				if !appendJSONLeafBucketPayload(decoder, state, nextPath, depth+1, limits) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			// A value-position Delim token is only '{' or '[': a stray '}' or
			// ']' is a decoder error, not a token. Retained as fail-closed
			// defense so an unexpected shape cannot slip past unbucketed.
			return false
		}
	case nil:
		return true
	case string:
		appendJSONLeafBucketValue(state, path, depth, limits.MaxDepth, value)
		return true
	case json.Number:
		appendJSONLeafBucketValue(state, path, depth, limits.MaxDepth, value.String())
		return true
	case bool:
		appendJSONLeafBucketValue(state, path, depth, limits.MaxDepth, strconv.FormatBool(value))
		return true
	default:
		// Token returns only Delim, string, json.Number (UseNumber), bool, and
		// nil. Any other dynamic type is impossible; retained as fail-closed
		// defense rather than assuming the decoder's token set never widens.
		return false
	}
}

// bucketOverDepthValue consumes exactly one JSON value that sits past MaxDepth
// and folds every scalar leaf it contains into path's over-depth bucket, using
// an explicit container stack instead of recursion so pathological nesting
// cannot overflow the goroutine stack. depth is held fixed at the boundary
// value (already > maxDepth), so jsonLeafBucketIndex routes every leaf through
// the truncated-plus-digest path and no content is discarded. Object member
// names are consumed but not bucketed, matching the value-only contract of the
// recursive path. The fixed bucket count still bounds retained state.
func bucketOverDepthValue(decoder *json.Decoder, state *jsonLeafBucketState, path []byte, depth, maxDepth int) bool {
	// stack element true = inside an object (tokens alternate key/value),
	// false = inside an array (every element is a value).
	var stack []bool
	// expectKey is meaningful only while the top of stack is an object.
	expectKey := false
	for {
		if len(stack) > 0 && stack[len(stack)-1] && expectKey && decoder.More() {
			// Consume and discard the object member name.
			keyTok, err := decoder.Token()
			if err != nil {
				return false
			}
			if _, ok := keyTok.(string); !ok {
				return false
			}
			expectKey = false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, true)
				expectKey = true
			case '[':
				stack = append(stack, false)
			case '}', ']':
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
				expectKey = len(stack) > 0 && stack[len(stack)-1]
			}
		case string:
			appendJSONLeafBucketValue(state, path, depth, maxDepth, value)
			expectKey = len(stack) > 0 && stack[len(stack)-1]
		case json.Number:
			appendJSONLeafBucketValue(state, path, depth, maxDepth, value.String())
			expectKey = len(stack) > 0 && stack[len(stack)-1]
		case bool:
			appendJSONLeafBucketValue(state, path, depth, maxDepth, strconv.FormatBool(value))
			expectKey = len(stack) > 0 && stack[len(stack)-1]
		case nil:
			expectKey = len(stack) > 0 && stack[len(stack)-1]
		}
		if len(stack) == 0 {
			return true
		}
	}
}

func appendJSONLeafBucketValue(state *jsonLeafBucketState, path []byte, depth, maxDepth int, value string) {
	bucket := strconv.Itoa(jsonLeafBucketIndex(path, depth, maxDepth, state.bucketCount, state.key))
	state.payloads[bucket] = append(state.payloads[bucket], value...)
}

func jsonLeafBucketIndex(path []byte, depth, maxDepth, bucketCount int, key []byte) int {
	if bucketCount <= 0 || bucketCount > maxJSONLeafBuckets || len(key) == 0 {
		return 0
	}
	material := path
	if depth > maxDepth {
		digest := sha256.Sum256(path)
		prefixLen := min(len(path), maxPathBytesForBucketPrefix)
		material = make([]byte, prefixLen+1+hex.EncodedLen(len(digest)))
		copy(material, path[:prefixLen])
		material[prefixLen] = '#'
		hex.Encode(material[prefixLen+1:], digest[:])
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(material)
	digest := mac.Sum(nil)
	return int(binary.BigEndian.Uint16(digest[:2]) % uint16(bucketCount))
}

const (
	maxJSONLeafBuckets          = 65535
	maxPathBytesForBucketPrefix = 64
)

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
