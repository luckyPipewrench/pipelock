// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

// responseEnvelopeRemainder partitions by field ownership, rather than string
// equality across the message. Identical text in an extension still belongs to
// the envelope. Resource URIs keep injection coverage on a separate channel;
// they are not response text for inbound DLP.
func responseEnvelopeRemainder(raw []byte, rpc jsonrpc.RPCResponse) (string, string, bool) {
	// Check the complete message before removing any consumed subtrees. In
	// particular, pruning structuredContent must not relax the depth/key bound.
	if jsonrpc.ExtractKeysFromJSONResult(raw).Truncated {
		return "", "", false
	}
	var envelope map[string]any
	if json.Unmarshal(raw, &envelope) != nil {
		return "", "", false
	}
	var uris []string
	for _, key := range jsonrpc.SortedKeys(envelope) {
		value := envelope[key]
		// encoding/json accepts case-insensitive aliases. A shadowed alias
		// remains envelope text unless it is the value the typed parse used.
		switch {
		case strings.EqualFold(key, "result"):
			if sameResponseJSONValue(value, rpc.Result) {
				envelope[key] = removeTypedResponseText(value, rpc.Result, &uris)
			}
		case strings.EqualFold(key, "params"):
			if sameResponseJSONValue(value, rpc.Params) {
				envelope[key] = removeTypedResponseText(value, rpc.Params, &uris)
			}
		case strings.EqualFold(key, "error"):
			if !sameResponseJSONValue(value, rpc.Error) {
				continue
			}
			var rpcErr jsonrpc.RPCError
			if json.Unmarshal(rpc.Error, &rpcErr) == nil && rpcErr.Message != "" {
				if fields, ok := value.(map[string]any); ok {
					for _, name := range jsonrpc.SortedKeys(fields) {
						field := fields[name]
						switch {
						case strings.EqualFold(name, "message"):
							if field == rpcErr.Message {
								fields[name] = nil
							}
						case strings.EqualFold(name, "data"):
							if sameResponseJSONValue(field, rpcErr.Data) {
								fields[name] = removeTypedResponseText(field, rpcErr.Data, &uris)
							}
						}
					}
				}
			} else {
				envelope[key] = removeTypedResponseText(value, rpc.Error, &uris)
			}
		}
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", "", false
	}
	values := jsonrpc.ExtractVisibleStringsFromJSONResult(encoded)
	keys := jsonrpc.ExtractKeysFromJSONResult(encoded)
	if values.Truncated || keys.Truncated {
		return "", "", false
	}
	return strings.Join(append(values.Strings, keys.Keys...), "\n"), strings.Join(uris, "\n"), true
}

// removeTypedResponseText mirrors ExtractTextResult's successful typed parse
// and its arbitrary-JSON fallback. Null placeholders retain keys the typed
// extractor does not own. Removing structuredContent retains its parent key;
// the typed extractor already owns every value and nested key in that subtree.
func removeTypedResponseText(value any, raw json.RawMessage, uris *[]string) any {
	var result jsonrpc.ToolResult
	if json.Unmarshal(raw, &result) != nil || (len(result.Content) == 0 && result.StructuredContent == nil) {
		return removeResponseStringLeaves(value, false)
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return value
	}
	for _, name := range jsonrpc.SortedKeys(fields) {
		field := fields[name]
		switch {
		case strings.EqualFold(name, "structuredContent"):
			if sameResponseJSONValue(field, result.StructuredContent) {
				fields[name] = nil
			}
		case strings.EqualFold(name, "content"):
			blocks, ok := field.([]any)
			if !ok {
				continue
			}
			for i, item := range blocks {
				if i >= len(result.Content) {
					continue
				}
				typed := result.Content[i]
				block, ok := item.(map[string]any)
				if !ok {
					continue
				}
				owned := map[string]string{"text": typed.Text, "name": typed.Name, "title": typed.Title, "description": typed.Description, "data": typed.Data, "blob": typed.Blob, "raw": typed.Raw}
				for _, key := range jsonrpc.SortedKeys(block) {
					val := block[key]
					switch strings.ToLower(key) {
					case "text", "name", "title", "description", "data", "blob", "raw":
						if text, ok := val.(string); ok && text == owned[strings.ToLower(key)] {
							block[key] = nil
						}
					case "uri":
						if uri, ok := val.(string); ok {
							*uris = append(*uris, uri)
							block[key] = nil
						}
					case "resource":
						if resource, ok := val.(map[string]any); ok && typed.Resource != nil {
							for _, rk := range jsonrpc.SortedKeys(resource) {
								rv := resource[rk]
								if _, ok := rv.(string); !ok {
									continue
								}
								switch strings.ToLower(rk) {
								case "text":
									if rv == typed.Resource.Text {
										resource[rk] = nil
									}
								case "blob":
									if rv == typed.Resource.Blob {
										resource[rk] = nil
									}
								case "uri":
									*uris = append(*uris, rv.(string))
									resource[rk] = nil
								}
							}
						}
					}
				}
			}
		}
	}
	return value
}

func sameResponseJSONValue(value any, raw json.RawMessage) bool {
	var selected any
	return json.Unmarshal(raw, &selected) == nil && reflect.DeepEqual(value, selected)
}

func removeResponseStringLeaves(value any, mediaCandidate bool) any {
	switch v := value.(type) {
	case string:
		if mediaCandidate {
			encoded, err := json.Marshal(map[string]string{"data": v})
			if err != nil {
				return value
			}
			visible := jsonrpc.ExtractVisibleStringsFromJSONResult(encoded)
			// A decoded media view is distinct from the raw string consumed
			// by the arbitrary-JSON fallback. Retain it for envelope scanning.
			if len(visible.Strings) > 0 && (len(visible.Strings) != 1 || visible.Strings[0] != v) {
				return value
			}
		}
		return nil
	case []any:
		for i, item := range v {
			v[i] = removeResponseStringLeaves(item, mediaCandidate)
		}
	case map[string]any:
		for key, item := range v {
			media := strings.EqualFold(key, "data") || strings.EqualFold(key, "blob") || strings.EqualFold(key, "raw")
			v[key] = removeResponseStringLeaves(item, media)
		}
	}
	return value
}
