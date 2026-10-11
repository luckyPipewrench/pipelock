// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"bytes"
	"encoding/json"
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// ValidateMessageKeys rejects malformed JSON and exact duplicates everywhere,
// then checks case aliases only in protocol fields that are bound to schemas.
// Arguments, metadata and JSON Schema properties remain case-sensitive maps.
func ValidateMessageKeys(data []byte) error {
	if err := redact.NoDuplicateJSONKeys(data); err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := ValidateMessageKeys(item); err != nil {
				return err
			}
		}
		return nil
	}
	if err := redact.NoSchemaKeyAliases(data, reflect.TypeFor[RPCResponse]()); err != nil {
		return err
	}
	var rpc RPCResponse
	if err := json.Unmarshal(data, &rpc); err != nil {
		return nil // The consumer owns field-type and protocol validation.
	}
	if len(rpc.Error) > 0 {
		if err := redact.NoSchemaKeyAliases(rpc.Error, reflect.TypeFor[RPCError]()); err != nil {
			return err
		}
	}
	if rpc.Method == "tools/call" {
		var schema struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      json.RawMessage `json:"_meta"`
		}
		if len(rpc.Params) > 0 {
			if err := redact.NoSchemaKeyAliases(rpc.Params, reflect.TypeOf(schema)); err != nil {
				return err
			}
		}
	}
	if rpc.Method == "resources/read" && len(rpc.Params) > 0 {
		var schema struct {
			URI string `json:"uri"`
		}
		if err := redact.NoSchemaKeyAliases(rpc.Params, reflect.TypeOf(schema)); err != nil {
			return err
		}
	}
	result := bytes.TrimSpace(rpc.Result)
	if len(result) > 0 && result[0] == '{' {
		var schema struct {
			Tools []struct {
				Name         string          `json:"name"`
				Title        string          `json:"title"`
				Description  string          `json:"description"`
				InputSchema  json.RawMessage `json:"inputSchema"`
				OutputSchema json.RawMessage `json:"outputSchema"`
				Annotations  json.RawMessage `json:"annotations"`
				Meta         json.RawMessage `json:"_meta"`
			} `json:"tools"`
			Content           []ContentBlock  `json:"content"`
			StructuredContent json.RawMessage `json:"structuredContent"`
			IsError           bool            `json:"isError"`
			NextCursor        string          `json:"nextCursor"`
			Meta              json.RawMessage `json:"_meta"`
		}
		if err := redact.NoSchemaKeyAliases(result, reflect.TypeOf(schema)); err != nil {
			return err
		}
	}
	return nil
}
