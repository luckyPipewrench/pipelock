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
			if err := validateMessageSchemaKeys(bytes.TrimSpace(item)); err != nil {
				return err
			}
		}
		return nil
	}
	return validateMessageSchemaKeys(trimmed)
}

// The whole document has already passed key validation. A batch has exactly
// one message level; non-object elements have no protocol fields to bind.
// Consumers own rejection of invalid message shapes, including nested arrays.
func validateMessageSchemaKeys(data []byte) error {
	if len(data) == 0 || data[0] != '{' {
		return nil
	}
	if err := redact.NoSchemaKeyAliasesInValidatedJSON(data, reflect.TypeFor[RPCResponse]()); err != nil {
		return err
	}
	// Extract raw fields so an unrelated field-type error cannot skip nested
	// schema checks. The consumer still owns field-type and protocol validation.
	var rpc struct {
		Method json.RawMessage `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(data, &rpc); err != nil {
		return nil
	}
	var method string
	if len(rpc.Method) > 0 {
		_ = json.Unmarshal(rpc.Method, &method)
	}
	if len(rpc.Error) > 0 {
		if err := redact.NoSchemaKeyAliasesInValidatedJSON(rpc.Error, reflect.TypeFor[RPCError]()); err != nil {
			return err
		}
	}
	if method == "tools/call" {
		var schema struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      json.RawMessage `json:"_meta"`
		}
		if len(rpc.Params) > 0 {
			if err := redact.NoSchemaKeyAliasesInValidatedJSON(rpc.Params, reflect.TypeOf(schema)); err != nil {
				return err
			}
		}
	}
	if method == "resources/read" && len(rpc.Params) > 0 {
		var schema struct {
			URI string `json:"uri"`
		}
		if err := redact.NoSchemaKeyAliasesInValidatedJSON(rpc.Params, reflect.TypeOf(schema)); err != nil {
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
		if err := redact.NoSchemaKeyAliasesInValidatedJSON(result, reflect.TypeOf(schema)); err != nil {
			return err
		}
	}
	return nil
}
