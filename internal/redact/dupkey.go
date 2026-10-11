// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// checkNoDuplicateKeys is the package-internal wrapper used by RewriteJSON.
// External callers (e.g. the MCP envelope/params decoders) use
// NoDuplicateJSONKeys, which has the same semantics.
func checkNoDuplicateKeys(body []byte) error {
	return NoDuplicateJSONKeys(body)
}

// NoDuplicateJSONKeys verifies that no JSON object in body has two members
// with exactly equal decoded names at the same nesting level. Schema field
// aliases are checked separately by NoSchemaKeyAliases.
// Decoding duplicate-key JSON into map[string]interface{} (or
// map[string]json.RawMessage) silently
// discards all but one occurrence, which lets an attacker smuggle a secret
// past anything that selects values from the post-decode map by smuggling
// the secret behind a benign duplicate. A first-wins upstream parser
// still treats the discarded secret as the authoritative value, so the
// JSON parser differential becomes an information-flow bypass.
//
// MCP redaction and MCP input scanning select tools/call routing fields
// (`method`, `params`, `arguments`) from a decoded map BEFORE
// RewriteJSON's own guard runs, so they need this check at the ingress
// point - not inside the redaction engine.
//
// The check walks the token stream of body via encoding/json so it sees
// the raw key order, not the post-map representation. Arrays are walked
// for contained objects but contribute no keys.
//
// Returns nil if every object is duplicate-free. On a duplicate, returns
// a *BlockError with ReasonDuplicateKey. Any other tokenizer error
// returns a *BlockError with ReasonBodyUnparseable so malformed input
// falls through to the same fail-closed path as elsewhere in
// RewriteJSON.
func NoDuplicateJSONKeys(body []byte) error {
	return keyBlock(jsonscan.ValidateKeys(body, maxDuplicateKeyScanDepth))
}

// NoSchemaKeyAliases validates exact duplicates throughout the document and
// rejects noncanonical case aliases only at fields bound by schema. RawMessage
// and free-form map keys retain their case-sensitive application meaning.
func NoSchemaKeyAliases(body []byte, schema reflect.Type) error {
	if err := NoDuplicateJSONKeys(body); err != nil {
		return err
	}
	return keyBlock(jsonscan.RejectStructAliases(body, schema))
}

func keyBlock(err error) error {
	if err != nil {
		if errors.Is(err, jsonscan.ErrDuplicateKey) || errors.Is(err, jsonscan.ErrCaseFoldedKey) {
			return newBlock(ReasonDuplicateKey, 0, err.Error())
		}
		return newBlock(ReasonBodyUnparseable, 0, "invalid JSON: "+err.Error())
	}
	return nil
}

// Keep the MCP/redaction transport's existing encoding/json nesting bound.
const maxDuplicateKeyScanDepth = 10000
