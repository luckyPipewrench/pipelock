// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// checkNoDuplicateKeys is the package-internal wrapper used by RewriteJSON.
// External callers (e.g. the MCP envelope/params decoders) use
// NoDuplicateJSONKeys, which has the same semantics.
func checkNoDuplicateKeys(body []byte) error {
	return NoDuplicateJSONKeys(body)
}

// NoDuplicateJSONKeys verifies that no JSON object in body has two members
// with the same name at the same nesting level. Decoding duplicate-key JSON
// into map[string]interface{} (or map[string]json.RawMessage) silently
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
	dec := json.NewDecoder(bytes.NewReader(body))
	// UseNumber for parity with the main decode path; it affects how
	// numeric tokens are represented but is irrelevant for key tracking.
	dec.UseNumber()
	if err := walkForDuplicates(dec, 0); err != nil {
		return err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return newBlock(ReasonBodyUnparseable, 0, err.Error())
		}
		return newBlock(ReasonBodyUnparseable, 0, fmt.Sprintf("unexpected trailing JSON token %v", tok))
	}
	return nil
}

// maxDuplicateKeyScanDepth bounds the recursion in walkForDuplicates. The
// token-streaming walk recurses one Go stack frame per JSON nesting level and,
// unlike the value decoder, encoding/json's Token() API enforces no depth
// limit - so a maliciously deep array (well within the 10MB line cap) would
// otherwise exhaust the goroutine stack and crash the process. The cap matches
// encoding/json's own maxNestingDepth, so any body that survives this walk is
// also accepted by the json.Unmarshal that immediately follows every caller:
// no new false positives, and anything deeper fails closed identically on both
// (here as ReasonBodyUnparseable, there as an invalid-JSON parse error).
const maxDuplicateKeyScanDepth = 10000

// walkForDuplicates consumes exactly one JSON value from dec and recurses
// into any contained objects or arrays. The caller supplies a decoder
// that has not yet emitted the outer value's opening token. depth is the
// current nesting level, bounded by maxDuplicateKeyScanDepth.
func walkForDuplicates(dec *json.Decoder, depth int) error {
	if depth >= maxDuplicateKeyScanDepth {
		return newBlock(ReasonBodyUnparseable, 0, "JSON nesting exceeds maximum scan depth")
	}
	tok, err := dec.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return newBlock(ReasonBodyUnparseable, 0, err.Error())
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		// Scalar: string / number / bool / null - nothing to do.
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return newBlock(ReasonBodyUnparseable, 0, err.Error())
			}
			key, ok := keyTok.(string)
			if !ok {
				// JSON guarantees object keys are strings; this
				// branch is defensive against a decoder bug.
				return newBlock(ReasonBodyUnparseable, 0, "object key was not a string")
			}
			if _, dup := seen[key]; dup {
				return newBlock(ReasonDuplicateKey, 0, fmt.Sprintf("duplicate object key %q", key))
			}
			seen[key] = struct{}{}
			if err := walkForDuplicates(dec, depth+1); err != nil {
				return err
			}
		}
		// Consume the matching '}'.
		if _, err := dec.Token(); err != nil {
			return newBlock(ReasonBodyUnparseable, 0, err.Error())
		}
	case '[':
		for dec.More() {
			if err := walkForDuplicates(dec, depth+1); err != nil {
				return err
			}
		}
		// Consume the matching ']'.
		if _, err := dec.Token(); err != nil {
			return newBlock(ReasonBodyUnparseable, 0, err.Error())
		}
	default:
		// ']' or '}' at this position means the body is malformed.
		return newBlock(ReasonBodyUnparseable, 0, fmt.Sprintf("unexpected delimiter %q", delim))
	}
	return nil
}
