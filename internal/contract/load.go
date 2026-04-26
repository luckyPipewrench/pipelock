// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrEmptyPayload rejects empty or JSON-null inputs at the strict transport boundary.
var ErrEmptyPayload = errors.New("empty or null payload")

// ErrUnknownField rejects unknown fields at the strict transport boundary.
// The wrapped json error has the offending field name.
var ErrUnknownField = errors.New("unknown field in signed-artifact transport payload")

// DecodeStrictJSON decodes raw into target with the strictness required for
// signed-artifact transports per the design doc canonicalization invariants:
//
//   - Empty input or the literal "null" reject (no silent zero-value binding).
//   - Unknown fields reject (Decoder.DisallowUnknownFields). This is the
//     normative check from the design's "unknown fields reject recursively at
//     every depth" rule. Without it, downstream Validate() runs on a typed
//     struct that already dropped unsigned/unchecked fields from the input.
//   - Integer fidelity preserved (Decoder.UseNumber).
//   - Trailing tokens after the value reject (no junk after the payload).
//
// Use this for every transport-to-typed-struct binding. Validate() and
// SignablePreimage() never see the raw transport bytes; they only see the
// typed struct, so unknown-field rejection MUST happen here.
func DecodeStrictJSON(raw []byte, target any) error {
	// RFC 8259 lets insignificant whitespace surround any JSON value, so a
	// bare null payload can arrive as " null", "null\n", "\tnull\r\n", etc.
	// Without trimming first, the equality check below misses those forms,
	// json.Decoder.Decode then binds null to a typed struct as the zero
	// value with no error, and the trailing-token guard sees EOF and returns
	// nil. That silently violates the "no silent zero-value binding"
	// invariant. Trim ASCII JSON whitespace before the literal compare.
	trimmed := bytes.TrimLeft(raw, " \t\n\r")
	trimmed = bytes.TrimRight(trimmed, " \t\n\r")
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ErrEmptyPayload
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(target); err != nil {
		// json.Decoder reports unknown fields with a message starting with
		// "json: unknown field"; normalize to our sentinel for errors.Is.
		// Syntax errors stay as plain decode errors.
		var syntaxErr *json.SyntaxError
		if !errors.As(err, &syntaxErr) && isUnknownField(err) {
			return fmt.Errorf("%w: %w", ErrUnknownField, err)
		}
		return fmt.Errorf("strict decode: %w", err)
	}
	// Trailing tokens after the value (another value, a delimiter) are rejected.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTrailingTokens, err)
		}
		return fmt.Errorf("%w after top-level value", ErrTrailingTokens)
	}
	return nil
}

// isUnknownField reports whether err is the json.Decoder's "unknown field" error.
// The stdlib does not export a typed error for this case, so we string-match.
func isUnknownField(err error) bool {
	const prefix = "json: unknown field "
	if err == nil {
		return false
	}
	msg := err.Error()
	return len(msg) >= len(prefix) && msg[:len(prefix)] == prefix
}

// LoadContract parses raw JSON into a Contract using DecodeStrictJSON.
// Unknown fields, trailing tokens, and empty/null payloads reject.
func LoadContract(raw []byte) (Contract, error) {
	var c Contract
	if err := DecodeStrictJSON(raw, &c); err != nil {
		return Contract{}, fmt.Errorf("load contract: %w", err)
	}
	return c, nil
}

// LoadActiveManifest parses raw JSON into an ActiveManifest using DecodeStrictJSON.
func LoadActiveManifest(raw []byte) (ActiveManifest, error) {
	var m ActiveManifest
	if err := DecodeStrictJSON(raw, &m); err != nil {
		return ActiveManifest{}, fmt.Errorf("load active_manifest: %w", err)
	}
	return m, nil
}

// LoadCompileManifest parses raw JSON into a CompileManifest using DecodeStrictJSON.
func LoadCompileManifest(raw []byte) (CompileManifest, error) {
	var m CompileManifest
	if err := DecodeStrictJSON(raw, &m); err != nil {
		return CompileManifest{}, fmt.Errorf("load compile_manifest: %w", err)
	}
	return m, nil
}

// LoadTombstone parses raw JSON into a Tombstone using DecodeStrictJSON.
func LoadTombstone(raw []byte) (Tombstone, error) {
	var t Tombstone
	if err := DecodeStrictJSON(raw, &t); err != nil {
		return Tombstone{}, fmt.Errorf("load tombstone: %w", err)
	}
	return t, nil
}

// LoadKeyRoster parses raw JSON into a KeyRoster using DecodeStrictJSON.
func LoadKeyRoster(raw []byte) (KeyRoster, error) {
	var r KeyRoster
	if err := DecodeStrictJSON(raw, &r); err != nil {
		return KeyRoster{}, fmt.Errorf("load key_roster: %w", err)
	}
	return r, nil
}

// LoadVerificationMetadata parses raw JSON into a VerificationMetadata using DecodeStrictJSON.
func LoadVerificationMetadata(raw []byte) (VerificationMetadata, error) {
	var v VerificationMetadata
	if err := DecodeStrictJSON(raw, &v); err != nil {
		return VerificationMetadata{}, fmt.Errorf("load verification_metadata: %w", err)
	}
	return v, nil
}
