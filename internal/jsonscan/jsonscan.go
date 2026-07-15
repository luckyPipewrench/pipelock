// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package jsonscan provides a streaming duplicate-key check used on the receipt
// and flight-recorder verify paths. It is a leaf package so both internal/receipt
// and internal/recorder can share one implementation (receipt imports recorder,
// so the shared helper cannot live in either of them).
package jsonscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

// ErrDuplicateKey is returned when input contains a duplicate object key.
var ErrDuplicateKey = fmt.Errorf("duplicate object key")

// MaxNestingDepth bounds the scanner's recursion. json.Decoder.Token() (unlike
// json.Unmarshal) does NOT enforce a nesting limit, so without this bound a
// deeply nested document could overflow the goroutine stack and panic — and the
// verify paths run this scan before json.Unmarshal, which would otherwise be the
// depth backstop. The cap is the shared cross-language receipt-nesting limit:
// all reference verifiers enforce 128 explicitly, so they reject input nested
// beyond this depth. Receipts nest ~4 levels, so honest input is never
// affected; over-deep input is rejected, not crashed.
const MaxNestingDepth = 128

// MaxExactJSONInteger is the largest integer every supported verifier runtime
// can represent exactly. JavaScript numbers lose integer precision above this
// boundary, while Go and Rust retain it; accepting larger JSON numbers would
// let identical bytes produce different packet or receipt semantics.
const MaxExactJSONInteger = 1<<53 - 1

// RejectDuplicateKeys reports an error if data contains a duplicate object key
// at any nesting depth. It streams tokens with a json.Decoder so it sees every
// key occurrence, not the last-wins map encoding/json would build. encoding/json
// silently keeps the last value for a duplicate key, which lets an attacker
// smuggle a different value past a display, log, or summary layer that reads the
// first occurrence (a parser-differential vector).
func RejectDuplicateKeys(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		// Empty or malformed input: defer to the caller's json.Unmarshal so it
		// produces the canonical parse error rather than masking it here.
		return nil
	}
	return check(dec, tok, 0)
}

// check recursively validates the value whose opening token is tok. For objects
// it tracks the set of keys seen at that level; for arrays it recurses into each
// element; scalars are accepted as-is. depth bounds the recursion to prevent a
// stack-overflow panic on maliciously nested input.
func check(dec *json.Decoder, tok json.Token, depth int) error {
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar value
	}
	if depth >= MaxNestingDepth {
		return fmt.Errorf("JSON nesting exceeds maximum depth %d", MaxNestingDepth)
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
			}
			seen[key] = struct{}{}
			valTok, err := dec.Token()
			if err != nil {
				return err
			}
			if err := check(dec, valTok, depth+1); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return err
		}
	case '[':
		for dec.More() {
			valTok, err := dec.Token()
			if err != nil {
				return err
			}
			if err := check(dec, valTok, depth+1); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return err
		}
	}
	return nil
}

// RejectUnsafeNumbers rejects JSON numbers whose magnitude is outside the
// exact integer range shared by Go, Rust, and JavaScript. This is deliberately
// separate from RejectDuplicateKeys: generic Pipelock state legitimately uses
// the full uint64 range, while public evidence artifacts must decode to the
// same value in every supported verifier runtime.
//
// The decoder is allowed to consume multiple top-level values so the helper
// also covers JSONL evidence files. Malformed input is rejected here rather
// than deferred because callers invoke this only at verifier boundaries.
func RejectUnsafeNumbers(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		number, ok := tok.(json.Number)
		if !ok {
			continue
		}
		value, err := strconv.ParseFloat(string(number), 64)
		if err != nil {
			return fmt.Errorf("invalid JSON number %q: %w", number, err)
		}
		if math.Abs(value) > MaxExactJSONInteger {
			return fmt.Errorf("JSON number %q exceeds cross-language exact range", number)
		}
	}
}
