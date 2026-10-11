// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package jsonscan provides shared JSON key validation and strict schema
// decoding for transport and signed-artifact ingestion. It is a leaf package
// so callers with different dependency graphs use the same checks.
package jsonscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrDuplicateKey is returned when input contains a duplicate object key.
var ErrDuplicateKey = fmt.Errorf("duplicate object key")

// ErrCaseFoldedKey is returned when an object key matches a schema key only
// after case folding.
var ErrCaseFoldedKey = errors.New("case-folded object key alias")

// MaxNestingDepth bounds the scanner's recursion. Before Go 1.27,
// json.Decoder.Token() (unlike json.Unmarshal) enforced no nesting limit, and
// Go 1.27 stops it only at 10000 levels, so without this bound a
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
// at any nesting depth, including case-folded collisions. It streams tokens
// with a json.Decoder so it sees every key occurrence, not the last-wins map
// encoding/json would build. encoding/json
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
	return check(dec, tok, 0, MaxNestingDepth)
}

// ErrTrailingTokens indicates content after the first JSON value.
var ErrTrailingTokens = errors.New("trailing tokens after JSON value")

// ValidateKeys validates one JSON document, rejecting duplicate names under
// Unicode simple folding, including escaped spellings. maxDepth preserves each
// transport's existing nesting bound; schema names and values are not rewritten.
func ValidateKeys(data []byte, maxDepth int) error {
	if !utf8.Valid(data) {
		return errors.New("JSON is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if err := check(dec, tok, 0, maxDepth); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTrailingTokens, err)
		}
		return ErrTrailingTokens
	}
	return nil
}

// FoldKey returns a key for the equivalence classes used by strings.EqualFold
// and encoding/json's struct-field lookup. Lowercasing alone misses the Kelvin
// sign and long s. Folding each rune to the smallest rune in its SimpleFold
// cycle covers ASCII, Unicode and decoded JSON escapes without normalization.
func FoldKey(key string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < smallest {
				smallest = next
			}
		}
		return smallest
	}, key)
}

// HasKeyAlias reports a noncanonical spelling of a configured field. It also
// rejects a lone alias, which exact-key map lookup would otherwise call absent.
func HasKeyAlias[V any](object map[string]V, field string) bool {
	for key := range object {
		if key != field && strings.EqualFold(key, field) {
			return true
		}
	}
	return false
}

// RejectCaseFoldedAliases rejects top-level object keys that match one of the
// allowed schema keys only after case folding. encoding/json otherwise accepts
// those aliases for struct fields, so inputs such as "token" plus "Token" can
// overwrite the same destination field even after exact duplicate keys have
// been rejected. Callers should run RejectDuplicateKeys first.
func RejectCaseFoldedAliases(data []byte, allowedKeys ...string) error {
	if len(allowedKeys) == 0 {
		return errors.New("allowed JSON schema keys are required")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	if object == nil {
		return errors.New("JSON value must be an object")
	}
	for key := range object {
		for _, allowed := range allowedKeys {
			if key != allowed && strings.EqualFold(key, allowed) {
				return fmt.Errorf("%w: %q aliases %q", ErrCaseFoldedKey, key, allowed)
			}
		}
	}
	return nil
}

// check recursively validates the value whose opening token is tok. For objects
// it tracks the set of keys seen at that level; for arrays it recurses into each
// element; scalars are accepted as-is. depth bounds the recursion to prevent a
// stack-overflow panic on maliciously nested input.
func check(dec *json.Decoder, tok json.Token, depth, maxDepth int) error {
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar value
	}
	if depth >= maxDepth {
		return fmt.Errorf("JSON nesting exceeds maximum depth %d", maxDepth)
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
			folded := FoldKey(key)
			if _, dup := seen[folded]; dup {
				return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
			}
			seen[folded] = struct{}{}
			valTok, err := dec.Token()
			if err != nil {
				return err
			}
			if err := check(dec, valTok, depth+1, maxDepth); err != nil {
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
			if err := check(dec, valTok, depth+1, maxDepth); err != nil {
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

// TopLevelDuplicateKeys inventories ambiguous keys in an already parsed object.
// Values are skipped intact; duplicates in unrelated nested application data do
// not make an operation discriminator ambiguous.
func TopLevelDuplicateKeys(data []byte) map[string]struct{} {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	seen := make(map[string]string)
	var duplicates map[string]struct{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return nil
		}
		folded := FoldKey(key)
		if first, exists := seen[folded]; exists {
			if duplicates == nil {
				duplicates = make(map[string]struct{})
			}
			duplicates[first] = struct{}{}
			duplicates[key] = struct{}{}
		}
		seen[folded] = key
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil
		}
	}
	return duplicates
}
