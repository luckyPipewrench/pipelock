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

// MaxDecoderNestingDepth is encoding/json's container-depth ceiling. Older
// toolchains do not enforce it in Decoder.Token, so the shared walker must.
const MaxDecoderNestingDepth = 10000

// MaxExactJSONInteger is the largest integer every supported verifier runtime
// can represent exactly. JavaScript numbers lose integer precision above this
// boundary, while Go and Rust retain it; accepting larger JSON numbers would
// let identical bytes produce different packet or receipt semantics.
const MaxExactJSONInteger = 1<<53 - 1

// RejectDuplicateKeys reports an error if data contains a duplicate object key
// at any nesting depth, comparing decoded names exactly. It streams tokens
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
	return check(dec, tok, 0, MaxNestingDepth, false)
}

// ErrTrailingTokens indicates content after the first JSON value.
var ErrTrailingTokens = errors.New("trailing tokens after JSON value")

// ValidateKeys validates one JSON document, rejecting duplicate names under
// exact decoded spelling, including escaped spellings. maxDepth preserves each
// transport's existing nesting bound; schema names and values are not rewritten.
func ValidateKeys(data []byte, maxDepth int) error {
	return validateKeys(data, maxDepth, false)
}

// ValidateFoldedKeys rejects case-insensitive collisions in a schema object.
// Use ValidateKeys for free-form application maps. Typed decoders should use
// RejectStructAliases so only schema-bound names are folded.
func ValidateFoldedKeys(data []byte, maxDepth int) error {
	return validateKeys(data, maxDepth, true)
}

func validateKeys(data []byte, maxDepth int, folded bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if err := check(dec, tok, 0, maxDepth, folded); err != nil {
		return err
	}
	// Preserve duplicate diagnostics even when another string contains invalid
	// UTF-8. Callers must still reject every other validation error.
	if !utf8.Valid(data) {
		return errors.New("JSON is not valid UTF-8")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTrailingTokens, err)
		}
		return ErrTrailingTokens
	}
	return nil
}

// FoldKey uses the pinned Unicode simple-fold table shared by every verifier.
// Native lowercase/full casefold and toolchain-dependent tables differ.
func FoldKey(key string) string {
	return strings.Map(func(r rune) rune {
		if folded, ok := keyFoldTable[r]; ok {
			return folded
		}
		return r
	}, key)
}

var keyFoldTable = func() map[rune]rune {
	result := make(map[rune]rune)
	for _, group := range strings.Fields(KeyFoldGroups) {
		chars := []rune(group)
		for _, char := range chars {
			result[char] = chars[0]
		}
	}
	return result
}()

// HasKeyAlias reports a noncanonical spelling of a configured field. It also
// rejects a lone alias, which exact-key map lookup would otherwise call absent.
func HasKeyAlias[V any](object map[string]V, field string) bool {
	for key := range object {
		if key != field && FoldKey(key) == FoldKey(field) {
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
			if key != allowed && FoldKey(key) == FoldKey(allowed) {
				return fmt.Errorf("%w: %q aliases %q (case-insensitive)", ErrCaseFoldedKey, key, allowed)
			}
		}
	}
	return nil
}

// check recursively validates the value whose opening token is tok. For objects
// it tracks the set of keys seen at that level; for arrays it recurses into each
// element; scalars are accepted as-is. depth bounds the recursion to prevent a
// stack-overflow panic on maliciously nested input.
func check(dec *json.Decoder, tok json.Token, depth, maxDepth int, folded bool) error {
	if depth > maxDepth {
		return fmt.Errorf("JSON nesting exceeds maximum depth %d (depth limit)", maxDepth)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar value
	}
	// depth is zero-based for an opening container. An empty container at the
	// ceiling still adds one level even though it has no value to recurse into.
	if depth >= MaxDecoderNestingDepth {
		return fmt.Errorf("JSON nesting exceeds maximum depth %d (depth limit)", MaxDecoderNestingDepth)
	}
	switch delim {
	case '{':
		seen := make(map[string]string)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			identity := key
			if folded {
				identity = FoldKey(key)
			}
			if previous, dup := seen[identity]; dup {
				if previous != key {
					return fmt.Errorf("%w: %q and %q collide (case-insensitive)", ErrDuplicateKey, previous, key)
				}
				return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
			}
			seen[identity] = key
			valTok, err := dec.Token()
			if err != nil {
				return err
			}
			if err := check(dec, valTok, depth+1, maxDepth, folded); err != nil {
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
			if err := check(dec, valTok, depth+1, maxDepth, folded); err != nil {
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
		if first, exists := seen[key]; exists {
			if duplicates == nil {
				duplicates = make(map[string]struct{})
			}
			duplicates[first] = struct{}{}
			duplicates[key] = struct{}{}
		}
		seen[key] = key
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil
		}
	}
	return duplicates
}
