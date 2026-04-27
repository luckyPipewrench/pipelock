// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// ErrFloatNotAllowed indicates a float appeared in a signable preimage.
// Use decimal strings for non-integer numerics in signed schema fields.
var ErrFloatNotAllowed = errors.New("float not allowed in canonicalization; use decimal string")

// ErrDuplicateKey indicates a duplicate key was found during strict parse.
var ErrDuplicateKey = errors.New("duplicate key in JSON object")

// ErrTrailingTokens indicates that valid JSON was followed by additional non-whitespace tokens.
// Trailing tokens are a potential injection vector in signed artifact payloads.
var ErrTrailingTokens = errors.New("trailing tokens after JSON value")

// Canonicalize produces RFC 8785 JCS bytes for the given value.
// Strings are NFC-normalized. Floats are rejected. Map keys are sorted lexicographically by codepoint.
func Canonicalize(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := canonicalizeInto(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalizeInto(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		nfcStr := norm.NFC.String(x)
		b, err := json.Marshal(nfcStr)
		if err != nil {
			return fmt.Errorf("marshal string: %w", err)
		}
		buf.Write(b)
		return nil
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
		return nil
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
		return nil
	case float32, float64:
		return ErrFloatNotAllowed
	case json.Number:
		// Integer-only check.
		if _, err := x.Int64(); err != nil {
			return fmt.Errorf("non-integer json.Number %q: %w (use decimal string for fractional values)", x.String(), ErrFloatNotAllowed)
		}
		buf.WriteString(x.String())
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalizeInto(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		// Track both NFC-normalized form (for sort + output) and original form
		// (for value lookup). Without this, a map keyed with NFD strings would
		// silently miss the value lookup since x[nfc(k)] != x[k] when k is NFD.
		type mapKey struct{ nfc, orig string }
		pairs := make([]mapKey, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return fmt.Errorf("invalid UTF-8 in map key: %q", k)
			}
			pairs = append(pairs, mapKey{nfc: norm.NFC.String(k), orig: k})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].nfc < pairs[j].nfc })
		// Reject NFC-collisions: two distinct original keys that normalize to the
		// same NFC form would produce a JSON object with duplicate keys after
		// canonicalization. Treat as fatal.
		for i := 1; i < len(pairs); i++ {
			if pairs[i].nfc == pairs[i-1].nfc && pairs[i].orig != pairs[i-1].orig {
				return fmt.Errorf("%w: NFC collision between %q and %q", ErrDuplicateKey, pairs[i-1].orig, pairs[i].orig)
			}
		}
		buf.WriteByte('{')
		for i, p := range pairs {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(p.nfc)
			if err != nil {
				return fmt.Errorf("marshal map key %q: %w", p.nfc, err)
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := canonicalizeInto(buf, x[p.orig]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonicalize: unsupported type %T", v)
	}
}

// ParseJSONStrict decodes JSON with duplicate-key rejection and integer
// preservation via json.Decoder.UseNumber. Returns map[string]any / []any
// trees suitable for Canonicalize.
//
// ErrTrailingTokens is returned if any non-whitespace tokens follow the value.
// Trailing whitespace (spaces, newlines) is permitted by the JSON spec and is not an error.
func ParseJSONStrict(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	val, err := parseStrictValue(dec)
	if err != nil {
		return nil, err
	}
	// Trailing whitespace is not a token and dec.Token returns io.EOF for it.
	// Any other token, including a stray delimiter, is rejected.
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrTrailingTokens, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTrailingTokens, tok)
	}
	return val, nil
}

// parseStrictValue walks a json.Decoder rejecting duplicate keys.
func parseStrictValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return parseStrictFrom(dec, tok)
}

func parseStrictFrom(dec *json.Decoder, tok json.Token) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				ktok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := ktok.(string)
				if !ok {
					return nil, fmt.Errorf("expected string key, got %T", ktok)
				}
				if _, exists := obj[key]; exists {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
				}
				val, err := parseStrictValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseStrictValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %v", t)
		}
	case json.Number:
		return t, nil
	case string, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("unexpected token %T", tok)
	}
}
