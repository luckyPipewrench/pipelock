// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package jcs implements RFC 8785 JSON Canonicalization Scheme (JCS) exactly,
// using only the standard library.
//
// It exists as a standalone, dependency-free implementation because it is used
// to reconstruct the byte-exact preimage that a THIRD PARTY signed when it
// produced an A2A Agent Card JWS signature. A canonicalizer that diverges by a
// single byte would false-reject legitimately signed cards, so this package
// deliberately does NOT reuse internal/contract's canonicalizer, which:
//
//   - NFC-normalizes strings (RFC 8785 requires string data to be preserved),
//   - rejects non-integer numbers (JCS cards may carry decimals/exponents), and
//   - sorts object members by Go code-point order rather than UTF-16 code units.
//
// The three RFC 8785 rules that bite are all handled here: UTF-16 code-unit key
// ordering (§3.2.3), minimal string escaping with no normalization (§3.2.2.2),
// and ES6 number serialization (§3.2.2.3).
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrDuplicateKey indicates a duplicate member name in a JSON object. A signed
// card with duplicate keys is ambiguous, so canonicalization fails closed.
var ErrDuplicateKey = errors.New("duplicate key in JSON object")

// ErrTrailingTokens indicates non-whitespace content followed the JSON value.
// Trailing tokens are an injection/ambiguity vector in signed payloads.
var ErrTrailingTokens = errors.New("trailing tokens after JSON value")

// ErrInvalidNumber indicates a number that cannot be represented as a finite
// IEEE-754 double (NaN/Infinity), which JSON/JCS does not permit.
var ErrInvalidNumber = errors.New("invalid JSON number")

// ErrInvalidUnicode indicates JSON string data that cannot be represented as
// valid Unicode. RFC 8785 requires this to fail instead of being repaired.
var ErrInvalidUnicode = errors.New("invalid Unicode in JSON string data")

// ErrMaxDepth indicates JSON nesting exceeded maxParseDepth. Bounding recursion
// keeps a deeply nested attacker payload from overflowing the stack (callers
// feed untrusted input; a panic would violate the never-panic-on-input rule).
var ErrMaxDepth = errors.New("JSON nesting too deep")

// maxParseDepth bounds object/array recursion depth. Far deeper than any real
// Agent Card or JWS header.
const maxParseDepth = 512

// Canonicalize parses raw JSON strictly and returns its RFC 8785 canonical form.
func Canonicalize(raw []byte) ([]byte, error) {
	v, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return Marshal(v)
}

// Parse strictly decodes JSON into a tree of map[string]any / []any / string /
// bool / nil / json.Number. It rejects duplicate object keys and trailing
// tokens. Numbers are preserved as json.Number so Marshal can apply the ES6
// serialization rule rather than Go's default float formatting.
func Parse(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: input is not valid UTF-8", ErrInvalidUnicode)
	}
	if err := rejectInvalidEscapedSurrogates(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	// Reject anything other than trailing whitespace. dec.Token returns io.EOF
	// once only whitespace remains.
	if tok, terr := dec.Token(); !errors.Is(terr, io.EOF) {
		if terr != nil {
			return nil, fmt.Errorf("%w: %w", ErrTrailingTokens, terr)
		}
		return nil, fmt.Errorf("%w: %v", ErrTrailingTokens, tok)
	}
	return v, nil
}

func rejectInvalidEscapedSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(raw) {
				return nil // JSON decoder reports the malformed escape.
			}
			if raw[i+1] != 'u' {
				i++
				continue
			}
			r, ok := parseHex4(raw[i+2:])
			if !ok {
				return nil // JSON decoder reports the malformed escape.
			}
			i += 5
			if r >= 0xD800 && r <= 0xDBFF {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return fmt.Errorf("%w: unpaired high surrogate", ErrInvalidUnicode)
				}
				low, ok := parseHex4(raw[i+3:])
				if !ok {
					return nil // JSON decoder reports the malformed escape.
				}
				if low < 0xDC00 || low > 0xDFFF {
					return fmt.Errorf("%w: high surrogate not followed by low surrogate", ErrInvalidUnicode)
				}
				i += 6
				continue
			}
			if r >= 0xDC00 && r <= 0xDFFF {
				return fmt.Errorf("%w: unpaired low surrogate", ErrInvalidUnicode)
			}
		}
	}
	return nil
}

func parseHex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var v rune
	for i := 0; i < 4; i++ {
		c := b[i]
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + rune(c-'0')
		case c >= 'a' && c <= 'f':
			v = v*16 + rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v*16 + rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxParseDepth {
		return nil, fmt.Errorf("%w: exceeds %d", ErrMaxDepth, maxParseDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return parseFrom(dec, tok, depth)
}

func parseFrom(dec *json.Decoder, tok json.Token, depth int) (any, error) {
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
					return nil, fmt.Errorf("expected string object key, got %T", ktok)
				}
				if _, exists := obj[key]; exists {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
				}
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, err
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %v", t)
		}
	case json.Number, string, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("unexpected token %T", tok)
	}
}

// Marshal serializes a parsed JSON tree to its RFC 8785 canonical form.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := marshalInto(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func marshalInto(buf *bytes.Buffer, v any) error {
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
		if !utf8.ValidString(x) {
			return fmt.Errorf("%w: invalid UTF-8 string", ErrInvalidUnicode)
		}
		writeJCSString(buf, x)
		return nil
	case json.Number:
		f, err := strconv.ParseFloat(x.String(), 64)
		if err != nil {
			return fmt.Errorf("%w: %q: %w", ErrInvalidNumber, x.String(), err)
		}
		s, err := formatNumber(f)
		if err != nil {
			return err
		}
		buf.WriteString(s)
		return nil
	case float64:
		s, err := formatNumber(x)
		if err != nil {
			return err
		}
		buf.WriteString(s)
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := marshalInto(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return fmt.Errorf("%w: invalid UTF-8 object key", ErrInvalidUnicode)
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, k)
			buf.WriteByte(':')
			if err := marshalInto(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
}

// lessUTF16 reports whether a sorts before b by UTF-16 code-unit sequence, as
// required by RFC 8785 §3.2.3. This differs from Go's default string comparison
// for code points above U+FFFF: an astral character is a high surrogate
// (0xD800-0xDBFF) in UTF-16, so it sorts before BMP characters U+E000-U+FFFF,
// the opposite of code-point order.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeJCSString writes s as a canonical JSON string per RFC 8785 §3.2.2.2.
// Only the mandatory escapes are emitted; all other characters (including every
// non-ASCII code point) are written as literal UTF-8 with no normalization.
// Notably this does NOT escape U+2028/U+2029, which Go's encoding/json escapes
// even with HTML escaping disabled — a real divergence that would break parity.
func writeJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				const hexdigits = "0123456789abcdef"
				buf.WriteByte(hexdigits[(r>>4)&0xf])
				buf.WriteByte(hexdigits[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// formatNumber serializes a float64 per RFC 8785 §3.2.2.3 (the ECMAScript
// Number-to-string algorithm). The implementation follows the RFC 8785
// reference algorithm from cyberphone/json-canonicalization (Apache-2.0):
// select fixed-point notation for magnitudes in [1e-6, 1e21) and exponential
// otherwise, take Go's shortest round-trippable representation, then strip the
// single padding zero Go adds to two-digit exponents (Go emits "1e+09" where
// ES6 wants "1e+9").
func formatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: non-finite", ErrInvalidNumber)
	}
	if f == 0 { // also normalizes -0 to "0"
		return "0", nil
	}

	sign := ""
	if f < 0 {
		f = -f
		sign = "-"
	}

	format := byte('e')
	if f < 1e21 && f >= 1e-6 {
		format = 'f'
	}
	s := strconv.FormatFloat(f, format, -1, 64)

	if e := strings.IndexByte(s, 'e'); e > 0 {
		// s[e+1] is the exponent sign ('+'/'-'); s[e+2] is the first digit.
		// Go pads to a minimum of two exponent digits, so a leading '0' here
		// is padding that ES6 omits.
		if e+2 < len(s) && s[e+2] == '0' {
			s = s[:e+2] + s[e+3:]
		}
	}
	return sign + s, nil
}
