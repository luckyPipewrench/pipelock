// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// The I-JSON safe-integer range. JSON numbers are interoperable across
// languages only inside [-(2^53-1), 2^53-1]; outside it, a JavaScript or
// other-language verifier silently rounds to the nearest float64, which changes
// the canonical bytes and breaks the signature. AARP therefore allows raw JSON
// numbers ONLY inside this range and requires every identity, digest, counter,
// timestamp, or amount field to be a typed string instead.
const (
	maxSafeInteger = (1 << 53) - 1
	minSafeInteger = -((1 << 53) - 1)
)

// Number-safety failure classes. Callers map these to their result contracts;
// compare with errors.Is.
var (
	// ErrUnsafeNumber means a raw JSON number is a float, uses exponent form,
	// is negative zero, or falls outside the I-JSON safe-integer range.
	ErrUnsafeNumber = errors.New("aarp: unsafe JSON number; identity/digest/amount/timestamp fields must be typed strings")

	// ErrBadGrammar means a typed-string field does not match its declared
	// grammar (hex digest, decimal amount, unsigned counter, RFC3339Nano time).
	ErrBadGrammar = errors.New("aarp: typed-string field violates its grammar")
)

// EnforceSafeNumbers walks a parsed JSON tree (as produced by
// contract.ParseJSONStrict, which decodes numbers as json.Number) and rejects
// any number that is not a safe integer. It is the structural guard that makes
// an AARP envelope canonicalize identically across languages.
//
// A safe number is an integer with no fractional part, no exponent, not
// negative zero, and within [minSafeInteger, maxSafeInteger]. Everything else
// belongs in a typed string and is rejected here so it can never reach the
// canonical signing input.
func EnforceSafeNumbers(tree any) error {
	return enforceSafeNumbers(tree, "$")
}

func enforceSafeNumbers(v any, path string) error {
	switch x := v.(type) {
	case json.Number:
		return checkSafeNumber(string(x), path)
	case map[string]any:
		for k, val := range x {
			if err := enforceSafeNumbers(val, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for i, val := range x {
			if err := enforceSafeNumbers(val, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	// Strings, bools, and nil carry no numeric interoperability hazard.
	return nil
}

// checkSafeNumber validates a single raw JSON number literal. The literal is the
// exact source text json.Number preserves, so float/exponent/negative-zero
// detection is done on the text before any lossy conversion.
func checkSafeNumber(lit, path string) error {
	if lit == "" {
		return fmt.Errorf("%w: empty number at %s", ErrUnsafeNumber, path)
	}
	// Float and exponent forms are forbidden outright: their value-vs-text
	// relationship is what diverges across language parsers.
	if strings.ContainsAny(lit, ".eE") {
		return fmt.Errorf("%w: float or exponent form %q at %s", ErrUnsafeNumber, lit, path)
	}
	// Negative zero is a distinct text with an ambiguous canonical form.
	if lit == "-0" {
		return fmt.Errorf("%w: negative zero at %s", ErrUnsafeNumber, path)
	}
	n, ok := new(big.Int).SetString(lit, 10)
	if !ok {
		return fmt.Errorf("%w: non-integer literal %q at %s", ErrUnsafeNumber, lit, path)
	}
	if n.Cmp(big.NewInt(maxSafeInteger)) > 0 || n.Cmp(big.NewInt(minSafeInteger)) < 0 {
		return fmt.Errorf("%w: %q outside I-JSON safe range at %s", ErrUnsafeNumber, lit, path)
	}
	return nil
}

// hexDigestLen is the lowercase-hex length of a SHA-256 digest.
const hexDigestLen = 64

// ValidateHex256 checks a lowercase-hex SHA-256 digest grammar: exactly 64
// characters drawn from [0-9a-f]. Uppercase is rejected so the canonical bytes
// are stable (a digest is identity, not free text).
func ValidateHex256(s string) error {
	if len(s) != hexDigestLen {
		return fmt.Errorf("%w: digest length %d, want %d", ErrBadGrammar, len(s), hexDigestLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: digest contains non-lowercase-hex byte %q", ErrBadGrammar, c)
		}
	}
	return nil
}

// ValidateUint64String checks an unsigned decimal counter grammar: one or more
// digits, no sign, no leading zeros (except the single literal "0"), within
// uint64. Sequence numbers, nanosecond timestamps, and large counters use this
// because their values routinely exceed the I-JSON safe range.
func ValidateUint64String(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty unsigned counter", ErrBadGrammar)
	}
	if s == "0" {
		return nil
	}
	if s[0] == '0' {
		return fmt.Errorf("%w: leading zero in counter %q", ErrBadGrammar, s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return fmt.Errorf("%w: non-digit in counter %q", ErrBadGrammar, s)
		}
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return fmt.Errorf("%w: unparseable counter %q", ErrBadGrammar, s)
	}
	// Range-check against uint64 without overflow.
	maxU64 := new(big.Int).SetUint64(^uint64(0))
	if n.Cmp(maxU64) > 0 {
		return fmt.Errorf("%w: counter %q exceeds uint64", ErrBadGrammar, s)
	}
	return nil
}

// ValidateDecimalAmount checks a fixed-point decimal amount grammar: an optional
// leading minus, an integer part with no leading zeros (except a single "0"), an
// optional fractional part with at least one digit and no trailing zeros, no
// exponent, and no negative zero. Amounts are typed strings so currency and
// quantity values never ride through a float.
func ValidateDecimalAmount(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty amount", ErrBadGrammar)
	}
	neg := false
	body := s
	if body[0] == '-' {
		neg = true
		body = body[1:]
	}
	if body == "" {
		return fmt.Errorf("%w: amount has sign but no digits", ErrBadGrammar)
	}
	intPart, fracPart, hasFrac := strings.Cut(body, ".")
	if intPart == "" {
		return fmt.Errorf("%w: amount missing integer part in %q", ErrBadGrammar, s)
	}
	if len(intPart) > 1 && intPart[0] == '0' {
		return fmt.Errorf("%w: leading zero in amount %q", ErrBadGrammar, s)
	}
	if !allDigits(intPart) {
		return fmt.Errorf("%w: non-digit in amount integer part %q", ErrBadGrammar, s)
	}
	allZeroInt := strings.Trim(intPart, "0") == ""
	allZeroFrac := true
	if hasFrac {
		if fracPart == "" {
			return fmt.Errorf("%w: amount has decimal point but no fraction in %q", ErrBadGrammar, s)
		}
		if !allDigits(fracPart) {
			return fmt.Errorf("%w: non-digit in amount fraction %q", ErrBadGrammar, s)
		}
		if fracPart[len(fracPart)-1] == '0' {
			return fmt.Errorf("%w: trailing zero in amount fraction %q", ErrBadGrammar, s)
		}
		allZeroFrac = strings.Trim(fracPart, "0") == ""
	}
	if neg && allZeroInt && allZeroFrac {
		return fmt.Errorf("%w: negative zero amount %q", ErrBadGrammar, s)
	}
	return nil
}

// ValidateTimestamp checks an RFC 3339 timestamp with nanosecond precision and a
// mandatory zone. Times are typed strings (never epoch numbers) so a verifier in
// any language parses the same instant from the same bytes.
func ValidateTimestamp(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty timestamp", ErrBadGrammar)
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
		return fmt.Errorf("%w: timestamp %q is not RFC3339Nano: %w", ErrBadGrammar, s, err)
	}
	return nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}
