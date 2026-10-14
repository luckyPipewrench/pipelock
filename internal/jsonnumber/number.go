// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package jsonnumber provides bounded, exact RFC 8259 number parsing shared by
// configuration and security scanners.
package jsonnumber

import (
	"encoding/json"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// These bounds preserve the existing MCP tool-policy parsing contract.
const (
	maxNumberChars  = 4096
	maxNumberExpAbs = 10000
)

var numberPattern = regexp.MustCompile(`^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$`)

// Parse returns an exact rational, bounding the spelling and exponent before
// constructing big numbers. Grammar: https://www.rfc-editor.org/rfc/rfc8259#section-6.
func Parse(n json.Number) (*big.Rat, bool) {
	s := n.String()
	exp, ok := boundedComponents(s)
	if !ok {
		return nil, false
	}
	base, _, _ := strings.Cut(strings.ToLower(s), "e")
	negative := strings.HasPrefix(base, "-")
	base = strings.TrimPrefix(base, "-")
	intPart, fracPart, hasFrac := strings.Cut(base, ".")
	digits, scale := intPart, 0
	if hasFrac {
		digits += fracPart
		scale = len(fracPart)
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		digits = "0"
	}
	num := new(big.Int)
	if _, ok := num.SetString(digits, 10); !ok {
		return nil, false
	}
	if negative {
		num.Neg(num)
	}
	den := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
	if exp >= 0 {
		num.Mul(num, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exp)), nil))
	} else {
		den.Mul(den, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-exp)), nil))
	}
	return new(big.Rat).SetFrac(num, den), true
}

// boundedComponents preserves the pre-existing tool-policy grammar and resource
// limits before either exact parsing or construction of a card-only view.
func boundedComponents(s string) (int, bool) {
	if len(s) == 0 || len(s) > maxNumberChars || !numberPattern.MatchString(s) {
		return 0, false
	}
	_, exponent, hasExp := strings.Cut(strings.ToLower(s), "e")
	if !hasExp {
		return 0, true
	}
	exp, err := strconv.Atoi(exponent)
	return exp, err == nil && exp <= maxNumberExpAbs && exp >= -maxNumberExpAbs
}
