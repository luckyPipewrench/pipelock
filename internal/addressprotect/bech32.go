// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"errors"
	"strings"
)

// Bech32 encoding versions. The checksum polynomial constant differs between
// BIP-173 (bech32, SegWit v0) and BIP-350 (bech32m, SegWit v1+ / Taproot).
const (
	bech32Version  = 1 // BIP-173
	bech32mVersion = 2 // BIP-350
)

// bech32Charset is the 32-character alphabet used by bech32 encoding.
// It excludes 1, b, i, o to avoid visual ambiguity.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var (
	errBech32InvalidLength = errors.New("bech32: input too short")
	errBech32NoSeparator   = errors.New("bech32: no separator '1' found")
	errBech32MixedCase     = errors.New("bech32: mixed case not allowed")
	errBech32InvalidChar   = errors.New("bech32: invalid data character")
	errBech32Checksum      = errors.New("bech32: invalid checksum")
	errBech32EmptyHRP      = errors.New("bech32: empty human-readable part")
	errBech32DataTooShort  = errors.New("bech32: data part too short for checksum")
)

// bech32CharIndex maps each ASCII byte to its bech32 alphabet index, or -1.
var bech32CharIndex [128]int8

func init() {
	for i := range bech32CharIndex {
		bech32CharIndex[i] = -1
	}
	for i, c := range bech32Charset {
		bech32CharIndex[c] = int8(i) //nolint:gosec // charset has 32 entries, always fits int8
	}
}

// bech32Polymod computes the BCH polynomial checksum used by bech32.
// The generator polynomial coefficients are defined in BIP-173.
func bech32Polymod(values []int) int {
	gen := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := range 5 {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the human-readable part for checksum computation.
// Each character contributes its high 3 bits, then a zero separator, then its low 5 bits.
func bech32HRPExpand(hrp string) []int {
	result := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		result = append(result, int(c>>5))
	}
	result = append(result, 0)
	for _, c := range hrp {
		result = append(result, int(c&31))
	}
	return result
}

// bech32Decode decodes a bech32 or bech32m encoded string.
// Returns the human-readable part, data (5-bit values excluding checksum),
// encoding version (bech32Version or bech32mVersion), and any error.
func bech32Decode(s string) (string, []byte, int, error) {
	// BIP-173: minimum length is 8 (1-char HRP + separator + 6-char checksum).
	if len(s) < 8 {
		return "", nil, 0, errBech32InvalidLength
	}

	// Reject mixed case — bech32 is case-insensitive but must be uniform.
	lower := strings.ToLower(s)
	upper := strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, 0, errBech32MixedCase
	}
	s = lower

	// The last '1' separates HRP from data.
	sepIdx := strings.LastIndex(s, "1")
	if sepIdx < 1 {
		return "", nil, 0, errBech32NoSeparator
	}

	hrp := s[:sepIdx]
	if len(hrp) == 0 {
		return "", nil, 0, errBech32EmptyHRP
	}

	dataStr := s[sepIdx+1:]
	// Data must contain at least the 6-character checksum.
	if len(dataStr) < 6 {
		return "", nil, 0, errBech32DataTooShort
	}

	// Convert data characters to 5-bit values.
	data := make([]byte, len(dataStr))
	for i, c := range dataStr {
		if c > 127 {
			return "", nil, 0, errBech32InvalidChar
		}
		idx := bech32CharIndex[c]
		if idx < 0 {
			return "", nil, 0, errBech32InvalidChar
		}
		data[i] = byte(idx)
	}

	// Verify checksum: polymod of (hrp_expand || data) must equal 1 (bech32)
	// or 0x2bc830a3 (bech32m).
	hrpExp := bech32HRPExpand(hrp)
	values := make([]int, len(hrpExp)+len(data))
	copy(values, hrpExp)
	for i, v := range data {
		values[len(hrpExp)+i] = int(v)
	}

	polymod := bech32Polymod(values)

	var ver int
	switch polymod {
	case 1:
		ver = bech32Version
	case 0x2bc830a3:
		ver = bech32mVersion
	default:
		return "", nil, 0, errBech32Checksum
	}

	// Return data without the 6-byte checksum.
	return hrp, data[:len(data)-6], ver, nil
}
