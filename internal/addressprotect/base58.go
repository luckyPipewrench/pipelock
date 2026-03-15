// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

// base58Alphabet is the Bitcoin base58 alphabet (excludes 0, O, I, l to avoid
// visual ambiguity — the same property that makes it popular for addresses).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	errInvalidBase58Char = errors.New("invalid base58 character")
	errBase58Checksum    = errors.New("base58check: invalid checksum")
	errBase58TooShort    = errors.New("base58check: payload too short for version + checksum")
)

// base58CharIndex maps each byte to its base58 alphabet index, or -1 if invalid.
var base58CharIndex [256]int8

func init() {
	for i := range base58CharIndex {
		base58CharIndex[i] = -1
	}
	for i, c := range base58Alphabet {
		base58CharIndex[c] = int8(i) //nolint:gosec // alphabet has 58 entries, always fits int8
	}
}

// base58Decode decodes a base58-encoded string to bytes.
// Leading '1' characters decode to leading zero bytes (base58 convention).
func base58Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}

	// Count leading '1's → leading zero bytes in output.
	var leadingZeros int
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingZeros++
	}

	// Convert base58 digits to a big integer.
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range s {
		if c > 255 {
			return nil, errInvalidBase58Char
		}
		idx := base58CharIndex[byte(c)]
		if idx < 0 {
			return nil, errInvalidBase58Char
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}

	// Prepend the leading zero bytes that the big integer dropped.
	decoded := n.Bytes()
	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)
	return result, nil
}

// base58CheckDecode decodes a Base58Check-encoded string and verifies
// the trailing 4-byte SHA-256d checksum.
// Returns the payload (without version or checksum) and the version byte.
// Used by BTC P2PKH (version 0x00) and P2SH (version 0x05).
func base58CheckDecode(s string) (payload []byte, version byte, err error) {
	decoded, err := base58Decode(s)
	if err != nil {
		return nil, 0, err
	}

	// Layout: [version (1 byte)] [payload (N bytes)] [checksum (4 bytes)]
	// Minimum: 1 + 0 + 4 = 5 bytes (though real addresses have 20-byte payloads).
	const checksumLen = 4
	if len(decoded) < 1+checksumLen {
		return nil, 0, errBase58TooShort
	}

	body := decoded[:len(decoded)-checksumLen]
	checksum := decoded[len(decoded)-checksumLen:]

	// SHA256(SHA256(body))[0:4] must equal checksum.
	h1 := sha256.Sum256(body)
	h2 := sha256.Sum256(h1[:])
	if h2[0] != checksum[0] || h2[1] != checksum[1] ||
		h2[2] != checksum[2] || h2[3] != checksum[3] {
		return nil, 0, errBase58Checksum
	}

	return body[1:], body[0], nil
}
