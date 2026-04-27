// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Domain separators for binary Merkle hashing. They prevent second-preimage
// attacks where an internal node hash could be mistaken for a leaf hash.
const (
	merkleLeafTag     byte = 0x00
	merkleInternalTag byte = 0x01
)

// MerkleRoot computes a binary SHA-256 Merkle root over the canonical bytes
// of each Rule. Order-sensitive — caller is responsible for emitting rules
// in canonical order.
//
// Empty input returns sha256(0x00) hex with the "sha256:" prefix as the
// well-known empty-tree convention (single byte: the leaf domain separator).
func MerkleRoot(rules []Rule) (string, error) {
	if len(rules) == 0 {
		s := sha256.Sum256([]byte{merkleLeafTag})
		return "sha256:" + hex.EncodeToString(s[:]), nil
	}

	level := make([][]byte, 0, len(rules))
	for i, r := range rules {
		canon, err := r.SignablePreimage()
		if err != nil {
			return "", fmt.Errorf("merkle leaf %d: %w", i, err)
		}
		// Streaming hash avoids the make([]byte, 0, 1+len(canon)) allocation
		// pattern that CodeQL flags as go/allocation-size-overflow.
		h := sha256.New()
		h.Write([]byte{merkleLeafTag})
		h.Write(canon)
		level = append(level, h.Sum(nil))
	}

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			var right []byte
			if i+1 < len(level) {
				right = level[i+1]
			} else {
				right = left // duplicate odd leaf at this level
			}
			h := sha256.New()
			h.Write([]byte{merkleInternalTag})
			h.Write(left)
			h.Write(right)
			next = append(next, h.Sum(nil))
		}
		level = next
	}

	return "sha256:" + hex.EncodeToString(level[0]), nil
}
