// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import (
	"crypto/sha256"
	"regexp"
	"strings"
)

// validLengths are the BIP-39 mnemonic word counts (128-256 bits of entropy).
var validLengths = []int{12, 15, 18, 21, 24}

// separatorRE splits on whitespace and common seed phrase delimiters.
var separatorRE = regexp.MustCompile(`[-\s,|;:]+`)

// SeedMatch is the internal detection result. Package-internal only —
// converted to TextDLPMatch at the scanner integration boundary.
// Never includes the actual mnemonic words.
type SeedMatch struct {
	WordCount     int    // 12, 15, 18, 21, or 24
	ChecksumValid bool   // true if BIP-39 checksum passed
	Encoded       string // "", "base64", "hex", "url"
}

// Detect scans text for BIP-39 seed phrases. Returns all matches found.
// minWords must be one of {12, 15, 18, 21, 24}.
// If verifyChecksum is true, only phrases with valid BIP-39 checksums are returned.
func Detect(text string, minWords int, verifyChecksum bool) []SeedMatch {
	tokens := tokenize(text)
	if len(tokens) < minWords {
		return nil
	}

	var matches []SeedMatch
	for _, wantLen := range validLengths {
		if wantLen < minWords {
			continue
		}
		if wantLen > len(tokens) {
			break
		}
		for start := 0; start <= len(tokens)-wantLen; start++ {
			if !IsWord(tokens[start]) {
				continue // early bail: first word not BIP-39
			}
			if !allBIP39(tokens[start : start+wantLen]) {
				continue
			}
			indices := wordIndices(tokens[start : start+wantLen])
			checksumOK := validateChecksum(indices)
			if verifyChecksum && !checksumOK {
				continue
			}
			matches = append(matches, SeedMatch{
				WordCount:     wantLen,
				ChecksumValid: checksumOK,
			})
			// Skip past this match to avoid overlapping detections
			start += wantLen - 1
		}
	}
	return matches
}

// tokenize splits text into lowercase words using the separator pattern.
func tokenize(text string) []string {
	raw := separatorRE.Split(text, -1)
	tokens := make([]string, 0, len(raw))
	for _, t := range raw {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			tokens = append(tokens, t)
		}
	}
	return tokens
}

// allBIP39 returns true if every word in the slice is a BIP-39 word.
func allBIP39(words []string) bool {
	for _, w := range words {
		if !IsWord(w) {
			return false
		}
	}
	return true
}

// wordIndices converts words to their BIP-39 indices (0-2047).
func wordIndices(words []string) []int {
	indices := make([]int, len(words))
	for i, w := range words {
		indices[i] = IndexOf(w)
	}
	return indices
}

// validateChecksum implements BIP-39 checksum validation.
// Each word index is 11 bits. The concatenated bits split into:
//   - entropy: first ENT bits (where ENT = wordCount * 11 - wordCount * 11 / 33)
//   - checksum: first ENT/32 bits of SHA-256(entropy)
func validateChecksum(indices []int) bool {
	totalBits := len(indices) * 11 // 11 bits per word
	checksumBits := totalBits / 33 // ENT/32, and totalBits = ENT + ENT/32 = 33*ENT/32
	entropyBits := totalBits - checksumBits

	// Pack word indices into a byte slice as a bitstream.
	data := make([]byte, (totalBits+7)/8)
	for i, idx := range indices {
		// Each index is 11 bits, big-endian into the bitstream.
		for bit := 10; bit >= 0; bit-- {
			bitPos := i*11 + (10 - bit)
			if idx&(1<<bit) != 0 {
				data[bitPos/8] |= 1 << (7 - bitPos%8)
			}
		}
	}

	// Extract entropy bytes (first entropyBits).
	entropyBytes := data[:entropyBits/8]

	// Compute SHA-256 of entropy.
	hash := sha256.Sum256(entropyBytes)

	// Compare leading checksumBits of hash against the checksum portion of data.
	for i := 0; i < checksumBits; i++ {
		dataBit := (data[(entropyBits+i)/8] >> (7 - (entropyBits+i)%8)) & 1
		hashBit := (hash[i/8] >> (7 - i%8)) & 1
		if dataBit != hashBit {
			return false
		}
	}
	return true
}
