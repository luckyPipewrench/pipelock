// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import (
	"crypto/sha256"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// validLengths are the BIP-39 mnemonic word counts (128-256 bits of entropy).
var validLengths = []int{12, 15, 18, 21, 24}

// SeedMatch is the internal detection result. Package-internal only -
// converted to TextDLPMatch at the scanner integration boundary.
// Never includes the actual mnemonic words.
type SeedMatch struct {
	WordCount     int    // 12, 15, 18, 21, or 24
	ChecksumValid bool   // true if BIP-39 checksum passed
	Encoded       string // "", "base64", "hex", "url"
}

// SeedSpan is a seed phrase match with byte offsets into the original text.
type SeedSpan struct {
	SeedMatch
	Start int
	End   int
}

type tokenSpan struct {
	word  string
	start int
	end   int
}

// Detect scans text for BIP-39 seed phrases. Returns all matches found.
// minWords must be one of {12, 15, 18, 21, 24}.
// If verifyChecksum is true, only phrases with valid BIP-39 checksums are returned.
func Detect(text string, minWords int, verifyChecksum bool) []SeedMatch {
	spans := DetectSpans(text, minWords, verifyChecksum)
	if len(spans) == 0 {
		return nil
	}
	matches := make([]SeedMatch, 0, len(spans))
	for _, span := range spans {
		matches = append(matches, span.SeedMatch)
	}
	return matches
}

// DetectSpans scans text for BIP-39 seed phrases and returns byte offsets for
// each phrase. It uses the same checksum semantics as Detect.
func DetectSpans(text string, minWords int, verifyChecksum bool) []SeedSpan {
	tokens := tokenizeWithSpans(text)
	if len(tokens) < minWords {
		return nil
	}

	var matches []SeedSpan
	for _, wantLen := range validLengths {
		if wantLen < minWords {
			continue
		}
		if wantLen > len(tokens) {
			break
		}
		for start := 0; start <= len(tokens)-wantLen; start++ {
			if !IsWord(tokens[start].word) {
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
			matches = append(matches, SeedSpan{
				SeedMatch: SeedMatch{
					WordCount:     wantLen,
					ChecksumValid: checksumOK,
				},
				Start: tokens[start].start,
				End:   tokens[start+wantLen-1].end,
			})
			// Skip past this match to avoid overlapping detections
			start += wantLen - 1
		}
	}
	return matches
}

// isSeedSeparator splits on whitespace and common seed-phrase delimiters. It
// covers the full Go whitespace set (ASCII whitespace, NBSP, Unicode line and
// paragraph separators, NEL), the historical Mongolian vowel separator used in
// existing DLP whitespace normalization, Unicode dash punctuation (en/em/figure
// dashes vs ASCII hyphen), and literal , _ / | ; : • · delimiters seen in
// numbered or bulleted backups. Broadening this closes the "split words with a
// glyph the tokenizer ignores" evasion class.
//
// "." is deliberately NOT a separator: the request-body scanner joins distinct
// JSON field values with "." (proxy.bodyDLPJoinSeparator) so cross-field DLP
// works without merging tokens. Treating "." as intra-phrase here would let the
// detector synthesize a mnemonic across separate fields (a false positive that
// proxy.TestScanRequestBody_SeedPhraseDoesNotSpanJSONFields guards against).
func isSeedSeparator(r rune) bool {
	if unicode.IsSpace(r) || unicode.Is(unicode.Pd, r) || r == '\u180E' {
		return true
	}
	switch r {
	case ',', '_', '/', '|', ';', ':', '•', '·':
		return true
	default:
		return false
	}
}

// tokenize splits text into lowercase words using seed phrase separators.
func tokenizeWithSpans(text string) []tokenSpan {
	tokens := make([]tokenSpan, 0, 16)
	start := 0
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if isSeedSeparator(r) {
			appendTokenSpan(&tokens, text, start, i)
			start = i + size
		}
		i += size
	}
	appendTokenSpan(&tokens, text, start, len(text))
	return tokens
}

func appendTokenSpan(tokens *[]tokenSpan, text string, start, end int) {
	if start >= end {
		return
	}
	raw := text[start:end]
	// Canonicalize the token for the wordlist lookup the same way the main DLP
	// scanner canonicalizes secrets (normalize.ForDLP): strip control/invisible
	// and exotic-whitespace characters, NFKC-fold compatibility forms (fullwidth),
	// map cross-script homoglyphs (Cyrillic/Greek lookalikes) to ASCII, and strip
	// combining marks. This is match-only: the span offsets below still index the
	// ORIGINAL bytes, so redaction removes the real on-wire characters.
	word := strings.ToLower(normalize.ForDLP(strings.TrimSpace(raw)))
	if word == "" {
		return
	}
	*tokens = append(*tokens, tokenSpan{
		word:  word,
		start: start,
		end:   end,
	})
}

// allBIP39 returns true if every word in the slice is a BIP-39 word.
func allBIP39(words []tokenSpan) bool {
	for _, w := range words {
		if !IsWord(w.word) {
			return false
		}
	}
	return true
}

// wordIndices converts words to their BIP-39 indices (0-2047).
func wordIndices(words []tokenSpan) []int {
	indices := make([]int, len(words))
	for i, w := range words {
		indices[i] = IndexOf(w.word)
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
