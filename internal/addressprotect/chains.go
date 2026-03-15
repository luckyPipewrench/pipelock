// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"regexp"
	"strings"
)

// rawMatch holds a candidate address string found by a chain detector.
type rawMatch struct {
	text   string
	offset int
}

// chainValidator detects, validates, normalizes, and produces comparison keys
// for addresses of a specific blockchain.
type chainValidator interface {
	// Detect finds candidate address strings in text using regex.
	Detect(text string) []rawMatch
	// Validate checks structural validity (checksum, decode, format).
	// Only structurally valid addresses become Hits.
	Validate(raw string) bool
	// Normalize returns the canonical form for comparison.
	Normalize(raw string) string
	// CompareKey extracts the payload portion for similarity scoring,
	// stripping chain-specific prefixes that consume useful comparison chars.
	CompareKey(normalized string) string
}

// Chain name constants used in Hit.Chain and config.
const (
	ChainETH = "eth"
	ChainBTC = "btc"
	ChainSOL = "sol"
	ChainBNB = "bnb"
)

// Compile-time interface satisfaction checks.
var (
	_ chainValidator = ethValidator{}
	_ chainValidator = btcValidator{}
	_ chainValidator = solValidator{}
	_ chainValidator = bnbValidator{}
)

// ---------- ETH ----------

var ethRegex = regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)

type ethValidator struct{}

func (ethValidator) Detect(text string) []rawMatch {
	locs := ethRegex.FindAllStringIndex(text, -1)
	matches := make([]rawMatch, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, rawMatch{text: text[loc[0]:loc[1]], offset: loc[0]})
	}
	return matches
}

func (ethValidator) Validate(raw string) bool {
	// Regex already enforces 0x + 40 hex chars. No EIP-55 checksum in v1.
	return len(raw) == 42 && strings.HasPrefix(strings.ToLower(raw), "0x")
}

func (ethValidator) Normalize(raw string) string {
	return strings.ToLower(raw)
}

func (ethValidator) CompareKey(normalized string) string {
	// Strip "0x" prefix — compare hex payload only.
	if len(normalized) > 2 {
		return normalized[2:]
	}
	return normalized
}

// ---------- BTC ----------

// BTC has three address sub-formats. Each has its own regex, validation, and CompareKey.
// Similarity is within-format only: P2PKH vs P2PKH, bech32 v0 vs bech32 v0, etc.
// Cross-format comparison is not performed (visually distinct formats).

// P2PKH: starts with '1', 25-34 chars, Base58Check with version 0x00.
// P2SH: starts with '3', 25-34 chars, Base58Check with version 0x05.
var btcLegacyRegex = regexp.MustCompile(`\b[13][1-9A-HJ-NP-Za-km-z]{24,33}\b`)

// Bech32 (SegWit v0 + Taproot v1): bc1 followed by bech32 chars.
// v0 (bc1q): 42 total chars. v1 (bc1p): 62 total chars.
var btcBech32Regex = regexp.MustCompile(`\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59}\b`)

type btcValidator struct{}

func (btcValidator) Detect(text string) []rawMatch {
	lower := strings.ToLower(text)
	var matches []rawMatch

	// Detect bech32 addresses (case-insensitive, but bech32 must be uniform case).
	for _, loc := range btcBech32Regex.FindAllStringIndex(lower, -1) {
		// Use the original text segment to preserve case for validation.
		matches = append(matches, rawMatch{text: text[loc[0]:loc[1]], offset: loc[0]})
	}

	// Detect legacy base58 addresses (case-sensitive).
	for _, loc := range btcLegacyRegex.FindAllStringIndex(text, -1) {
		matches = append(matches, rawMatch{text: text[loc[0]:loc[1]], offset: loc[0]})
	}

	return matches
}

func (btcValidator) Validate(raw string) bool {
	lower := strings.ToLower(raw)

	// Bech32/Bech32m: validate checksum and HRP.
	if strings.HasPrefix(lower, "bc1") {
		hrp, _, ver, err := bech32Decode(lower)
		if err != nil || hrp != "bc" {
			return false
		}
		// SegWit v0 uses bech32, v1+ uses bech32m.
		witnessVer := lower[3] // 'q' = v0, 'p' = v1
		if witnessVer == 'q' && ver != bech32Version {
			return false
		}
		if witnessVer == 'p' && ver != bech32mVersion {
			return false
		}
		return true
	}

	// Legacy P2PKH (version 0x00) or P2SH (version 0x05).
	_, version, err := base58CheckDecode(raw)
	if err != nil {
		return false
	}
	return version == 0x00 || version == 0x05
}

func (btcValidator) Normalize(raw string) string {
	lower := strings.ToLower(raw)
	// Bech32 addresses normalize to lowercase.
	if strings.HasPrefix(lower, "bc1") {
		return lower
	}
	// Legacy base58 is case-sensitive — return as-is.
	return raw
}

func (btcValidator) CompareKey(normalized string) string {
	// Bech32: strip "bc1" prefix, keep witness version char.
	// This means v0 (bc1q...) and v1 (bc1p...) addresses have different
	// CompareKey prefixes and are never compared against each other.
	if strings.HasPrefix(normalized, "bc1") && len(normalized) > 3 {
		return normalized[3:]
	}
	// Legacy base58: full string is the compare key.
	return normalized
}

// ---------- SOL ----------

// SOL addresses are base58-encoded Ed25519 public keys (32 bytes).
// The regex matches base58 strings of 32-44 chars. Validation requires
// decoding to exactly 32 bytes — this is the primary false positive filter.
var solRegex = regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`)

type solValidator struct{}

func (solValidator) Detect(text string) []rawMatch {
	locs := solRegex.FindAllStringIndex(text, -1)
	matches := make([]rawMatch, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, rawMatch{text: text[loc[0]:loc[1]], offset: loc[0]})
	}
	return matches
}

func (solValidator) Validate(raw string) bool {
	decoded, err := base58Decode(raw)
	if err != nil {
		return false
	}
	// Must decode to exactly 32 bytes (Ed25519 public key).
	return len(decoded) == 32
}

func (solValidator) Normalize(raw string) string {
	// SOL base58 is case-sensitive — return as-is.
	return raw
}

func (solValidator) CompareKey(normalized string) string {
	// Full string — no prefix to strip.
	return normalized
}

// ---------- BNB (Beacon Chain) ----------

// BNB Beacon Chain uses bech32 with "bnb" HRP. BSC/BEP-20 uses 0x (covered by ETH).
var bnbRegex = regexp.MustCompile(`\bbnb1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}\b`)

type bnbValidator struct{}

func (bnbValidator) Detect(text string) []rawMatch {
	lower := strings.ToLower(text)
	locs := bnbRegex.FindAllStringIndex(lower, -1)
	matches := make([]rawMatch, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, rawMatch{text: lower[loc[0]:loc[1]], offset: loc[0]})
	}
	return matches
}

func (bnbValidator) Validate(raw string) bool {
	hrp, _, _, err := bech32Decode(strings.ToLower(raw))
	return err == nil && hrp == "bnb"
}

func (bnbValidator) Normalize(raw string) string {
	// Bech32 is always lowercase.
	return strings.ToLower(raw)
}

func (bnbValidator) CompareKey(normalized string) string {
	// Strip "bnb1" prefix.
	if len(normalized) > 4 && strings.HasPrefix(normalized, "bnb1") {
		return normalized[4:]
	}
	return normalized
}
