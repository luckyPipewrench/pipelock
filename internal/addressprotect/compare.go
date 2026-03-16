// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Verdict represents the result of comparing a detected address against the allowlist.
type Verdict int

const (
	// VerdictLookalike means the address resembles an allowlisted address but isn't
	// an exact match — possible address poisoning. Action applies.
	VerdictLookalike Verdict = iota
	// VerdictUnknown means the address is valid but not in the allowlist.
	// unknown_action applies.
	VerdictUnknown
)

// Hit represents a valid crypto address detected in text.
// Only structurally valid addresses become Hits. Invalid candidates
// are discarded internally and never surface.
type Hit struct {
	Chain      string `json:"chain"`      // "eth", "btc", "sol", "bnb"
	Raw        string `json:"raw"`        // as found in text
	Normalized string `json:"normalized"` // canonical form for comparison
}

// Finding represents the result of comparing a Hit against the allowlist.
type Finding struct {
	Hit
	Verdict     Verdict `json:"verdict"`
	Action      string  `json:"action"`                 // resolved action: block or warn (from config, verdict-specific)
	MatchedAddr string  `json:"matched_addr,omitempty"` // truncated allowlist address (lookalike only)
	Explanation string  `json:"explanation"`
}

// Result is the public output of CheckText.
type Result struct {
	Hits     []Hit     `json:"hits"`               // all valid addresses detected (telemetry)
	Findings []Finding `json:"findings,omitempty"` // actionable findings only
}

// isSimilar checks if two addresses on the same chain are poisoning lookalikes.
// Operates on CompareKey values (chain payload only, not full address string).
// Returns true when: same length, same prefix/suffix, different middle.
func isSimilar(a, b string, prefixLen, suffixLen int) bool {
	if a == b {
		return false // exact match, not a lookalike
	}
	if len(a) != len(b) {
		return false // different length, not a lookalike
	}
	if prefixLen+suffixLen >= len(a) {
		return false // guard: prefix+suffix must be shorter than payload
	}
	return a[:prefixLen] == b[:prefixLen] &&
		a[len(a)-suffixLen:] == b[len(b)-suffixLen:]
}

// truncateAddr produces a display-safe truncated address.
// Uses CompareKey (payload) for prefix/suffix selection, then re-adds chain prefix.
// Example: ETH "0x742d35cc...f2bd3e", BTC bech32 "bc1qw508...8f3t4".
func truncateAddr(normalized string, v chainValidator) string {
	key := v.CompareKey(normalized)

	// Short addresses: show full.
	const minTruncLen = 16
	if len(key) < minTruncLen {
		return normalized
	}

	// Show first 6 and last 6 chars of the payload.
	const showChars = 6
	prefix := key[:showChars]
	suffix := key[len(key)-showChars:]

	// Re-add chain prefix for display.
	chainPrefix := normalized[:len(normalized)-len(key)]
	return fmt.Sprintf("%s%s...%s", chainPrefix, prefix, suffix)
}

// compareHit checks a single Hit against the allowlist for one chain.
// Returns a Finding if the address is a lookalike or unknown (when actioned).
// Returns nil for exact matches (allow through, no Finding).
func compareHit(hit Hit, allowedKeys []string, prefixLen, suffixLen int, action, unknownAction string, v chainValidator) *Finding {
	hitKey := v.CompareKey(hit.Normalized)

	// Check for exact match first — short-circuit, no Finding.
	for _, allowed := range allowedKeys {
		if hitKey == v.CompareKey(allowed) {
			return nil // exact match = allow
		}
	}

	// Check for lookalike (same prefix/suffix, different middle).
	for _, allowed := range allowedKeys {
		allowedKey := v.CompareKey(allowed)
		if isSimilar(hitKey, allowedKey, prefixLen, suffixLen) {
			return &Finding{
				Hit:         hit,
				Verdict:     VerdictLookalike,
				Action:      action,
				MatchedAddr: truncateAddr(allowed, v),
				Explanation: fmt.Sprintf(
					"%s address %s resembles allowlisted %s: first %d and last %d payload characters match, middle differs (possible address poisoning)",
					chainLabel(hit.Chain),
					truncateAddr(hit.Normalized, v),
					truncateAddr(allowed, v),
					prefixLen, suffixLen,
				),
			}
		}
	}

	// Unknown: valid address not in allowlist.
	if unknownAction == config.ActionAllow {
		return nil // no Finding for unknown when action is allow
	}
	return &Finding{
		Hit:     hit,
		Verdict: VerdictUnknown,
		Action:  unknownAction,
		Explanation: fmt.Sprintf(
			"%s address %s is not in the allowlist",
			chainLabel(hit.Chain),
			truncateAddr(hit.Normalized, v),
		),
	}
}

// chainLabel returns a display label for a chain constant.
func chainLabel(chain string) string {
	switch chain {
	case ChainETH:
		return "ETH"
	case ChainBTC:
		return "BTC"
	case ChainSOL:
		return "SOL"
	case ChainBNB:
		return "BNB"
	default:
		return chain
	}
}
