// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package addressprotect detects crypto address poisoning attacks.
// It compares blockchain addresses found in text against a user-supplied
// allowlist of known-good destinations. This is destination verification,
// not secret detection — separate from DLP.
package addressprotect

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// Checker is the runtime orchestrator for address protection.
// One shared instance per Scanner. Holds compiled validators and the
// merged/normalized allowlist (global + per-agent).
// Purely value-based (maps, slices, ints) — no closeable resources.
type Checker struct {
	validators  map[string]chainValidator
	globalAllow map[string][]string            // chain -> []normalized addresses
	agentAllow  map[string]map[string][]string // agentID -> chain -> []normalized
	prefixLen   int
	suffixLen   int
	action      string // block or warn (for lookalike findings)
	unknownAct  string // allow, warn, or block (for unknown addresses)
}

// NewChecker builds a Checker from config. Returns nil if disabled.
// MUST only be called after config.Validate() passes — panics on
// invalid config (programming error post-validation, consistent with
// scanner.New() pattern).
func NewChecker(cfg *config.AddressProtection, agentConfigs map[string][]string) *Checker {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	c := &Checker{
		validators:  make(map[string]chainValidator),
		globalAllow: make(map[string][]string),
		agentAllow:  make(map[string]map[string][]string),
		prefixLen:   cfg.Similarity.PrefixLength,
		suffixLen:   cfg.Similarity.SuffixLength,
		action:      cfg.Action,
		unknownAct:  cfg.UnknownAction,
	}

	// Defaults for similarity: 4 prefix, 4 suffix.
	if c.prefixLen <= 0 {
		c.prefixLen = 4
	}
	if c.suffixLen <= 0 {
		c.suffixLen = 4
	}

	// Register enabled chain validators.
	if chainEnabled(cfg.Chains.ETH, true) {
		c.validators[ChainETH] = ethValidator{}
	}
	if chainEnabled(cfg.Chains.BTC, true) {
		c.validators[ChainBTC] = btcValidator{}
	}
	if chainEnabled(cfg.Chains.SOL, false) { // SOL disabled by default (high FP risk).
		c.validators[ChainSOL] = solValidator{}
	}
	if chainEnabled(cfg.Chains.BNB, true) {
		c.validators[ChainBNB] = bnbValidator{}
	}

	// Parse, normalize, and dedup global allowed addresses.
	c.globalAllow = c.parseAllowlist(cfg.AllowedAddresses)

	// Parse per-agent allowed addresses (additive with global).
	for agentID, addrs := range agentConfigs {
		parsed := c.parseAllowlist(addrs)
		if len(parsed) > 0 {
			c.agentAllow[agentID] = parsed
		}
	}

	return c
}

// chainEnabled resolves a *bool chain toggle with a default value.
// nil means "use the default for this chain".
func chainEnabled(toggle *bool, defaultOn bool) bool {
	if toggle == nil {
		return defaultOn
	}
	return *toggle
}

// parseAllowlist validates and normalizes addresses, grouping by chain.
// Invalid addresses are silently skipped (config.Validate catches them first).
func (c *Checker) parseAllowlist(addresses []string) map[string][]string {
	result := make(map[string][]string)
	for _, addr := range addresses {
		for chain, v := range c.validators {
			if v.Validate(addr) {
				norm := v.Normalize(addr)
				result[chain] = appendUnique(result[chain], norm)
				break // address belongs to one chain
			}
		}
	}
	return result
}

// appendUnique appends s to the slice if not already present.
func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// CheckText detects crypto addresses in text and evaluates them against
// the effective allowlist for the given agent.
// agentID "" uses global allowlist only. This is the expected value for
// MCP stdio (one agent per process) and body scan in v1 (no agent ID
// parameter in the function signature).
func (c *Checker) CheckText(text, agentID string) Result {
	if c == nil {
		return Result{}
	}

	// Step 1: Strip zero-width/invisible Unicode characters only.
	// Do NOT use StripControlChars (strips \n, \t which serve as word
	// boundaries in joined text from extract.AllStringsFromJSON).
	// Do NOT use ForDLP (NFKC/confusable mapping corrupts base58/bech32).
	cleaned := normalize.StripZeroWidth(text)

	// Step 2: Iterative URL decode (inline, avoids circular import with scanner).
	cleaned = iterativeURLDecode(cleaned)

	// Detect addresses in cleaned text.
	var hits []Hit
	hits = c.detectInText(cleaned, hits)

	// Step 3-4: Try base64/hex decode and detect in decoded form.
	if decoded, ok := tryBase64Decode(cleaned); ok {
		hits = c.detectInText(decoded, hits)
	}
	if decoded, ok := tryHexDecode(cleaned); ok {
		hits = c.detectInText(decoded, hits)
	}

	if len(hits) == 0 {
		return Result{}
	}

	// Resolve effective allowlist: global + agent-specific (additive).
	effectiveAllow := c.effectiveAllowlist(agentID)

	// If no allowlist configured, feature is inert (hits for telemetry only).
	if len(effectiveAllow) == 0 {
		return Result{Hits: hits}
	}

	// Evaluate each hit against the allowlist.
	var findings []Finding
	for _, hit := range hits {
		v, ok := c.validators[hit.Chain]
		if !ok {
			continue
		}
		chainAllowed := effectiveAllow[hit.Chain]
		if len(chainAllowed) == 0 {
			continue // no allowlisted addresses for this chain
		}
		f := compareHit(hit, chainAllowed, c.prefixLen, c.suffixLen, c.action, c.unknownAct, v)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return Result{Hits: hits, Findings: findings}
}

// detectInText runs all enabled chain validators on the text,
// appending valid hits to the provided slice.
func (c *Checker) detectInText(text string, hits []Hit) []Hit {
	for chain, v := range c.validators {
		for _, m := range v.Detect(text) {
			if v.Validate(m.text) {
				hits = append(hits, Hit{
					Chain:      chain,
					Raw:        m.text,
					Normalized: v.Normalize(m.text),
				})
			}
		}
	}
	return hits
}

// effectiveAllowlist merges global and agent-specific allowlists (additive).
func (c *Checker) effectiveAllowlist(agentID string) map[string][]string {
	agentAddrs, hasAgent := c.agentAllow[agentID]
	if !hasAgent || agentID == "" {
		return c.globalAllow
	}

	// Merge: global + agent-specific, deduped.
	merged := make(map[string][]string, len(c.globalAllow))
	for chain, addrs := range c.globalAllow {
		merged[chain] = append(merged[chain], addrs...)
	}
	for chain, addrs := range agentAddrs {
		for _, addr := range addrs {
			merged[chain] = appendUnique(merged[chain], addr)
		}
	}
	return merged
}

// maxDecodeRounds limits iterative URL decoding to prevent infinite loops.
const maxDecodeRounds = 10

// iterativeURLDecode applies URL decoding until the string stops changing.
// Duplicates scanner.IterativeDecode because scanner imports addressprotect
// (circular import). normalize.StripZeroWidth is fine — no cycle there.
func iterativeURLDecode(s string) string {
	for range maxDecodeRounds {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return s
}

// tryBase64Decode attempts standard and URL-safe base64 decoding.
// Returns decoded string and true only if the entire input decodes
// successfully and produces valid UTF-8.
func tryBase64Decode(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil && len(decoded) > 0 && utf8.Valid(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

// tryHexDecode attempts hex decoding. Returns decoded string and true
// only if the entire input decodes and produces valid UTF-8.
func tryHexDecode(s string) (string, bool) {
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) == 0 || !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}

// StrictestAction returns the strictest action across a set of findings.
// block > warn > allow. Used by transports to determine the effective action.
func StrictestAction(findings []Finding) string {
	action := ""
	for _, f := range findings {
		if f.Action == config.ActionBlock {
			return config.ActionBlock
		}
		if f.Action == config.ActionWarn {
			action = config.ActionWarn
		}
	}
	return action
}
