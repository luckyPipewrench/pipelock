// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// matchSingleCredentialArgument applies the shipped public-key boundary to one
// submitted string and each of its local identities independently. Aliases of
// that string must not manufacture a second argument. Each candidate still uses
// the full normalization and pairwise checks, so shell text remains blocked.
//
// Recognize only the two shipped argument patterns (the hostile preset adds
// Kubernetes and Docker locations). A custom pattern, scoped rule, or patch rule
// retains the ordinary matcher, even if it uses the same rule name.
func (pc *Config) matchSingleCredentialArgument(rule *CompiledRule, args []string, raw json.RawMessage) (matched, handled bool) {
	if rule.Name != "Credential File Access" || rule.ArgPattern == nil || rule.ArgKey != nil || rule.ArgSource != "" {
		return false, false
	}
	// A custom rule that reuses the shipped name and argument pattern with its
	// own tool scope keeps the ordinary matcher: provenance is the shipped tool
	// pattern as well, in its built-in or preset spelling.
	if rule.ToolPattern == nil || !shippedCredentialToolPatterns[rule.ToolPattern.String()] {
		return false, false
	}
	pattern := rule.ArgPattern.String()
	if pattern != `(?i)(`+sensitiveFilePathPattern+`)` &&
		pattern != `(?i)(`+sensitiveFilePathPattern+`|\.kube[\\/]?config|\.docker[\\/]?config)` {
		return false, false
	}
	var keys []string
	if len(raw) != 0 {
		extracted := jsonrpc.ExtractStringsFromJSONResult(raw)
		if extracted.Truncated {
			return false, false
		}
		args = extracted.Strings
		var ok bool
		if keys, ok = jsonObjectKeys(raw); !ok {
			return false, false
		}
	}
	if len(args) != 1 {
		return false, false
	}
	// A JSON key is not an alias of the value, but it is text the tool may act
	// on. Any key that names a protected path on its own keeps the block, so the
	// exception can only narrow what the value alone would match.
	for _, key := range pc.localPaths.expand(keys) {
		if pc.credentialCandidateMatches(rule, key) {
			return true, true
		}
	}
	for _, candidate := range pc.localPaths.expand(args) {
		if pc.credentialCandidateMatches(rule, candidate) {
			return true, true
		}
	}
	return false, true
}

// credentialCandidateMatches runs every normalization view of one string.
func (pc *Config) credentialCandidateMatches(rule *CompiledRule, candidate string) bool {
	single := []string{candidate}
	tokens, joined := normalizeArgTokens(single, normalize.ForMatching, policyPreNormalize)
	altTokens, altJoined := normalizeArgTokens(single, normalize.ForPolicy, policyPreNormalize)
	baseTokens, baseJoined := normalizeArgTokens(single, normalize.ForMatching, nil)
	rawTokens, rawJoined := literalArgTokens(single)
	return matchArgPattern(rule.ArgPattern, tokens, joined) ||
		matchArgPattern(rule.ArgPattern, altTokens, altJoined) ||
		matchArgPattern(rule.ArgPattern, baseTokens, baseJoined) ||
		matchArgPattern(rule.ArgPattern, rawTokens, rawJoined)
}

// jsonObjectKeys returns every object key at any depth. ok is false when the
// arguments cannot be parsed, which sends the call back to the ordinary matcher.
func jsonObjectKeys(raw json.RawMessage) (keys []string, ok bool) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false
	}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				keys = append(keys, k)
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(v)
	return keys, true
}

// shippedCredentialToolPatterns holds the two spellings Pipelock ships for the
// Credential File Access tool pattern: the built-in rule after alias wrapping,
// and the preset YAML form that writes the alias prefix once. Both are derived
// from the built-in rule, so a change there changes this set with it.
var shippedCredentialToolPatterns = func() map[string]bool {
	out := make(map[string]bool, 2)
	for _, r := range DefaultToolPolicyRules() {
		if r.Name != "Credential File Access" {
			continue
		}
		out[r.ToolPattern] = true
		body := strings.TrimSuffix(strings.TrimPrefix(r.ToolPattern, `(?i)^(?:`+builtinToolNameAliasPrefix+`)?`), `$`)
		out[`(?i)^`+builtinToolNameAliasPrefix+`?`+body+`$`] = true
	}
	return out
}()
