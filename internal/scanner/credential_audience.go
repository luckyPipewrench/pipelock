// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/destination"
)

// CredentialAudienceAllow records a DLP match deliberately allowed because a
// compiled-in provider credential was presented to that provider's declared
// audience. It never carries matched credential bytes.
type CredentialAudienceAllow struct {
	PatternName string `json:"pattern_name"`
	Surface     string `json:"surface"`
	Destination string `json:"destination"`
}

// CredentialAudienceMismatch is explanatory metadata for a provider-bound DLP
// block. It names only compiled pattern metadata and canonical destination,
// never the matched credential.
type CredentialAudienceMismatch struct {
	PatternName string   `json:"pattern_name"`
	Surface     string   `json:"surface"`
	Destination string   `json:"destination"`
	Hosts       []string `json:"hosts"`
}

type credentialAudienceCandidate struct {
	patternName string
	hosts       []string
	core        bool
}

// filterCredentialAudience is the one destination-aware filter for compiled
// credential audience exceptions. Empty lists, core patterns, malformed
// targets, and a mismatch all retain the DLP match and therefore block. This
// deliberately fails closed: a host allow is never inferred from a parse error.
func filterCredentialAudience(candidates []credentialAudienceCandidate, target, surface string) ([]bool, []CredentialAudienceAllow) {
	keep := make([]bool, len(candidates))
	for i := range keep {
		keep[i] = true
	}
	host, ok := canonicalCredentialAudienceDestination(target)
	if !ok {
		return keep, nil
	}

	var allows []CredentialAudienceAllow
	for i, candidate := range candidates {
		if candidate.core || len(candidate.hosts) == 0 || !destination.MatchesDomainList(host, candidate.hosts) {
			continue
		}
		keep[i] = false
		allows = append(allows, CredentialAudienceAllow{
			PatternName: candidate.patternName,
			Surface:     surface,
			Destination: host,
		})
	}
	return keep, deduplicateCredentialAudienceAllows(allows)
}

// canonicalCredentialAudienceDestination reuses destination's normalized host
// and port validation. Credential audiences establish host ownership, so this
// intentionally ignores the validated port; it is not an exact-destination
// grant, which must continue to bind host and port. WebSocket frame DLP accepts
// ws/wss because the proxy's parsed upstream URL is its verified destination
// authority; raw MCP input has no such target and intentionally never calls
// this helper.
func canonicalCredentialAudienceDestination(target string) (string, bool) {
	parsed, err := url.Parse(target)
	if err != nil || parsed == nil || parsed.User != nil || parsed.Hostname() == "" {
		return "", false
	}

	scheme := strings.ToLower(parsed.Scheme)
	var defaultPort string
	switch scheme {
	case "https", "wss":
		defaultPort = "443"
	default:
		// Only an encrypted scheme may earn an audience allow. Host ownership
		// says who the destination is; it says nothing about who else can read
		// the credential in transit. Removing a DLP match for a cleartext
		// http:// or ws:// request would hand the credential to any observer
		// on the path, so cleartext keeps the match and blocks.
		return "", false
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPort
	}
	value, err := destination.ParsePort(port)
	if err != nil {
		return "", false
	}
	dest, err := destination.New(destination.NetworkTCP, parsed.Hostname(), value)
	if err != nil {
		return "", false
	}
	return dest.Host, true
}

func (s *Scanner) credentialAudienceAllows(pattern *compiledPattern, target, surface string) (CredentialAudienceAllow, bool) {
	if pattern == nil {
		return CredentialAudienceAllow{}, false
	}
	keep, allows := filterCredentialAudience([]credentialAudienceCandidate{{
		patternName: pattern.name,
		hosts:       pattern.credentialAudienceHosts,
		core:        pattern.core,
	}}, target, surface)
	if len(keep) != 1 || keep[0] || len(allows) != 1 {
		return CredentialAudienceAllow{}, false
	}
	return allows[0], true
}

func (s *Scanner) credentialAudienceMismatch(pattern *compiledPattern, target, surface string) (CredentialAudienceMismatch, bool) {
	if pattern == nil || pattern.core || len(pattern.credentialAudienceHosts) == 0 {
		return CredentialAudienceMismatch{}, false
	}
	host, ok := canonicalCredentialAudienceDestination(target)
	if !ok || destination.MatchesDomainList(host, pattern.credentialAudienceHosts) {
		return CredentialAudienceMismatch{}, false
	}
	return CredentialAudienceMismatch{
		PatternName: pattern.name,
		Surface:     surface,
		Destination: host,
		Hosts:       append([]string(nil), pattern.credentialAudienceHosts...),
	}, true
}

// FilterTextDLPMatchesForDestination applies the compiled-only audience rule
// after raw text scanning. Callers must pass their proxy-owned upstream target;
// destination-free surfaces (notably MCP stdio and MCP HTTP/SSE input) must not
// call it and therefore remain fail-closed.
func (s *Scanner) FilterTextDLPMatchesForDestination(matches []TextDLPMatch, target, surface string) ([]TextDLPMatch, []CredentialAudienceAllow) {
	if len(matches) == 0 {
		return matches, nil
	}
	candidates := make([]credentialAudienceCandidate, len(matches))
	for i, match := range matches {
		candidates[i].patternName = match.PatternName
		if pattern := s.dlpPatternByName(match.PatternName); pattern != nil {
			candidates[i].hosts = pattern.credentialAudienceHosts
			candidates[i].core = pattern.core
		}
	}
	keep, allows := filterCredentialAudience(candidates, target, surface)
	filtered := make([]TextDLPMatch, 0, len(matches))
	for i, match := range matches {
		if keep[i] {
			filtered = append(filtered, match)
		}
	}
	return filtered, allows
}

func (s *Scanner) dlpPatternByName(name string) *compiledPattern {
	for _, pattern := range s.dlpPatterns {
		if pattern.name == name {
			return pattern
		}
	}
	return nil
}

func deduplicateCredentialAudienceAllows(allows []CredentialAudienceAllow) []CredentialAudienceAllow {
	if len(allows) < 2 {
		return allows
	}
	seen := make(map[string]struct{}, len(allows))
	unique := make([]CredentialAudienceAllow, 0, len(allows))
	for _, allow := range allows {
		key := allow.PatternName + "\x00" + allow.Surface + "\x00" + allow.Destination
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, allow)
	}
	return unique
}
