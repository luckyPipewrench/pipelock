// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
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
	patternName       string
	hosts             []string
	authorizationOnly bool
	carrierMask       uint8
}

// CredentialAudienceAuthorizationHeaderSurface distinguishes Authorization from other
// request headers during the decision. Both report the existing "header"
// telemetry surface.
const CredentialAudienceAuthorizationHeaderSurface = "authorization_header"

const credentialAudienceAuthorizationHeaderName = "Authorization"

const (
	credentialAudienceAuthorizationAnySurface = "authorization_header_any"
	credentialAudiencePrivateTokenSurface     = "header_private_token"
	credentialAudienceJobTokenSurface         = "header_job_token"
)

// CredentialAudienceHeaderSurface classifies the header that carried a match.
// Bearer Authorization stays distinct so the Google OAuth exception cannot
// attach to an arbitrary Authorization value. GitHub accepts either Bearer or
// the older token scheme, so any other Authorization value is its own surface.
func CredentialAudienceHeaderSurface(headerName, value string) string {
	switch {
	case strings.EqualFold(headerName, credentialAudienceAuthorizationHeaderName):
		fields := strings.Fields(value)
		if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
			return CredentialAudienceAuthorizationHeaderSurface
		}
		return credentialAudienceAuthorizationAnySurface
	case strings.EqualFold(headerName, "Private-Token"):
		return credentialAudiencePrivateTokenSurface
	case strings.EqualFold(headerName, "Job-Token"):
		return credentialAudienceJobTokenSurface
	default:
		return "header"
	}
}

func audienceSurfacePermitted(surface string, authorizationOnly bool, mask uint8) bool {
	if !authorizationOnly && mask == 0 {
		return true
	}
	switch surface {
	case CredentialAudienceAuthorizationHeaderSurface:
		return authorizationOnly || mask&config.CredentialAudienceCarrierAuthorization != 0
	case credentialAudienceAuthorizationAnySurface:
		return mask&config.CredentialAudienceCarrierAuthorization != 0
	case credentialAudiencePrivateTokenSurface:
		return mask&config.CredentialAudienceCarrierPrivateToken != 0
	case credentialAudienceJobTokenSurface:
		return mask&config.CredentialAudienceCarrierJobToken != 0
	default:
		return false
	}
}

// filterCredentialAudience is the one destination-aware filter for compiled
// credential audience exceptions. An empty host list, a malformed target, and a
// mismatch all retain the DLP match and therefore block. A core-floor pattern is
// filtered here only when it carries a compiled audience: core-ness alone no
// longer disqualifies the exception, because the audience is compiled-in and
// unreachable from YAML, so this cannot widen the floor from configuration. This
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
		if !audienceSurfacePermitted(surface, candidate.authorizationOnly, candidate.carrierMask) {
			continue
		}
		if len(candidate.hosts) == 0 || !destination.MatchesDomainList(host, candidate.hosts) {
			continue
		}
		keep[i] = false
		recordSurface := surface
		switch surface {
		case CredentialAudienceAuthorizationHeaderSurface, credentialAudienceAuthorizationAnySurface, credentialAudiencePrivateTokenSurface, credentialAudienceJobTokenSurface:
			recordSurface = "header"
		}
		allows = append(allows, CredentialAudienceAllow{
			PatternName: candidate.patternName,
			Surface:     recordSurface,
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

func (p *compiledPattern) credentialAudienceCarrierRestricted() bool {
	return p != nil && (p.credentialAudienceAuthorizationOnly || p.credentialAudienceCarrierMask != 0)
}

func (s *Scanner) credentialAudienceAllows(pattern *compiledPattern, target, surface string) (CredentialAudienceAllow, bool) {
	if pattern == nil {
		return CredentialAudienceAllow{}, false
	}
	keep, allows := filterCredentialAudience([]credentialAudienceCandidate{{
		patternName:       pattern.name,
		hosts:             pattern.credentialAudienceHosts,
		authorizationOnly: pattern.credentialAudienceAuthorizationOnly,
		carrierMask:       pattern.credentialAudienceCarrierMask,
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
		candidates[i].hosts = match.credentialAudienceHosts
		candidates[i].authorizationOnly = match.credentialAudienceAuthorizationOnly
		candidates[i].carrierMask = match.credentialAudienceCarrierMask
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

// ScrubAuthorizedCredentialFromJoinedHeaders removes only raw matches that
// already qualify for an Authorization-header audience allow. The proxy scans
// each original header value and also scans a joined copy for split secrets.
// Without this narrow scrub the joined copy redetects the same allowed token
// as an unowned header and blocks it. The scrubbed copy decides only the
// Authorization-only patterns; see MergeJoinedHeaderMatches.
func (s *Scanner) ScrubAuthorizedCredentialFromJoinedHeaders(headerName, value, target string) string {
	surface := CredentialAudienceHeaderSurface(headerName, value)
	if surface == "header" {
		return value
	}
	patterns := s.dlpPatterns
	if s.core != nil {
		patterns = append(append([]*compiledPattern{}, patterns...), s.core.dlpPatterns...)
	}
	for _, pattern := range patterns {
		if !pattern.credentialAudienceCarrierRestricted() {
			continue
		}
		if _, ok := s.credentialAudienceAllows(pattern, target, surface); !ok {
			continue
		}
		value = pattern.re.ReplaceAllString(value, "[authorized-credential]")
	}
	return value
}

// MergeJoinedHeaderMatches combines the joined-header scan of the original
// values with the scan of the copy scrubbed by
// ScrubAuthorizedCredentialFromJoinedHeaders. The greedy token match can
// swallow the first half of an unrelated secret whose second half sits in
// another header, so every other pattern is decided on the original text.
// Only Authorization-only patterns are taken from the scrubbed copy.
func MergeJoinedHeaderMatches(original, scrubbed []TextDLPMatch) []TextDLPMatch {
	merged := make([]TextDLPMatch, 0, len(original)+len(scrubbed))
	for _, match := range original {
		if !match.credentialAudienceCarrierRestricted() {
			merged = append(merged, match)
		}
	}
	for _, match := range scrubbed {
		if match.credentialAudienceCarrierRestricted() {
			merged = append(merged, match)
		}
	}
	return merged
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
