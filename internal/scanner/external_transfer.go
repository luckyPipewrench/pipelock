// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// externalTransferURLCandidateRE finds the indirect-tool branch without
// guessing how a query key was percent-encoded. Query-key classification is
// performed after URL-query decoding by externalTransferHasSensitiveQueryKey.
var externalTransferURLCandidateRE = regexp.MustCompile(`(?im)(?:^|[.!?:]\s+)\s*(?:[-*]\s+)?(?:(?:please|must|required\s+to|need\s+to|you\s+(?:must|should|need\s+to))\s+)?(?:call|invoke|execute|run|fetch|curl|wget)\b(?:[^.\n!?;|&]|\.[^\s]){0,180}\bhttps?://[^\s;|]{1,600}`)

func responsePatternMatchLocations(p *compiledPattern, content string) [][]int {
	locs := p.re.FindAllStringIndex(content, -1)
	if p.name != externalDataTransferDirectivePatternName || p.re.String() != config.ExternalDataTransferDirectiveRegex {
		return locs
	}

	for _, loc := range externalTransferURLCandidateRE.FindAllStringIndex(content, -1) {
		if !externalTransferHasSensitiveQueryKey(content[loc[0]:loc[1]]) || overlapsResponseMatch(locs, loc) {
			continue
		}
		locs = append(locs, loc)
	}
	return locs
}

func overlapsResponseMatch(existing [][]int, candidate []int) bool {
	for _, loc := range existing {
		if candidate[0] < loc[1] && loc[0] < candidate[1] {
			return true
		}
	}
	return false
}

func externalTransferHasSensitiveQueryKey(candidate string) bool {
	lower := strings.ToLower(candidate)
	start := strings.LastIndex(lower, "http://")
	if httpsStart := strings.LastIndex(lower, "https://"); httpsStart > start {
		start = httpsStart
	}
	if start < 0 {
		return false
	}

	parsed, err := url.Parse(candidate[start:])
	if err != nil || parsed.RawQuery == "" {
		return false
	}
	for _, field := range strings.Split(parsed.RawQuery, "&") {
		rawKey, _, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		key, err := url.QueryUnescape(rawKey)
		if err == nil && isSensitiveTransferQueryKey(key) {
			return true
		}
	}
	return false
}

func isSensitiveTransferQueryKey(key string) bool {
	key = strings.ToLower(key)
	normalized := strings.NewReplacer("-", "_", " ", "_").Replace(key)
	switch normalized {
	case "session", "sessionid", "token", "secret", "credential", "credentials",
		"password", "passwd", "cookie", "cookies", "auth", "authorization", "jwt",
		"apikey", "api_key", "access_token", "refresh_token", "id_token", "api_token":
		return true
	}

	prefix, suffix, ok := strings.Cut(normalized, "_")
	if !ok {
		return false
	}
	switch prefix {
	case "session":
		return transferQuerySuffix(suffix, true)
	case "user", "customer", "workspace", "diagnostic":
		return transferQuerySuffix(suffix, false)
	default:
		return false
	}
}

func transferQuerySuffix(suffix string, allowID bool) bool {
	switch suffix {
	case "data", "details", "context", "information", "secret", "secrets", "token", "tokens",
		"cookie", "cookies", "key", "keys", "credential", "credentials":
		return true
	case "id":
		return allowID
	default:
		return false
	}
}
