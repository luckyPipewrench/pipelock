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

var externalTransferURLStartRE = regexp.MustCompile(`(?i)https?://`)

var externalTransferUploadArgRE = regexp.MustCompile(`(?i)(?:^|\s)(?:(-F|-T)([^\s;|&]+)|(-F|-T|--form|--upload-file|--post-file|--body-file)(?:=|\s+)([^\s;|&]+))`)

var externalTransferSensitiveFilenameRE = regexp.MustCompile(`(?i)^(?:(?:session[_.-]?(?:data|details|context|information|secrets?|tokens?|cookies?|keys?|credentials?|id)|diagnostic[_.-]?data|credentials?|secrets?|tokens?|cookies?|passwords?|passwd|api[_.-]?keys?|(?:private|ssh)[_.-]?keys?)(?:\.[a-z0-9_-]{1,16})?|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.(?:pem|key|der|ppk))?|\.env(?:\.[a-z0-9_-]{1,16})*)$`)

func responsePatternMatchLocations(p *compiledPattern, content string) [][]int {
	locs := p.re.FindAllStringIndex(content, -1)
	if p.name != externalDataTransferDirectivePatternName || p.re.String() != config.ExternalDataTransferDirectiveRegex {
		return locs
	}

	for _, loc := range externalTransferURLCandidateRE.FindAllStringIndex(content, -1) {
		candidate := content[loc[0]:loc[1]]
		if (!externalTransferHasSensitiveQueryKey(candidate) && !externalTransferHasSensitiveUploadSource(candidate)) || overlapsResponseMatch(locs, loc) {
			continue
		}
		locs = append(locs, loc)
	}
	return locs
}

func externalTransferHasSensitiveUploadSource(candidate string) bool {
	for _, match := range externalTransferUploadArgRE.FindAllStringSubmatch(candidate, -1) {
		flag, arg := match[1], match[2]
		if flag == "" {
			flag, arg = match[3], match[4]
		}
		flag = strings.ToLower(flag)
		arg = strings.Trim(arg, "'\"`")
		if flag == "-f" || flag == "--form" {
			if !strings.Contains(arg, "@") {
				continue
			}
			_, arg, _ = strings.Cut(arg, "@")
		}
		arg = strings.TrimPrefix(arg, "@")
		if slash := strings.LastIndexAny(arg, "/\\"); slash >= 0 {
			arg = arg[slash+1:]
		}
		if len(arg) > 160 {
			continue
		}
		if externalTransferSensitiveFilenameRE.MatchString(arg) {
			return true
		}
	}
	return false
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
	for _, loc := range externalTransferURLStartRE.FindAllStringIndex(candidate, -1) {
		rawURL := candidate[loc[0]:]
		if end := strings.IndexAny(rawURL, " \t\r\n;|"); end >= 0 {
			rawURL = rawURL[:end]
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.RawQuery == "" {
			continue
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
