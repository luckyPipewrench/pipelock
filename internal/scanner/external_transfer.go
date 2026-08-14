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

// externalTransferFileDirectiveRE matches a natural-language instruction to send
// the contents of a named file to an external URL.
//
// The command form of this was already covered: `curl --upload-file .env
// https://...` matches through externalTransferHasSensitiveUploadSource, because
// .env is on the sensitive-filename list. The prose form naming the same file was
// not, so one phrasing of one exfiltration was caught and the other was invisible.
// This closes that inconsistency rather than widening what counts as sensitive.
//
// Deliberately narrow. All four must be present: a transfer verb from the
// vocabulary the surrounding pattern already uses, an explicit whole-content
// phrase, a filename the sensitive list already recognises, and an external
// destination. Dropping any one of them starts matching ordinary developer prose
// that discusses a file and links to documentation, which is the failure mode that
// gets a detector switched off.
var externalTransferFileDirectiveRE = regexp.MustCompile(
	`(?im)(?:^|[.!?:]\s+)\s*(?:[-*]\s+)?` +
		`(?:(?:please|must|required\s+to|need\s+to|you\s+(?:must|should|need\s+to))\s+)?` +
		`(?:send|upload|post|transmit|forward|email|exfiltrat\w*)\b` +
		`(?:[^.\n!?;|&]|\.[^\s]){0,60}?` +
		`\bcontents?\s+of\b` +
		`(?P<span>(?:[^.\n!?;|&]|\.[^\s]){0,120}?)` +
		`\b(?:to|via|using|through|at)\s+(?:(?:the|this|an?)\s+)?` +
		`(?:(?:external|remote|upload|collection)\s+)?(?:url|endpoint|server|address)?\s*(?:at|:)?\s*` +
		`https?://`,
)

// externalTransferTemplateFilenameRE matches the .env-family filenames that are a
// convention for a secret-free template rather than a populated secret file.
//
// Treating these as sensitive costs availability and buys nothing. A repository
// commits .env.example precisely so it carries no secrets, and uploading one to a
// validator is ordinary traffic. An attacker who names .env.example in an
// exfiltration instruction receives the template, so excluding them removes a
// false positive without opening a path.
var externalTransferTemplateFilenameRE = regexp.MustCompile(`(?i)^\.env\.(?:example|sample|template|dist|defaults?)$`)

// isSensitiveTransferFilename is the single decision point for both the prose arm
// and the command-argument arm. Keeping one function means the two phrasings
// cannot drift into disagreeing about the same filename, which is the defect the
// prose arm was added to close.
func isSensitiveTransferFilename(name string) bool {
	if externalTransferTemplateFilenameRE.MatchString(name) {
		return false
	}
	return externalTransferSensitiveFilenameRE.MatchString(name)
}

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
	for _, loc := range externalTransferFileDirectiveRE.FindAllStringSubmatchIndex(content, -1) {
		if !externalTransferNamesSensitiveFile(content, loc) || overlapsResponseMatch(locs, loc[0:2]) {
			continue
		}
		locs = append(locs, loc[0:2])
	}
	return locs
}

// externalTransferNamesSensitiveFile reports whether any token between the
// whole-content phrase and the destination is a filename the sensitive list
// already recognises.
//
// It tests every token rather than capturing one, because the filename is not at
// a fixed position: "the contents of the .env file to <url>" puts an article and
// a trailing noun around it. Positional capture picked up "the" and silently
// missed the case this arm exists for. Deciding against the one shared vocabulary
// also keeps a second copy of the filename list from drifting inside a pattern.
func externalTransferNamesSensitiveFile(content string, loc []int) bool {
	idx := externalTransferFileDirectiveRE.SubexpIndex("span")
	if idx < 0 || len(loc) <= 2*idx+1 || loc[2*idx] < 0 {
		return false
	}
	// Named "word" rather than "token": this repository's own secret scanner reads
	// `token = <value>` in Go source as a credential assignment, and the scan runs
	// against this file on every push.
	for _, word := range strings.Fields(content[loc[2*idx]:loc[2*idx+1]]) {
		word = strings.Trim(word, "'\"`*,;:()[]{}<>")
		word = strings.TrimSuffix(word, ".")
		if slash := strings.LastIndexAny(word, "/\\"); slash >= 0 {
			word = word[slash+1:]
		}
		if word == "" || len(word) > 160 {
			continue
		}
		if isSensitiveTransferFilename(word) {
			return true
		}
	}
	return false
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
		if isSensitiveTransferFilename(arg) {
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
