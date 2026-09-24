// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"strings"
)

// urlAssignmentPatternName is the built-in pattern this check narrows.
const urlAssignmentPatternName = "Credential in URL"

// urlAssignmentKeywords is the keyword alternation shared with the built-in
// Credential in URL regex; a parity test fails if the two drift apart.
const urlAssignmentKeywords = `password|passwd|secret|token|apikey|api_key|api-key`

// statementCandidateRe splits a Credential in URL candidate from the
// statement-position branch (line start or ';') into its value. Candidates
// from '?' or '&' never match, so query positions always count.
var statementCandidateRe = regexp.MustCompile(`(?is)^(?:;[ \t]*|[ \t]*)(?:` + urlAssignmentKeywords + `)[ \t]*=[ \t]*(.*)$`)

// envLookupValueRe is the closed, case-sensitive set of single
// environment-variable lookups a value may be. NAME follows the POSIX portable
// environment-variable form (uppercase letters, digits, underscore, not
// starting with a digit; IEEE Std 1003.1 Base Definitions 8.1). Dots are
// optional because the subdomain view scans a copy of the text with every '.'
// removed.
var envLookupValueRe = func() *regexp.Regexp {
	const name = `[A-Z_][A-Z0-9_]{0,127}`
	const quoted = `(?:"` + name + `"|'` + name + `')`
	const dot = `\.?`
	return regexp.MustCompile(`^(?:` +
		`os` + dot + `environ\[` + quoted + `\]|` +
		`os` + dot + `environ` + dot + `get\(` + quoted + `\)|` +
		`os` + dot + `getenv\(` + quoted + `\)|` +
		`process` + dot + `env` + dot + name + `|` +
		`process` + dot + `env\[` + quoted + `\]|` +
		`os` + dot + `Getenv\(` + quoted + `\)|` +
		`ENV\[` + quoted + `\]|` +
		`ENV` + dot + `fetch\(` + quoted + `\)` +
		`)$`)
}()

// toolCommandCredentialInURLCandidate reports whether a Credential in URL
// candidate still counts as a finding in tool-command text. It does not count
// only when all three hold in the view the scanner found it in:
//
//   - it comes from the statement-position branch (line start or ';'), never
//     '?' or '&';
//   - its whole value is exactly one listed environment lookup; and
//   - the statement ends right after it (see endsStatement).
//
// Judging the candidate in its own view matters: normalization can remove the
// line break between two statements, and in that view the lookup and a
// following literal form one candidate whose value is not a lookup, so it still
// counts. Every candidate in every view is judged, and the scan reports a
// finding if any of them counts.
//
// On the wire the same characters are literal bytes and the quoted name could
// be the credential itself, so only scanners built with
// Options.ToolCommandEnvLookups carry this check.
func toolCommandCredentialInURLCandidate(view string, start, end int) bool {
	parts := statementCandidateRe.FindStringSubmatch(view[start:end])
	if parts == nil || semicolonInURL(view, start) {
		return true
	}
	value := parts[1]
	if envLookupValueRe.MatchString(value) {
		return !endsStatement(view, end)
	}
	// The closing quote of a `python3 -c '...'` argument sits inside the
	// candidate because the value runs to the next whitespace, '&' or ';'.
	// Accept exactly one such quote, and only when nothing but the end of the
	// statement follows it.
	if n := len(value); n > 1 && (value[n-1] == '\'' || value[n-1] == '"') && envLookupValueRe.MatchString(value[:n-1]) {
		return !endsAfterClosingQuote(view, end)
	}
	return true
}

// endsAfterClosingQuote reports whether view[pos:] is only optional spaces or
// tabs followed by end of text, a line break, or ';'.
func endsAfterClosingQuote(view string, pos int) bool {
	for pos < len(view) && (view[pos] == ' ' || view[pos] == '\t') {
		pos++
	}
	return pos == len(view) || view[pos] == '\n' || view[pos] == '\r' || view[pos] == ';'
}

// endsStatement reports whether view[pos:] begins with the end of a statement:
// optional spaces or tabs, then end of text, a line break, ';', or a closing
// quote that is itself followed by end of text or whitespace (the end of a
// quoted `python3 -c '...'` argument). Anything else, such as an `or` default,
// a comment, a concatenation, or appended characters, means the value
// continues past the lookup.
func endsStatement(view string, pos int) bool {
	for pos < len(view) && (view[pos] == ' ' || view[pos] == '\t') {
		pos++
	}
	if pos == len(view) {
		return true
	}
	switch view[pos] {
	case '\n', '\r', ';':
		return true
	case '\'', '"':
		next := pos + 1
		return next == len(view) || strings.ContainsRune(" \t\r\n", rune(view[next]))
	}
	return false
}

// semicolonInURL reports whether a candidate that starts with ';' sits inside
// a URL, where ';' separates query parameters and the value is sent as literal
// bytes. It looks back from the ';' to the previous whitespace: a token there
// containing "?" or "://" is a URL. Views that remove whitespace make that
// token longer, which can only turn a statement into a URL, never the reverse.
func semicolonInURL(view string, start int) bool {
	if start >= len(view) || view[start] != ';' {
		return false
	}
	i := start
	for i > 0 && !strings.ContainsRune(" \t\r\n", rune(view[i-1])) {
		i--
	}
	token := view[i:start]
	return strings.Contains(token, "?") || strings.Contains(token, "://")
}
