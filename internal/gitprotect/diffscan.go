// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package gitprotect provides git-aware security features for Pipelock,
// including pre-push secret scanning and branch validation.
package gitprotect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// suppressRe matches inline suppression comments: // pipelock:ignore or # pipelock:ignore
// Must stay in sync with cliutil.SuppressRe — duplicated here to avoid import cycle.
var suppressRe = regexp.MustCompile(`(?://|#)\s*pipelock:ignore(?:\s+(.+?))?\s*$`)

// Finding represents a secret detected in a git diff.
type Finding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Content  string `json:"content"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
}

// addedLine represents a line that was added in a diff hunk.
type addedLine struct {
	lineNum int
	content string
}

// parseDiff extracts added lines from unified diff output.
// It tracks the current file from "+++ b/filename" or "+++ filename" lines
// (supporting both standard and --no-prefix diffs) and line numbers from
// "@@ -X,Y +Z,W @@" hunk headers. Only lines starting with "+" (but not
// "+++") are captured. CRLF line endings are normalized before parsing.
func parseDiff(diffText string) map[string][]addedLine {
	// Normalize \r\n to \n to handle Windows-style line endings.
	diffText = strings.ReplaceAll(diffText, "\r\n", "\n")

	result := make(map[string][]addedLine)
	lines := strings.Split(diffText, "\n")

	var currentFile string
	var lineNum int

	for _, line := range lines {
		// Track current file from "+++ b/filename" header (standard prefix)
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = line[6:] // strip "+++ b/"
			continue
		}

		// Also handle --no-prefix diffs: "+++ filename" (no b/ prefix).
		// Must come after the "+++ b/" check to avoid stripping "b/" from paths.
		if strings.HasPrefix(line, "+++ ") && !strings.HasPrefix(line, "+++ /dev/null") {
			currentFile = line[4:] // strip "+++ "
			continue
		}

		// Skip other diff headers
		if strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "diff ") ||
			strings.HasPrefix(line, "index ") {
			continue
		}

		// Parse hunk header for line numbers: @@ -X,Y +Z,W @@
		if strings.HasPrefix(line, "@@") {
			lineNum = parseHunkNewStart(line)
			continue
		}

		if currentFile == "" {
			continue
		}

		// Added lines start with "+" (but not "+++")
		if strings.HasPrefix(line, "+") {
			content := line[1:] // strip leading "+"
			result[currentFile] = append(result[currentFile], addedLine{
				lineNum: lineNum,
				content: content,
			})
			lineNum++
		} else if strings.HasPrefix(line, "-") {
			// Removed lines don't increment the new-file line counter
			continue
		} else {
			// Context lines increment the counter
			lineNum++
		}
	}

	return result
}

// parseHunkNewStart extracts the starting line number of the new file
// from a hunk header like "@@ -10,5 +20,8 @@" (returns 20).
func parseHunkNewStart(hunkLine string) int {
	// Format: @@ -old_start[,old_count] +new_start[,new_count] @@
	idx := strings.Index(hunkLine, "+")
	if idx < 0 {
		return 1
	}

	rest := hunkLine[idx+1:]
	// new_start ends at "," or " "
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		end = len(rest)
	}

	n, err := strconv.Atoi(rest[:end])
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// CompiledDLPPattern is a pre-compiled DLP regex for scanning diffs.
type CompiledDLPPattern struct {
	Class    redact.Class
	Name     string
	Re       *regexp.Regexp
	Severity string
	validate func(string) bool // post-match checksum (Luhn, mod-97, etc.), nil = regex-only
}

var gitProtectClassByPatternName = map[string]redact.Class{
	"AWS Key":         redact.ClassAWSAccessKey,
	"Google API Key":  redact.ClassGoogleAPIKey,
	"GitHub Token":    redact.ClassGitHubToken,
	"Slack Token":     redact.ClassSlackToken,
	"JWT":             redact.ClassJWT,
	"SSH Private Key": redact.ClassSSHPrivateKey,
}

// CompileDLPPatterns compiles config DLP patterns into reusable scanners.
// Patterns that map cleanly to the shared redact matcher surface use matcher
// class spans; custom/validated patterns stay on the legacy regex path so git
// hooks preserve operator-defined detection semantics.
func CompileDLPPatterns(patterns []config.DLPPattern) []CompiledDLPPattern {
	var compiled []CompiledDLPPattern
	for _, p := range patterns {
		cp := CompiledDLPPattern{
			Name:     p.Name,
			Severity: p.Severity,
		}
		if class, ok := gitProtectClassByPatternName[p.Name]; ok && p.Validator == "" {
			cp.Class = class
		}

		pattern := p.Regex
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			if cp.Class != "" {
				compiled = append(compiled, cp)
			}
			continue
		}
		cp.Re = re
		if p.Validator != "" {
			cp.validate = scanner.DLPValidators[p.Validator]
		}
		compiled = append(compiled, cp)
	}
	return compiled
}

func (cp *CompiledDLPPattern) classMatches(matches []redact.Match) []redact.Match {
	if len(matches) == 0 {
		return nil
	}
	filtered := make([]redact.Match, 0, len(matches))
	for _, match := range matches {
		if match.Class != cp.Class {
			continue
		}
		if cp.validate != nil && !cp.validate(match.Original) {
			continue
		}
		filtered = append(filtered, match)
	}
	return filtered
}

func (cp *CompiledDLPPattern) regexMatches(text string) bool {
	if cp.Re == nil {
		return false
	}
	if cp.validate == nil {
		return cp.Re.MatchString(text)
	}
	for _, match := range cp.Re.FindAllString(text, -1) {
		if cp.validate(match) {
			return true
		}
	}
	return false
}

// ErrNoDiffHeaders is returned when input contains no unified diff file headers.
var ErrNoDiffHeaders = fmt.Errorf("no unified diff file headers found (expected '+++ b/filename' or '+++ filename')")

// ScanDiffResult holds findings and suppressed findings from a diff scan.
type ScanDiffResult struct {
	Findings   []Finding
	Suppressed []Finding // Findings suppressed by inline pipelock:ignore comments
}

// ScanDiff scans diff text for DLP pattern matches in added lines.
// It returns findings sorted by file then line number, with redacted content —
// the actual secret is replaced with [REDACTED] to prevent accidental exposure.
// Inline pipelock:ignore comments are handled here (not deferred to the CLI layer)
// because diff content is always available, unlike disk reads which can fail
// when CWD doesn't match the repo root or lines have shifted.
// Returns ErrNoDiffHeaders if the input contains no valid diff file headers,
// indicating the caller may have passed non-diff content.
func ScanDiff(diffText string, patterns []CompiledDLPPattern) (ScanDiffResult, error) {
	addedLines := parseDiff(diffText)

	// Check if input had content but no diff headers — likely not a diff.
	if len(addedLines) == 0 && len(strings.TrimSpace(diffText)) > 0 && len(patterns) > 0 {
		// Only error if the input has content — empty input is fine.
		if !strings.Contains(diffText, "+++ ") {
			return ScanDiffResult{}, ErrNoDiffHeaders
		}
	}

	if len(addedLines) == 0 || len(patterns) == 0 {
		return ScanDiffResult{}, nil
	}

	var findings []Finding
	var suppressed []Finding
	var matcher *redact.Matcher
	for file, lines := range addedLines {
		for _, al := range lines {
			// Respect pipelock:ignore inline comments.
			// Bare "pipelock:ignore" suppresses all patterns on the line.
			// "pipelock:ignore RuleName" suppresses only that specific pattern.
			suppressMatch := suppressRe.FindStringSubmatch(al.content)
			suppressAll := suppressMatch != nil && strings.TrimSpace(suppressMatch[1]) == ""
			suppressRule := ""
			if suppressMatch != nil && !suppressAll {
				suppressRule = strings.TrimSpace(suppressMatch[1])
			}

			for _, cp := range patterns {
				redacted := ""
				matched := false
				regexMatched := cp.regexMatches(al.content)
				if cp.Class != "" && (cp.Re == nil || regexMatched) {
					if matcher == nil {
						matcher = redact.NewDefaultMatcher()
					}
					matches := cp.classMatches(matcher.Scan(al.content))
					if len(matches) > 0 {
						redacted = replaceGitProtectMatches(al.content, matches)
						matched = true
					}
				}
				if regexMatched {
					if !matched {
						redacted = al.content
					}
					redacted = cp.Re.ReplaceAllString(redacted, "[REDACTED]")
					matched = true
				}
				if !matched {
					continue
				}
				f := Finding{
					File:     file,
					Line:     al.lineNum,
					Content:  redacted,
					Pattern:  cp.Name,
					Severity: cp.Severity,
				}
				if suppressAll || (suppressRule != "" && strings.EqualFold(suppressRule, cp.Name)) {
					suppressed = append(suppressed, f)
				} else {
					findings = append(findings, f)
				}
			}
		}
	}

	sortFindings := func(fs []Finding) {
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].File != fs[j].File {
				return fs[i].File < fs[j].File
			}
			return fs[i].Line < fs[j].Line
		})
	}
	sortFindings(findings)
	sortFindings(suppressed)

	return ScanDiffResult{Findings: findings, Suppressed: suppressed}, nil
}

func replaceGitProtectMatches(input string, matches []redact.Match) string {
	if input == "" || len(matches) == 0 {
		return input
	}

	var b strings.Builder
	cursor := 0
	for _, match := range matches {
		if match.Start < cursor || match.Start < 0 || match.End > len(input) || match.End <= match.Start {
			continue
		}
		b.WriteString(input[cursor:match.Start])
		b.WriteString("[REDACTED]")
		cursor = match.End
	}
	b.WriteString(input[cursor:])
	return b.String()
}

// FindingsJSON returns the findings as a JSON-encoded byte slice.
// An empty or nil slice is encoded as "[]" (not "null").
func FindingsJSON(findings []Finding) ([]byte, error) {
	if findings == nil {
		findings = []Finding{}
	}
	return json.Marshal(findings)
}

// FormatFindings returns a human-readable summary of findings.
func FormatFindings(findings []Finding) string {
	if len(findings) == 0 {
		return "No secrets found in diff."
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Found %d secret(s) in diff:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(&sb, "  %s:%d  %s (%s)\n", f.File, f.Line, f.Pattern, f.Severity)
		fmt.Fprintf(&sb, "    %s\n\n", f.Content)
	}
	return sb.String()
}
