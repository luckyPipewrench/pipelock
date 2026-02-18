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
)

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
	Name     string
	Re       *regexp.Regexp
	Severity string
}

// CompileDLPPatterns compiles config DLP patterns into reusable compiled patterns.
// Forces case-insensitive matching ((?i) prefix) to match scanner.go behavior —
// secrets in git diffs should be caught regardless of casing.
// Invalid patterns are skipped (validation should have caught them).
func CompileDLPPatterns(patterns []config.DLPPattern) []CompiledDLPPattern {
	var compiled []CompiledDLPPattern
	for _, p := range patterns {
		pattern := p.Regex
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, CompiledDLPPattern{
			Name:     p.Name,
			Re:       re,
			Severity: p.Severity,
		})
	}
	return compiled
}

// ErrNoDiffHeaders is returned when input contains no unified diff file headers.
var ErrNoDiffHeaders = fmt.Errorf("no unified diff file headers found (expected '+++ b/filename' or '+++ filename')")

// ScanDiff scans diff text for DLP pattern matches in added lines.
// It returns findings sorted by file then line number, with redacted content —
// the actual secret is replaced with [REDACTED] to prevent accidental exposure.
// Returns ErrNoDiffHeaders if the input contains no valid diff file headers,
// indicating the caller may have passed non-diff content.
func ScanDiff(diffText string, patterns []CompiledDLPPattern) ([]Finding, error) {
	addedLines := parseDiff(diffText)

	// Check if input had content but no diff headers — likely not a diff.
	if len(addedLines) == 0 && len(strings.TrimSpace(diffText)) > 0 && len(patterns) > 0 {
		// Only error if the input has content — empty input is fine.
		if !strings.Contains(diffText, "+++ ") {
			return nil, ErrNoDiffHeaders
		}
	}

	if len(addedLines) == 0 || len(patterns) == 0 {
		return nil, nil
	}

	var findings []Finding
	for file, lines := range addedLines {
		for _, al := range lines {
			for _, cp := range patterns {
				if cp.Re.MatchString(al.content) {
					redacted := cp.Re.ReplaceAllString(al.content, "[REDACTED]")
					findings = append(findings, Finding{
						File:     file,
						Line:     al.lineNum,
						Content:  redacted,
						Pattern:  cp.Name,
						Severity: cp.Severity,
					})
				}
			}
		}
	}

	// Sort by file, then by line number for deterministic output
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	return findings, nil
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
