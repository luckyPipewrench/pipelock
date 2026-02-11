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
// It tracks the current file from "+++ b/filename" lines and
// line numbers from "@@ -X,Y +Z,W @@" hunk headers.
// Only lines starting with "+" (but not "+++") are captured.
func parseDiff(diffText string) map[string][]addedLine {
	result := make(map[string][]addedLine)
	lines := strings.Split(diffText, "\n")

	var currentFile string
	var lineNum int

	for _, line := range lines {
		// Track current file from "+++ b/filename" header
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = line[6:] // strip "+++ b/"
			continue
		}

		// Skip other diff headers
		if strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "diff ") ||
			strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "+++ ") {
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
	if err != nil {
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
// Invalid patterns are skipped (validation should have caught them).
func CompileDLPPatterns(patterns []config.DLPPattern) []CompiledDLPPattern {
	var compiled []CompiledDLPPattern
	for _, p := range patterns {
		re, err := regexp.Compile(p.Regex)
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

// ScanDiff scans diff text for DLP pattern matches in added lines.
// It returns findings sorted by file then line number, with redacted content —
// the actual secret is replaced with [REDACTED] to prevent accidental exposure.
func ScanDiff(diffText string, patterns []CompiledDLPPattern) []Finding {
	addedLines := parseDiff(diffText)
	if len(addedLines) == 0 || len(patterns) == 0 {
		return nil
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

	return findings
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
	sb.WriteString(fmt.Sprintf("Found %d secret(s) in diff:\n\n", len(findings)))
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("  %s:%d  %s (%s)\n", f.File, f.Line, f.Pattern, f.Severity))
		sb.WriteString(fmt.Sprintf("    %s\n\n", f.Content))
	}
	return sb.String()
}
