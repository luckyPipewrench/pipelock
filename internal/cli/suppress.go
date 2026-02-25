package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

// Suppression source constants for suppressResult.
const (
	suppressSourceInline = "inline"
	suppressSourceConfig = "config"
)

// suppressRe matches inline suppression comments.
// Supports // and # comment styles. The optional capture group
// holds the rule name; when absent, all rules on that line are suppressed.
var suppressRe = regexp.MustCompile(`(?://|#)\s*pipelock:ignore(?:\s+(.+?))?\s*$`)

// suppressResult describes why a finding was suppressed.
type suppressResult struct {
	suppressed bool
	source     string // suppressSourceInline or suppressSourceConfig
	reason     string // config reason or rule name for inline
}

// checkInlineSuppression reads a source line from disk and checks for a
// pipelock:ignore comment. Returns whether the finding's rule is suppressed.
func checkInlineSuppression(file string, line int, rule string) suppressResult {
	if file == "" || line <= 0 {
		return suppressResult{}
	}

	src, err := readSourceLine(file, line)
	if err != nil {
		return suppressResult{}
	}

	m := suppressRe.FindStringSubmatch(src)
	if m == nil {
		return suppressResult{}
	}

	// m[1] is the optional rule name after pipelock:ignore.
	// Empty means suppress all rules on this line.
	ignoreRule := strings.TrimSpace(m[1])
	if ignoreRule == "" || strings.EqualFold(ignoreRule, rule) {
		return suppressResult{suppressed: true, source: suppressSourceInline}
	}

	return suppressResult{}
}

// checkConfigSuppression checks whether a finding matches any config suppress entry.
func checkConfigSuppression(file string, rule string, entries []config.SuppressEntry) suppressResult {
	if file == "" || len(entries) == 0 {
		return suppressResult{}
	}

	reason, ok := config.SuppressedReason(rule, file, entries)
	if ok {
		return suppressResult{
			suppressed: true,
			source:     suppressSourceConfig,
			reason:     reason,
		}
	}

	return suppressResult{}
}

// checkFinding runs the inline → config suppression pipeline for a single finding.
func checkFinding(file string, line int, pattern string, entries []config.SuppressEntry) suppressResult {
	if r := checkInlineSuppression(file, line, pattern); r.suppressed {
		return r
	}
	return checkConfigSuppression(file, pattern, entries)
}

// suppressGitFindings filters gitprotect findings through inline and config
// suppression. Returns the kept findings and suppressed findings.
func suppressGitFindings(findings []gitprotect.Finding, entries []config.SuppressEntry) (kept, suppressed []gitprotect.Finding, reasons []suppressResult) {
	for _, f := range findings {
		if r := checkFinding(f.File, f.Line, f.Pattern, entries); r.suppressed {
			suppressed = append(suppressed, f)
			reasons = append(reasons, r)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed, reasons
}

// suppressProjectFindings filters projectscan findings through inline and config
// suppression. Returns the kept findings and suppressed findings.
func suppressProjectFindings(findings []projectscan.Finding, entries []config.SuppressEntry) (kept, suppressed []projectscan.Finding, reasons []suppressResult) {
	for _, f := range findings {
		if r := checkFinding(f.File, f.Line, f.Pattern, entries); r.suppressed {
			suppressed = append(suppressed, f)
			reasons = append(reasons, r)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed, reasons
}

// printSuppressed writes a single SUPPRESSED line in verbose format.
func printSuppressed(w io.Writer, file string, line int, pattern string, r suppressResult) {
	loc := file
	if line > 0 {
		loc = fmt.Sprintf("%s:%d", file, line)
	}
	switch r.source {
	case suppressSourceInline:
		_, _ = fmt.Fprintf(w, "SUPPRESSED: %s  %s (inline)\n", loc, pattern)
	case suppressSourceConfig:
		if r.reason != "" {
			_, _ = fmt.Fprintf(w, "SUPPRESSED: %s  %s (config: %q)\n", loc, pattern, r.reason)
		} else {
			_, _ = fmt.Fprintf(w, "SUPPRESSED: %s  %s (config)\n", loc, pattern)
		}
	}
}

// printSuppressedGit writes suppressed git findings to w in verbose format.
func printSuppressedGit(w io.Writer, suppressed []gitprotect.Finding, reasons []suppressResult) {
	for i, f := range suppressed {
		printSuppressed(w, f.File, f.Line, f.Pattern, reasons[i])
	}
}

// printSuppressedProject writes suppressed project findings to w in verbose format.
func printSuppressedProject(w io.Writer, suppressed []projectscan.Finding, reasons []suppressResult) {
	for i, f := range suppressed {
		printSuppressed(w, f.File, f.Line, f.Pattern, reasons[i])
	}
}

// readSourceLine reads a specific line number from a file.
// Returns an empty string if the file doesn't exist or the line is out of range.
func readSourceLine(path string, line int) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path from finding, not user input
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	current := 0
	for scanner.Scan() {
		current++
		if current == line {
			return scanner.Text(), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("line %d out of range (file has %d lines)", line, current)
}
