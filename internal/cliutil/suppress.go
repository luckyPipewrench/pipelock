// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

// Suppression source constants for SuppressResult.
const (
	SuppressSourceInline = "inline"
	SuppressSourceConfig = "config"
)

// SuppressRe matches inline suppression comments.
// Supports // and # comment styles. The optional capture group
// holds the rule name; when absent, all rules on that line are suppressed.
var SuppressRe = regexp.MustCompile(`(?://|#)\s*pipelock:ignore(?:\s+(.+?))?\s*$`)

// SuppressResult describes why a finding was suppressed.
type SuppressResult struct {
	Suppressed bool
	Source     string // SuppressSourceInline or SuppressSourceConfig
	Reason     string // config reason or rule name for inline
}

// CheckInlineSuppression reads a source line from disk and checks for a
// pipelock:ignore comment. Returns whether the finding's rule is suppressed.
func CheckInlineSuppression(file string, line int, rule string) SuppressResult {
	if file == "" || line <= 0 {
		return SuppressResult{}
	}

	src, err := ReadSourceLine(file, line)
	if err != nil {
		return SuppressResult{}
	}

	m := SuppressRe.FindStringSubmatch(src)
	if m == nil {
		return SuppressResult{}
	}

	// m[1] is the optional rule name after pipelock:ignore.
	// Empty means suppress all rules on this line.
	ignoreRule := strings.TrimSpace(m[1])
	if ignoreRule == "" || strings.EqualFold(ignoreRule, rule) {
		return SuppressResult{Suppressed: true, Source: SuppressSourceInline}
	}

	return SuppressResult{}
}

// CheckConfigSuppression checks whether a finding matches any config suppress entry.
func CheckConfigSuppression(file string, rule string, entries []config.SuppressEntry) SuppressResult {
	if file == "" || len(entries) == 0 {
		return SuppressResult{}
	}

	reason, ok := config.SuppressedReason(rule, file, entries)
	if ok {
		return SuppressResult{
			Suppressed: true,
			Source:     SuppressSourceConfig,
			Reason:     reason,
		}
	}

	return SuppressResult{}
}

// CheckFinding runs the inline → config suppression pipeline for a single finding.
func CheckFinding(file string, line int, pattern string, entries []config.SuppressEntry) SuppressResult {
	if r := CheckInlineSuppression(file, line, pattern); r.Suppressed {
		return r
	}
	return CheckConfigSuppression(file, pattern, entries)
}

// SuppressGitFindings filters gitprotect findings through inline and config
// suppression. Returns the kept findings and suppressed findings.
func SuppressGitFindings(findings []gitprotect.Finding, entries []config.SuppressEntry) (kept, suppressed []gitprotect.Finding, reasons []SuppressResult) {
	for _, f := range findings {
		if r := CheckFinding(f.File, f.Line, f.Pattern, entries); r.Suppressed {
			suppressed = append(suppressed, f)
			reasons = append(reasons, r)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed, reasons
}

// SuppressProjectFindings filters projectscan findings through inline and config
// suppression. Returns the kept findings and suppressed findings.
// An optional baseDir joins with relative finding paths so inline suppression
// can open source files when the process CWD differs from the scan root.
func SuppressProjectFindings(findings []projectscan.Finding, entries []config.SuppressEntry, baseDir ...string) (kept, suppressed []projectscan.Finding, reasons []SuppressResult) {
	base := ""
	if len(baseDir) > 0 {
		base = baseDir[0]
	}
	for _, f := range findings {
		filePath := f.File
		if base != "" && filePath != "" && !filepath.IsAbs(filePath) {
			filePath = filepath.Join(base, filePath)
		}
		if r := CheckFinding(filePath, f.Line, f.Pattern, entries); r.Suppressed {
			suppressed = append(suppressed, f)
			reasons = append(reasons, r)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed, reasons
}

// PrintSuppressed writes a single SUPPRESSED line in verbose format.
func PrintSuppressed(w io.Writer, file string, line int, pattern string, r SuppressResult) {
	loc := file
	if line > 0 {
		loc = fmt.Sprintf("%s:%d", file, line)
	}
	switch r.Source {
	case SuppressSourceInline:
		_, _ = fmt.Fprintf(w, "SUPPRESSED: %s  %s (inline)\n", loc, pattern)
	case SuppressSourceConfig:
		if r.Reason != "" {
			_, _ = fmt.Fprintf(w, "SUPPRESSED: %s  %s (config: %q)\n", loc, pattern, r.Reason)
		} else {
			_, _ = fmt.Fprintf(w, "SUPPRESSED: %s  %s (config)\n", loc, pattern)
		}
	}
}

// PrintSuppressedGit writes suppressed git findings to w in verbose format.
func PrintSuppressedGit(w io.Writer, suppressed []gitprotect.Finding, reasons []SuppressResult) {
	for i, f := range suppressed {
		PrintSuppressed(w, f.File, f.Line, f.Pattern, reasons[i])
	}
}

// PrintSuppressedProject writes suppressed project findings to w in verbose format.
func PrintSuppressedProject(w io.Writer, suppressed []projectscan.Finding, reasons []SuppressResult) {
	for i, f := range suppressed {
		PrintSuppressed(w, f.File, f.Line, f.Pattern, reasons[i])
	}
}

// ReadSourceLine reads a specific line number from a file.
// Returns an empty string if the file doesn't exist or the line is out of range.
func ReadSourceLine(path string, line int) (string, error) {
	f, err := os.Open(filepath.Clean(path))
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
