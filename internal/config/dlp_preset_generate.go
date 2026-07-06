// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type dlpPresetTarget struct {
	Path    string
	Profile string
}

var dlpPresetTargets = []dlpPresetTarget{
	{Path: filepath.Join("configs", "audit.yaml"), Profile: DLPPresetProfileFull},
	{Path: filepath.Join("configs", "balanced.yaml"), Profile: DLPPresetProfileFull},
	{Path: filepath.Join("configs", "claude-code.yaml"), Profile: DLPPresetProfileFull},
	{Path: filepath.Join("configs", "cursor.yaml"), Profile: DLPPresetProfileFull},
	{Path: filepath.Join("configs", "generic-agent.yaml"), Profile: DLPPresetProfileFull},
	{Path: filepath.Join("configs", "strict.yaml"), Profile: DLPPresetProfileFull},
	{Path: filepath.Join("configs", "hostile-model.yaml"), Profile: DLPPresetProfileHostile},
	{Path: filepath.Join("examples", "quickstart", "pipelock.yaml"), Profile: DLPPresetProfileQuickstart},
}

// GenerateDLPPresetFiles reconciles shipped preset YAML dlp.patterns blocks
// against the canonical pattern registry and profile deltas.
func GenerateDLPPresetFiles(root string, write bool) (string, error) {
	var out strings.Builder
	updated := 0
	for _, target := range dlpPresetTargets {
		expected, err := PresetDLPPatterns(target.Profile)
		if err != nil {
			return "", fmt.Errorf("%s: %w", target.Path, err)
		}
		path := filepath.Join(root, target.Path)
		raw, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return "", fmt.Errorf("read %s: %w", target.Path, err)
		}
		got, err := parseYAMLDLPPatterns(raw)
		if err != nil {
			return "", fmt.Errorf("%s: %w", target.Path, err)
		}
		if diff := compareDLPPatternSets(got, expected); diff != "" {
			if !write {
				return "", fmt.Errorf("%s: %s", target.Path, diff)
			}
			rewritten, rewriteErr := rewriteDLPPatternBlock(raw, expected)
			if rewriteErr != nil {
				return "", fmt.Errorf("%s: %w", target.Path, rewriteErr)
			}
			if !bytes.Equal(raw, rewritten) {
				if writeErr := os.WriteFile(filepath.Clean(path), rewritten, 0o600); writeErr != nil {
					return "", fmt.Errorf("write %s: %w", target.Path, writeErr)
				}
				updated++
				fmt.Fprintf(&out, "updated %s (%s): %d patterns\n", target.Path, target.Profile, len(expected))
			}
			continue
		}
		fmt.Fprintf(&out, "checked %s (%s): %d patterns in sync\n", target.Path, target.Profile, len(expected))
	}
	fmt.Fprintf(&out, "DLP preset generation complete: %d files checked, %d updated\n", len(dlpPresetTargets), updated)
	return out.String(), nil
}

func parseYAMLDLPPatterns(raw []byte) ([]DLPPattern, error) {
	var doc struct {
		DLP struct {
			Patterns []DLPPattern `yaml:"patterns"`
		} `yaml:"dlp"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if len(doc.DLP.Patterns) == 0 {
		return nil, fmt.Errorf("dlp.patterns is empty or missing")
	}
	return doc.DLP.Patterns, nil
}

func compareDLPPatternSets(got, want []DLPPattern) string {
	if len(got) != len(want) {
		return fmt.Sprintf("pattern count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name {
			return fmt.Sprintf("pattern[%d].name = %q, want %q", i, got[i].Name, want[i].Name)
		}
		if got[i].Regex != want[i].Regex {
			return fmt.Sprintf("%s regex drifted: got %q, want %q", got[i].Name, got[i].Regex, want[i].Regex)
		}
		if got[i].Severity != want[i].Severity {
			return fmt.Sprintf("%s severity drifted: got %q, want %q", got[i].Name, got[i].Severity, want[i].Severity)
		}
		if got[i].Validator != want[i].Validator {
			return fmt.Sprintf("%s validator drifted: got %q, want %q", got[i].Name, got[i].Validator, want[i].Validator)
		}
		if !sameStrings(got[i].ExemptDomains, want[i].ExemptDomains) {
			return fmt.Sprintf("%s exempt_domains drifted: got %q, want %q", got[i].Name, got[i].ExemptDomains, want[i].ExemptDomains)
		}
	}
	return ""
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func rewriteDLPPatternBlock(raw []byte, patterns []DLPPattern) ([]byte, error) {
	lines := strings.SplitAfter(string(raw), "\n")
	patternsLine, err := findDLPPatternsLine(lines)
	if err != nil {
		return nil, err
	}
	patternsIndent := leadingSpaceCount(lines[patternsLine])
	blockEnd := len(lines)
	for i := patternsLine + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed != "" && leadingSpaceCount(lines[i]) <= patternsIndent {
			blockEnd = i
			break
		}
	}

	var out strings.Builder
	for _, line := range lines[:patternsLine+1] {
		out.WriteString(line)
	}
	out.WriteString(renderDLPPatternBlock(patterns, patternsIndent))
	for _, line := range lines[blockEnd:] {
		out.WriteString(line)
	}
	return []byte(out.String()), nil
}

func leadingSpaceCount(line string) int {
	for i := range line {
		if line[i] != ' ' {
			return i
		}
	}
	return len(line)
}

func findDLPPatternsLine(lines []string) (int, error) {
	inDLP := false
	for i, line := range lines {
		if !strings.HasPrefix(line, " ") && strings.TrimSpace(line) == "dlp:" {
			inDLP = true
			continue
		}
		if inDLP && !strings.HasPrefix(line, " ") && strings.TrimSpace(line) != "" {
			break
		}
		if inDLP && strings.TrimSpace(line) == "patterns:" {
			return i, nil
		}
	}
	return -1, fmt.Errorf("dlp.patterns block not found")
}

func renderDLPPatternBlock(patterns []DLPPattern, patternsIndent int) string {
	itemIndent := strings.Repeat(" ", patternsIndent+2)
	fieldIndent := strings.Repeat(" ", patternsIndent+4)
	exemptDomainIndent := strings.Repeat(" ", patternsIndent+6)

	var out strings.Builder
	for _, pattern := range patterns {
		fmt.Fprintf(&out, "%s- name: %q\n", itemIndent, pattern.Name)
		fmt.Fprintf(&out, "%sregex: '%s'\n", fieldIndent, strings.ReplaceAll(pattern.Regex, "'", "''"))
		fmt.Fprintf(&out, "%sseverity: %s\n", fieldIndent, pattern.Severity)
		if pattern.Validator != "" {
			fmt.Fprintf(&out, "%svalidator: %s\n", fieldIndent, pattern.Validator)
		}
		if len(pattern.ExemptDomains) > 0 {
			fmt.Fprintf(&out, "%sexempt_domains:\n", fieldIndent)
			for _, domain := range pattern.ExemptDomains {
				fmt.Fprintf(&out, "%s- %q\n", exemptDomainIndent, domain)
			}
		}
	}
	return out.String()
}
