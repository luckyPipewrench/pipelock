// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package skillscan

import (
	"regexp"
	"sort"
	"strings"
)

var capabilityPatterns = []struct {
	kind    CapabilityKind
	pattern *regexp.Regexp
	label   string
}{
	{CapabilityNetworkSink, regexp.MustCompile(`(?i)\b(curl|wget|http)\b.*https?://|fetch\s*\(\s*['"]https?://|requests\.(get|post|put|delete)\s*\(\s*['"]https?://|https?://`), "network egress"},
	{CapabilityFilesystemWrite, regexp.MustCompile(`(?i)(>\s*[^&]|>>|tee\s+|os\.WriteFile|writeFile\s*\(|open\s*\([^,\n]+,\s*['"][wa])`), "filesystem write"},
	{CapabilityExecSubprocess, regexp.MustCompile(`(?i)\b(bash|sh|zsh)\s+-c\b|subprocess\.|os\.system\s*\(|child_process|exec\s*\(`), "subprocess execution"},
	{CapabilityEnvRead, regexp.MustCompile(`(?i)\$[A-Z][A-Z0-9_]{2,}|os\.environ|process\.env|getenv\s*\(`), "environment read"},
	{CapabilitySecretRead, credentialSourcePattern, "secret reference"},
	{CapabilityClipboardRead, clipboardSourcePattern, "clipboard read"},
	{CapabilityDependencyPull, dependencyInstallPattern, "dependency install"},
}

var (
	dependencyInstallPattern = regexp.MustCompile(`(?i)\b(pip\s+install|npm\s+install|uvx|npx|pnpm\s+add|yarn\s+add)\b`)
	pinnedVersionPattern     = regexp.MustCompile(`@[0-9]+\.[0-9]+`)
)

func buildSkill(input skillInput, includeDeps bool) Skill {
	caps := inventoryCapabilities(input, includeDeps)
	return Skill{
		ID:              input.id,
		Path:            input.path,
		SizeBytes:       input.info.Size(),
		ContentSHA256:   sha256Hex(input.content),
		ReferencedFiles: input.refFiles,
		Capabilities:    caps,
		ScannedFiles:    input.scanFiles,
	}
}

func inventoryCapabilities(input skillInput, includeDeps bool) []Capability {
	byKind := map[CapabilityKind][]Evidence{}
	for _, file := range input.files {
		for lineNo, line := range file.lines {
			for _, rule := range capabilityPatterns {
				if rule.kind == CapabilityDependencyPull && !includeDeps {
					continue
				}
				if !rule.pattern.MatchString(line) {
					continue
				}
				ev := Evidence{Path: file.path, Line: lineNo + 1, Pattern: rule.label}
				if rule.kind == CapabilityDependencyPull && hasPinnedDependency(line) {
					ev.Pattern = "pinned dependency install"
				}
				byKind[rule.kind] = appendEvidence(byKind[rule.kind], ev)
			}
		}
	}
	var kinds []string
	for kind := range byKind {
		kinds = append(kinds, string(kind))
	}
	sort.Strings(kinds)
	out := make([]Capability, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, Capability{Kind: CapabilityKind(kind), Evidence: byKind[CapabilityKind(kind)]})
	}
	return out
}

func capabilitySummary(skill Skill) []string {
	var summary []string
	for _, cap := range skill.Capabilities {
		summary = append(summary, string(cap.Kind))
	}
	sort.Strings(summary)
	return summary
}

func appendEvidence(evidence []Evidence, ev Evidence) []Evidence {
	for _, existing := range evidence {
		if existing.Path == ev.Path && existing.Line == ev.Line && existing.Pattern == ev.Pattern {
			return evidence
		}
	}
	return append(evidence, ev)
}

func hasPinnedDependency(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "==") ||
		strings.Contains(lower, "@sha256:") ||
		strings.Contains(lower, "--require-hashes") ||
		strings.Contains(lower, "npm ci") ||
		pinnedVersionPattern.MatchString(lower)
}
