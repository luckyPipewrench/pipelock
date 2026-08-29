// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capabilitymanifest

import (
	"fmt"
	"strings"
)

const (
	AgentsSectionStart = "<!-- BEGIN capability-manifest (generated; run go generate ./internal/capabilitymanifest) -->"
	AgentsSectionEnd   = "<!-- END capability-manifest -->"
)

// RenderAgentsSection renders the exact generated block in AGENTS.md.
func RenderAgentsSection(manifest Manifest) string {
	var out strings.Builder
	out.WriteString(AgentsSectionStart)
	out.WriteString("\n\n## Capability surface\n\n")
	out.WriteString("The code-checked capability manifest is docs/security/capability-manifest.json. It lists the operator entry point and license gate for each surface below. Free means no license feature is required.\n\n")
	out.WriteString("| Capability | Access | Operator entry point |\n")
	out.WriteString("|---|---|---|\n")
	for _, capability := range manifest.Capabilities {
		fmt.Fprintf(&out, "| %s | %s | %s |\n", capability.Name, capability.Tier, capability.OperatorEntryPoint.Value)
	}
	out.WriteString("\n")
	out.WriteString(AgentsSectionEnd)
	out.WriteString("\n")
	return out.String()
}

// ReplaceAgentsSection replaces one generated block and rejects a missing or
// duplicated marker pair instead of guessing where generated text belongs.
func ReplaceAgentsSection(agents string, section string) (string, error) {
	start := strings.Index(agents, AgentsSectionStart)
	end := strings.Index(agents, AgentsSectionEnd)
	if start < 0 || end < 0 || end < start {
		return "", fmt.Errorf("AGENTS.md capability-manifest markers are missing or malformed")
	}
	if strings.Count(agents, AgentsSectionStart) != 1 || strings.Count(agents, AgentsSectionEnd) != 1 {
		return "", fmt.Errorf("AGENTS.md must contain exactly one capability-manifest marker pair")
	}
	end += len(AgentsSectionEnd)
	if end < len(agents) && agents[end] == '\n' {
		end++
	}
	return agents[:start] + section + agents[end:], nil
}
