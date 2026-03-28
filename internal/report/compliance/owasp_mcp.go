// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// OWASPMCPTop10 returns the OWASP MCP Top 10 mapping.
func OWASPMCPTop10() Framework {
	return Framework{
		ID:             "owasp_mcp_top_10",
		Name:           "OWASP MCP Top 10",
		Version:        "2025",
		MappingVersion: 1,
		URL:            "https://owasp.org/www-project-mcp-top-10/",
		Controls: []ControlMapping{
			{
				ID:       "MCP01",
				Name:     "Token Mismanagement & Secret Exposure",
				Status:   StatusCovered,
				Features: []string{"dlp", "env_leak", "canary_tokens"},
				Evidence: "DLP scanners and canary tokens detect secrets in outbound text, URLs, and environment leaks.",
			},
			{
				ID:       "MCP02",
				Name:     "Privilege Escalation via Scope Creep",
				Status:   StatusCovered,
				Features: []string{"agents", "session_profiling", "tool_policy"},
				Evidence: "Agent profiles, session profiling, and tool policy rules constrain privilege expansion.",
			},
			{
				ID:       "MCP03",
				Name:     "Tool Poisoning",
				Status:   StatusCovered,
				Features: []string{"mcp_tool_scanning", "mcp_tool_provenance", "behavioral_baseline"},
				Evidence: "Tool scanning detects poisoned descriptions, provenance verifies signatures, baseline detects drift.",
			},
			{
				ID:       "MCP04",
				Name:     "Software Supply Chain Attacks & Dependency Tampering",
				Status:   StatusCovered,
				Features: []string{"mcp_binary_integrity", "mcp_tool_provenance"},
				Evidence: "Binary integrity verifies subprocess hashes, tool provenance verifies Ed25519/Sigstore signatures.",
			},
			{
				ID:       "MCP05",
				Name:     "Command Injection & Execution",
				Status:   StatusCovered,
				Features: []string{"mcp_tool_policy", "sandbox"},
				Evidence: "Tool policy blocks dangerous tool calls, sandbox contains subprocess execution.",
			},
			{
				ID:       "MCP06",
				Name:     "Prompt Injection via Contextual Payloads",
				Status:   StatusCovered,
				Features: []string{"response_scanning", "mcp_input_scanning"},
				Evidence: "Bidirectional MCP scanning with 6-pass normalization detects injection in responses and tool args.",
			},
			{
				ID:         "MCP07",
				Name:       "Insufficient Authentication & Authorization",
				Status:     StatusPartial,
				Features:   []string{"agents", "mcp_session_binding"},
				Evidence:   "Agent profiles enforce per-agent policy, session binding pins tool inventories.",
				Limitation: "Org-wide authentication and authorization governance is a deployment concern.",
			},
			{
				ID:       "MCP08",
				Name:     "Lack of Audit and Telemetry",
				Status:   StatusCovered,
				Features: []string{"flight_recorder", "emit", "metrics"},
				Evidence: "Flight recorder produces hash-chained evidence, emit delivers to webhook/syslog/OTLP, Prometheus metrics.",
			},
			{
				ID:         "MCP09",
				Name:       "Shadow MCP Servers",
				Status:     StatusPartial,
				Features:   []string{"discover"},
				Evidence:   "Discovery surfaces unprotected MCP servers on the system.",
				Limitation: "Org-wide registry and approval workflow for MCP servers is not enforced by the proxy.",
			},
			{
				ID:       "MCP10",
				Name:     "Context Injection & Over-Sharing",
				Status:   StatusCovered,
				Features: []string{"response_scanning", "mcp_input_scanning", "flight_recorder"},
				Evidence: "Bidirectional scanning detects context injection, flight recorder provides forensic evidence.",
			},
		},
	}
}
