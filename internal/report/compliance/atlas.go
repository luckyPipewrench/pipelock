// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// MITREATLAS returns a compact ATLAS mapping derived from Zenity's
// collaboration updates and adjacent agentic techniques.
func MITREATLAS() Framework {
	return Framework{
		ID:             "mitre_atlas",
		Name:           "MITRE ATLAS",
		Version:        "2025-2026",
		MappingVersion: 1,
		URL:            "https://atlas.mitre.org/",
		Controls: []ControlMapping{
			{
				ID:       "ATLAS01",
				Name:     "Gather RAG-Indexed Targets",
				Status:   StatusCovered,
				Features: []string{"discover", "dlp"},
				Evidence: "Discovery and normalized-text scanning expose RAG target harvesting.",
			},
			{
				ID:       "ATLAS02",
				Name:     "Discover LLM System Information",
				Status:   StatusCovered,
				Features: []string{"simulate", "assess", "flight_recorder"},
				Evidence: "Replayed assessments and simulation traces expose leaked system details.",
			},
			{
				ID:       "ATLAS03",
				Name:     "Special Character Sets",
				Status:   StatusCovered,
				Features: []string{"dlp", "response_scanning"},
				Evidence: "Canonicalized scans catch delimiter and control-character probing.",
			},
			{
				ID:       "ATLAS04",
				Name:     "System Instruction Keywords",
				Status:   StatusCovered,
				Features: []string{"response_scanning", "tool_policy"},
				Evidence: "Prompt scanning and tool policy inspection surface instruction-keyword discovery.",
			},
			{
				ID:       "ATLAS05",
				Name:     "LLM Prompt Crafting",
				Status:   StatusCovered,
				Features: []string{"simulate"},
				Evidence: "Red-team chains exercise prompt crafting bypasses.",
			},
			{
				ID:       "ATLAS06",
				Name:     "Retrieval Content Crafting",
				Status:   StatusCovered,
				Features: []string{"response_scanning"},
				Evidence: "Content scanning catches crafted retrieval payloads.",
			},
			{
				ID:         "ATLAS07",
				Name:       "RAG Poisoning",
				Status:     StatusPartial,
				Features:   []string{"response_scanning", "simulate", "attestation"},
				Evidence:   "Detection and replay help, but source data curation is still external.",
				Limitation: "External corpus ownership is outside Pipelock's control plane.",
			},
			{
				ID:       "ATLAS08",
				Name:     "LLM Prompt Obfuscation",
				Status:   StatusCovered,
				Features: []string{"dlp", "response_scanning"},
				Evidence: "Normalized scanning detects hidden or obfuscated instruction payloads.",
			},
			{
				ID:         "ATLAS09",
				Name:       "LLM Trusted Output Components Manipulation",
				Status:     StatusPartial,
				Features:   []string{"attestation", "assess"},
				Evidence:   "Signed evidence reduces trust abuse, but final user trust decisions are external.",
				Limitation: "Consumer-side trust interpretation is not enforceable in-binary.",
			},
			{
				ID:         "ATLAS10",
				Name:       "Citation Manipulation",
				Status:     StatusPartial,
				Features:   []string{"attestation", "assess"},
				Evidence:   "Attested evidence can surface manipulated citations, but source validation is partial.",
				Limitation: "Citation correctness depends on upstream retrieval sources.",
			},
			{
				ID:         "ATLAS11",
				Name:       "False RAG Entry Injection",
				Status:     StatusPartial,
				Features:   []string{"response_scanning", "discover", "simulate"},
				Evidence:   "Detection surfaces injected entries, but source-system prevention is upstream.",
				Limitation: "Corpus write paths are not owned by the proxy.",
			},
			{
				ID:       "ATLAS12",
				Name:     "Data-Structure Injection",
				Status:   StatusCovered,
				Features: []string{"tool_policy", "mcp_tool_policy", "dlp"},
				Evidence: "Structured input validation and policy enforcement catch schema exploitation.",
			},
			{
				ID:       "ATLAS13",
				Name:     "Structured Self-Modeling",
				Status:   StatusCovered,
				Features: []string{"simulate"},
				Evidence: "Dry-run and simulation make structured prompt manipulation easier to validate.",
			},
			{
				ID:         "ATLAS14",
				Name:       "Agent Backdoor Persistence",
				Status:     StatusPartial,
				Features:   []string{"flight_recorder", "attestation", "hitl"},
				Evidence:   "Replay and human review help surface persistence, but long-lived agent control is external.",
				Limitation: "Persistent agent state and scheduler control are not fully governed by the proxy.",
			},
		},
	}
}
