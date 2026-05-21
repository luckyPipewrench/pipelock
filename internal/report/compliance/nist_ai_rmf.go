// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// NISTAIRMF returns a compact NIST AI Risk Management Framework (AI RMF 1.0)
// mapping. Source: NIST AI 100-1, January 2023, with the Generative AI
// Profile (NIST AI 600-1, July 2024) overlay where relevant.
//
// Coverage status reflects what the Pipelock proxy can mediate at runtime;
// risk-management governance (Map/Govern functions) is a deployment and
// process activity that the binary supports but cannot prove on its own.
func NISTAIRMF() Framework {
	return Framework{
		ID:             "nist_ai_rmf",
		Name:           "NIST AI RMF",
		Version:        "1.0",
		MappingVersion: 1,
		URL:            "https://www.nist.gov/itl/ai-risk-management-framework",
		Controls: []ControlMapping{
			{
				ID:         "GOVERN",
				Name:       "Govern",
				Status:     StatusPartial,
				Features:   []string{"emit", "flight_recorder", "attestation"},
				Evidence:   "Audit emission, tamper-evident flight recorder, and signed attestation bundles supply the artifacts a governance program records against AI RMF Govern outcomes.",
				Limitation: "Governance roles, RACI, and policy approval workflows live with the operator.",
			},
			{
				ID:         "MAP",
				Name:       "Map",
				Status:     StatusPartial,
				Features:   []string{"discover", "audit", "assess"},
				Evidence:   "Discover enumerates MCP servers and their protection state; audit and assess produce a per-deployment posture map of what is reachable, what is contained, and what is unprotected.",
				Limitation: "Stakeholder identification and impact classification remain process steps.",
			},
			{
				ID:       "MEASURE",
				Name:     "Measure",
				Status:   StatusCovered,
				Features: []string{"simulate", "assess", "metrics", "flight_recorder"},
				Evidence: "Simulate scenarios produce repeatable detection-coverage measurements; assess scores per-deployment posture across 4 weighted sections; Prometheus metrics and the flight recorder provide ongoing operational measurement.",
			},
			{
				ID:       "MANAGE",
				Name:     "Manage",
				Status:   StatusCovered,
				Features: []string{"forward_proxy", "mcp_tool_policy", "kill_switch", "adaptive_enforcement", "learn_lock"},
				Evidence: "Forward proxy and MCP tool policy enforce per-agent action limits; kill switch and adaptive enforcement contain in-progress incidents; live-lock contracts gate drift from a promoted baseline.",
			},
			{
				ID:       "GENAI_DATA",
				Name:     "Generative AI: Data Privacy",
				Status:   StatusCovered,
				Features: []string{"dlp", "redaction", "request_body_scanning", "address_protection", "seed_phrase_detection"},
				Evidence: "Class-preserving redaction protects PII/PHI in provider payloads; DLP, request-body scanning, and address/seed-phrase detectors prevent inadvertent disclosure to upstream models.",
			},
			{
				ID:       "GENAI_INTEGRITY",
				Name:     "Generative AI: Information Integrity",
				Status:   StatusCovered,
				Features: []string{"response_scanning", "mcp_tool_scanning", "browser_shield", "mcp_session_binding", "tool_chain_detection"},
				Evidence: "Response scanning catches prompt injection in tool results; MCP tool scanning + session binding detect poisoned descriptions and rug-pull drift; browser shield strips DOM traps from fetched pages.",
			},
			{
				ID:         "GENAI_PROVENANCE",
				Name:       "Generative AI: Provenance",
				Status:     StatusPartial,
				Features:   []string{"mediation_envelope", "flight_recorder", "mcp_binary_integrity", "mcp_tool_provenance"},
				Evidence:   "Mediation envelope signs outbound mediated requests (RFC 9421); flight recorder produces tamper-evident decision evidence; MCP binary-integrity manifest binds tool execution to a known binary.",
				Limitation: "Upstream model provenance is out of scope; Pipelock attests its own mediation, not the model's training data lineage.",
			},
			{
				ID:         "GENAI_HARMFUL",
				Name:       "Generative AI: Harmful Bias",
				Status:     StatusNotCovered,
				Features:   nil,
				Evidence:   "",
				Limitation: "Bias evaluation belongs to model selection and red-team programs upstream of network mediation.",
			},
		},
	}
}
