// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// OWASPAgenticTop10 returns the OWASP Agentic Top 10 mapping.
func OWASPAgenticTop10() Framework {
	return Framework{
		ID:             frameworkOWASPAgenticTop10,
		Name:           "OWASP Agentic Top 10",
		Version:        "2026",
		MappingVersion: 1,
		URL:            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
		Controls: []ControlMapping{
			{
				ID:       "ASI01",
				Name:     "Agent Goal Hijack",
				Status:   StatusCovered,
				Features: []string{featureResponseScanning, featureSimulate, featureCanaryTokens},
				Evidence: "Response injection scanning with 6-pass normalization catches goal-hijack attempts.",
			},
			{
				ID:       "ASI02",
				Name:     "Tool Misuse and Exploitation",
				Status:   StatusCovered,
				Features: []string{featureMCPToolPolicy, featureSandbox, featureHITL},
				Evidence: "Tool policy rules block dangerous calls, sandbox contains execution, HITL requires approval.",
			},
			{
				ID:         "ASI03",
				Name:       "Identity and Privilege Abuse",
				Status:     StatusPartial,
				Features:   []string{featureAgents, featureMCPSessionBinding},
				Evidence:   "Per-agent profiles enforce least-privilege policy, session binding pins tool inventories.",
				Limitation: "Identity lifecycle and credential revocation remain deployment concerns.",
			},
			{
				ID:       "ASI04",
				Name:     "Agentic Supply Chain Vulnerabilities",
				Status:   StatusCovered,
				Features: []string{featureMCPBinaryIntegrity, featureMCPToolProvenance},
				Evidence: "Binary integrity verifies subprocess hashes, tool provenance checks Ed25519 signatures.",
			},
			{
				ID:       "ASI05",
				Name:     "Unexpected Code Execution (RCE)",
				Status:   StatusCovered,
				Features: []string{featureSandbox, featureMCPToolPolicy},
				Evidence: "Landlock/seccomp sandbox contains processes, tool policy blocks shell execution patterns.",
			},
			{
				ID:         "ASI06",
				Name:       "Memory & Context Poisoning",
				Status:     StatusPartial,
				Features:   []string{featureResponseScanning, featureFlightRecorder},
				Evidence:   "Response scanning detects injection payloads, flight recorder preserves forensic evidence.",
				Limitation: "Cross-agent contamination tracking is not yet implemented.",
			},
			{
				ID:         "ASI07",
				Name:       "Insecure Inter-Agent Communication",
				Status:     StatusPartial,
				Features:   []string{featureResponseScanning, featureMCPInputScanning},
				Evidence:   "Bidirectional MCP scanning covers content flowing between agents through the proxy.",
				Limitation: "A2A protocol scanning not yet implemented; direct agent-to-agent bypasses proxy.",
			},
			{
				ID:         "ASI08",
				Name:       "Cascading Failures",
				Status:     StatusPartial,
				Features:   []string{featureSimulate, featureAdaptiveEnforcement, featureMetrics},
				Evidence:   "Simulation tests detection, adaptive enforcement escalates on threat accumulation.",
				Limitation: "Fleet-wide containment and failover policies are deployment concerns.",
			},
			{
				ID:         "ASI09",
				Name:       "Human-Agent Trust Exploitation",
				Status:     StatusPartial,
				Features:   []string{featureHITL, featureKillSwitch},
				Evidence:   "HITL approval and kill switch provide operator override points.",
				Limitation: "Human review behavior is outside binary enforcement.",
			},
			{
				ID:         "ASI10",
				Name:       "Rogue Agents",
				Status:     StatusNotCovered,
				Features:   []string{featureDiscover},
				Evidence:   "Discovery surfaces unprotected MCP servers on the local system.",
				Limitation: "External runtimes and shadow deployments require org-level control.",
			},
		},
	}
}
