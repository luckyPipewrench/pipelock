// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// SOC2TSC returns a compact SOC 2 Trust Services Criteria mapping.
func SOC2TSC() Framework {
	return Framework{
		ID:             "soc2_tsc",
		Name:           "SOC 2 Trust Services Criteria",
		Version:        "2025",
		MappingVersion: 1,
		URL:            "https://www.aicpa-cima.com/resources/article/trust-services-criteria",
		Controls: []ControlMapping{
			{
				ID:       "SEC",
				Name:     "Security",
				Status:   StatusCovered,
				Features: []string{"forward_proxy", "mcp_input_scanning", "dlp", "emit"},
				Evidence: "Proxy enforcement, MCP scanning, and structured audit logs support security controls.",
			},
			{
				ID:         "AVA",
				Name:       "Availability",
				Status:     StatusPartial,
				Features:   []string{"metrics", "simulate", "metrics"},
				Evidence:   "Metrics and health endpoints aid availability monitoring.",
				Limitation: "Capacity planning and SLAs remain deployment-specific.",
			},
			{
				ID:       "PI",
				Name:     "Processing Integrity",
				Status:   StatusCovered,
				Features: []string{"flight_recorder", "attestation", "signing"},
				Evidence: "Recorded evidence and verification flows preserve processing integrity.",
			},
			{
				ID:       "CONF",
				Name:     "Confidentiality",
				Status:   StatusCovered,
				Features: []string{"dlp", "flight_recorder", "canary_tokens"},
				Evidence: "DLP and redaction controls protect confidential information in transit and at rest.",
			},
			{
				ID:         "PRIV",
				Name:       "Privacy",
				Status:     StatusPartial,
				Features:   []string{"simulate", "assess"},
				Evidence:   "Policy testing helps identify privacy gaps.",
				Limitation: "Data subject workflows and retention policy remain outside the proxy.",
			},
		},
	}
}
