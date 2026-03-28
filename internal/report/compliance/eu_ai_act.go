// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// EUAIAct returns a compact EU AI Act mapping focused on record-keeping and
// deployer monitoring obligations.
func EUAIAct() Framework {
	return Framework{
		ID:             "eu_ai_act",
		Name:           "EU AI Act",
		Version:        "2024/1689",
		MappingVersion: 1,
		URL:            "https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng",
		Controls: []ControlMapping{
			{
				ID:       "A12",
				Name:     "Article 12 - Record-Keeping",
				Status:   StatusCovered,
				Features: []string{"flight_recorder", "attestation"},
				Evidence: "Replayable records and signed manifests support record-keeping.",
			},
			{
				ID:         "A13",
				Name:       "Article 13 - Transparency and Instructions",
				Status:     StatusPartial,
				Features:   []string{"assess"},
				Evidence:   "Reports and badges surface operational posture, but user instructions are deployment-specific.",
				Limitation: "Provider-facing documentation is only partly represented in the binary.",
			},
			{
				ID:       "A14",
				Name:     "Article 14 - Human Oversight",
				Status:   StatusCovered,
				Features: []string{"hitl", "simulate"},
				Evidence: "Human-in-the-loop approvals and dry-run testing support oversight.",
			},
			{
				ID:       "A26",
				Name:     "Article 26 - Deployer Monitoring",
				Status:   StatusCovered,
				Features: []string{"assess", "flight_recorder", "emit"},
				Evidence: "Assess outputs and recorded telemetry support deployer monitoring obligations.",
			},
		},
	}
}
