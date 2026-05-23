// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// SOC2TSC returns a compact SOC 2 Trust Services Criteria mapping.
func SOC2TSC() Framework {
	return Framework{
		ID:             frameworkSOC2TSC,
		Name:           "SOC 2 Trust Services Criteria",
		Version:        "2025",
		MappingVersion: 1,
		URL:            "https://www.aicpa-cima.com/resources/article/trust-services-criteria",
		Controls: []ControlMapping{
			{
				ID:       "SEC",
				Name:     "Security",
				Status:   StatusCovered,
				Features: []string{featureForwardProxy, featureMCPInputScanning, featureDLP, featureEmit},
				Evidence: "Proxy enforcement, MCP scanning, and structured audit logs support security controls.",
			},
			{
				ID:         "AVA",
				Name:       "Availability",
				Status:     StatusPartial,
				Features:   []string{featureMetrics, featureSimulate},
				Evidence:   "Metrics and health endpoints aid availability monitoring.",
				Limitation: "Capacity planning and SLAs remain deployment-specific.",
			},
			{
				ID:       "PI",
				Name:     "Processing Integrity",
				Status:   StatusCovered,
				Features: []string{featureFlightRecorder, featureAttestation, featureSigning},
				Evidence: "Recorded evidence and verification flows preserve processing integrity.",
			},
			{
				ID:       "CONF",
				Name:     "Confidentiality",
				Status:   StatusCovered,
				Features: []string{featureDLP, featureFlightRecorder, featureCanaryTokens},
				Evidence: "DLP and redaction controls protect confidential information in transit and at rest.",
			},
			{
				ID:         "PRIV",
				Name:       "Privacy",
				Status:     StatusPartial,
				Features:   []string{featureSimulate, featureAssess},
				Evidence:   "Policy testing helps identify privacy gaps.",
				Limitation: "Data subject workflows and retention policy remain outside the proxy.",
			},
		},
	}
}
