// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

// HIPAASecurityRule returns a compact HIPAA Security Rule mapping
// (45 CFR Part 164, Subpart C). Scope: Technical Safeguards (164.312)
// that the proxy mediates plus selected Administrative Safeguards
// (164.308) it touches through evidence emission. Physical Safeguards
// (164.310) are out of scope for a network proxy and intentionally
// omitted; physical security of the host running Pipelock is the
// operator's responsibility.
//
// Status reflects what the proxy enforces or what evidence the
// binary produces. Operator workflow (BAAs, training, sanctions)
// remains outside the proxy.
func HIPAASecurityRule() Framework {
	return Framework{
		ID:             frameworkHIPAASecurity,
		Name:           "HIPAA Security Rule",
		Version:        "2024",
		MappingVersion: 1,
		URL:            "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/",
		Controls: []ControlMapping{
			{
				ID:       "AC",
				Name:     "Access Control (164.312(a))",
				Status:   StatusCovered,
				Features: []string{featureForwardProxy, featureMCPToolPolicy, featureAPIAllowlist, featureAgents},
				Evidence: "Forward proxy and MCP tool policy enforce per-agent allowlists; per-agent license profiles restrict who can reach which destinations.",
			},
			{
				ID:       "AUDIT",
				Name:     "Audit Controls (164.312(b))",
				Status:   StatusCovered,
				Features: []string{featureEmit, featureFlightRecorder, featureAttestation},
				Evidence: "Pipelock emits structured audit events for every allow/block/redact decision; the flight recorder writes tamper-evident, optionally Ed25519-signed checkpoints to satisfy the audit-trail safeguard.",
			},
			{
				ID:       "INTEGRITY",
				Name:     "Integrity (164.312(c))",
				Status:   StatusCovered,
				Features: []string{featureMCPBinaryIntegrity, featureMCPToolProvenance, featureSigning, featureFlightRecorder},
				Evidence: "MCP binary-integrity manifests bind tool execution to a known hash; ed25519 signing on attestation and flight-recorder checkpoints prevents undetected alteration of ePHI handling evidence.",
			},
			{
				ID:         "AUTH",
				Name:       "Person or Entity Authentication (164.312(d))",
				Status:     StatusPartial,
				Features:   []string{featureMediationEnvelope, featureAgents, featureLicense},
				Evidence:   "Mediation envelope produces signed receipts that downstream verifiers can attest; per-agent license tokens identify the calling agent in audit emissions.",
				Limitation: "End-user authentication remains the agent platform's responsibility; Pipelock authenticates agents to upstream destinations, not humans to agents.",
			},
			{
				ID:         "TRANS_SEC",
				Name:       "Transmission Security (164.312(e))",
				Status:     StatusPartial,
				Features:   []string{featureForwardProxy, featureTLSInterception, featureRequestBodyScanning, featureRedaction},
				Evidence:   "Forward proxy mediates outbound HTTP(S); optional TLS interception (when configured) scans request bodies for unauthorized PHI disclosure; class-preserving redaction strips configured PHI fields from provider payloads before they leave the boundary.",
				Limitation: "Pipelock does not enforce HTTPS-only outbound by default; both http and https schemes are accepted. Encryption-in-transit enforcement requires a deployment policy (HTTP destinations on the blocklist or an upstream proxy that rejects them).",
			},
			{
				ID:         "EPHI_DLP",
				Name:       "ePHI Disclosure Prevention",
				Status:     StatusPartial,
				Features:   []string{featureDLP, featureRedaction, featureCrossRequestDetection, featureAddressProtection, featureSeedPhraseDetection},
				Evidence:   "DLP detects SSN-shaped identifiers and operator-configured custom PHI patterns; cross-request detection catches identifiers assembled across multiple requests; redaction class-preserves the personal class (SSN, credit-card) in provider bodies.",
				Limitation: "Out-of-the-box patterns do not include MRN, ICD codes, or other PHI-specific identifiers; operators must add `dlp.patterns` entries for the PHI shapes their workload handles.",
			},
			{
				ID:         "BAA",
				Name:       "Business Associate Agreement",
				Status:     StatusNotCovered,
				Features:   nil,
				Evidence:   "",
				Limitation: "BAAs are contractual instruments between covered entities and business associates; Pipelock as a deployed binary is not a party to BAA execution.",
			},
			{
				ID:         "WORKFORCE",
				Name:       "Workforce Security (164.308(a)(3))",
				Status:     StatusNotCovered,
				Features:   nil,
				Evidence:   "",
				Limitation: "Workforce authorization, supervision, and termination procedures are organizational controls outside the proxy boundary.",
			},
			{
				ID:         "CONTINGENCY",
				Name:       "Contingency Plan (164.308(a)(7))",
				Status:     StatusPartial,
				Features:   []string{featureKillSwitch, featureHealth},
				Evidence:   "Kill switch + health probes support emergency-mode operating procedures; flight recorder provides the audit trail required for post-incident review.",
				Limitation: "Disaster recovery, data backup, and testing schedules are operator-owned.",
			},
		},
	}
}
