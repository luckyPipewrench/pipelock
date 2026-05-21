// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

import "sort"

// Catalog returns the built-in compliance frameworks in a stable order.
// The order is the order frameworks render in the free-tier summary grid
// and in the paid-tier annex list. Adjacent frameworks are topically
// grouped: agent-security industry standards (OWASP, MITRE), then
// regulatory frameworks (EU AI Act, NIST AI RMF, HIPAA), then audit
// attestation (SOC 2). Adding a framework here automatically extends
// `assess` output, `summary.json` coverage summaries, and the free
// tier compliance grid.
func Catalog() []Framework {
	return []Framework{
		OWASPMCPTop10(),
		OWASPAgenticTop10(),
		MITREATLAS(),
		EUAIAct(),
		NISTAIRMF(),
		HIPAASecurityRule(),
		SOC2TSC(),
	}
}

// CoverageSummaries converts frameworks into their aggregate summaries.
func CoverageSummaries(frameworks []Framework) []CoverageSummary {
	summaries := make([]CoverageSummary, 0, len(frameworks))
	for _, f := range frameworks {
		summaries = append(summaries, f.CoverageSummary())
	}
	return summaries
}

// SortControls returns a copy of controls sorted by control ID.
func SortControls(controls []ControlMapping) []ControlMapping {
	out := make([]ControlMapping, len(controls))
	copy(out, controls)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}
