// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

import "sort"

// Catalog returns the built-in compliance frameworks in a stable order.
func Catalog() []Framework {
	return []Framework{
		OWASPMCPTop10(),
		OWASPAgenticTop10(),
		MITREATLAS(),
		EUAIAct(),
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
