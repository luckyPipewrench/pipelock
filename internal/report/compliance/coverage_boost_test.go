// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"testing"
)

func TestFramework_CoverageText(t *testing.T) {
	f := Framework{
		ID:             "test_fw",
		Name:           "Test Framework",
		Version:        "1.0",
		MappingVersion: 1,
		Controls: []ControlMapping{
			{ID: "C1", Status: StatusCovered},
			{ID: "C2", Status: StatusPartial},
			{ID: "C3", Status: StatusNotCovered},
		},
	}

	got := f.CoverageText()
	want := "1/3 covered"
	if got != want {
		t.Errorf("CoverageText() = %q, want %q", got, want)
	}
}

func TestCoverageSummary_CoverageText(t *testing.T) {
	cases := []struct {
		name    string
		summary CoverageSummary
		want    string
	}{
		{
			name:    "all covered",
			summary: CoverageSummary{Covered: 5, Total: 5},
			want:    "5/5 covered",
		},
		{
			name:    "none covered",
			summary: CoverageSummary{Covered: 0, Total: 3},
			want:    "0/3 covered",
		},
		{
			name:    "zero total",
			summary: CoverageSummary{Covered: 0, Total: 0},
			want:    "0/0 covered",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.summary.CoverageText()
			if got != tc.want {
				t.Errorf("CoverageText() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFramework_CoverageStatus(t *testing.T) {
	cases := []struct {
		name     string
		controls []ControlMapping
		want     string
	}{
		{
			name: "all covered",
			controls: []ControlMapping{
				{ID: "C1", Status: StatusCovered},
				{ID: "C2", Status: StatusCovered},
			},
			want: StatusCovered,
		},
		{
			name: "some partial no uncovered",
			controls: []ControlMapping{
				{ID: "C1", Status: StatusCovered},
				{ID: "C2", Status: StatusPartial},
			},
			want: StatusPartial,
		},
		{
			name: "any not covered",
			controls: []ControlMapping{
				{ID: "C1", Status: StatusCovered},
				{ID: "C2", Status: StatusNotCovered},
			},
			want: StatusNotCovered,
		},
		{
			name: "not covered takes priority over partial",
			controls: []ControlMapping{
				{ID: "C1", Status: StatusPartial},
				{ID: "C2", Status: StatusNotCovered},
			},
			want: StatusNotCovered,
		},
		{
			name:     "empty controls",
			controls: nil,
			want:     StatusCovered,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Framework{
				ID:             "test",
				Name:           "Test",
				MappingVersion: 1,
				Controls:       tc.controls,
			}
			got := f.CoverageStatus()
			if got != tc.want {
				t.Errorf("CoverageStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFramework_CoverageSummary_FieldMapping(t *testing.T) {
	f := Framework{
		ID:             "test_fw",
		Name:           "Test Framework",
		MappingVersion: 2,
		Controls: []ControlMapping{
			{ID: "C1", Status: StatusCovered},
			{ID: "C2", Status: StatusPartial},
			{ID: "C3", Status: StatusNotCovered},
			{ID: "C4", Status: StatusCovered},
			{ID: "C5", Status: "unknown"},
		},
	}

	s := f.CoverageSummary()

	if s.FrameworkID != "test_fw" {
		t.Errorf("FrameworkID = %q, want %q", s.FrameworkID, "test_fw")
	}
	if s.FrameworkName != "Test Framework" {
		t.Errorf("FrameworkName = %q, want %q", s.FrameworkName, "Test Framework")
	}
	if s.MappingVersion != 2 {
		t.Errorf("MappingVersion = %d, want 2", s.MappingVersion)
	}
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
	if s.Covered != 2 {
		t.Errorf("Covered = %d, want 2", s.Covered)
	}
	if s.Partial != 1 {
		t.Errorf("Partial = %d, want 1", s.Partial)
	}
	// "unknown" status falls through to default (NotCovered).
	if s.NotCovered != 2 {
		t.Errorf("NotCovered = %d, want 2", s.NotCovered)
	}
}

func TestSortControls_AlreadySorted(t *testing.T) {
	controls := []ControlMapping{
		{ID: "A"},
		{ID: "B"},
		{ID: "C"},
	}
	sorted := SortControls(controls)
	if sorted[0].ID != "A" || sorted[1].ID != "B" || sorted[2].ID != "C" {
		t.Error("already sorted input should remain sorted")
	}
}

func TestSortControls_Empty(t *testing.T) {
	sorted := SortControls(nil)
	if len(sorted) != 0 {
		t.Errorf("SortControls(nil) returned %d elements, want 0", len(sorted))
	}
}

func TestSortControls_Single(t *testing.T) {
	controls := []ControlMapping{{ID: "Z"}}
	sorted := SortControls(controls)
	if len(sorted) != 1 || sorted[0].ID != "Z" {
		t.Error("single element sort failed")
	}
}

func TestCoverageSummaries_Empty(t *testing.T) {
	summaries := CoverageSummaries(nil)
	if len(summaries) != 0 {
		t.Errorf("CoverageSummaries(nil) returned %d, want 0", len(summaries))
	}
}

func TestCoverageSummaries_PreservesOrder(t *testing.T) {
	frameworks := []Framework{
		{ID: "z_framework", Controls: []ControlMapping{{ID: "Z1", Status: StatusCovered}}},
		{ID: "a_framework", Controls: []ControlMapping{{ID: "A1", Status: StatusPartial}}},
	}
	summaries := CoverageSummaries(frameworks)
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}
	if summaries[0].FrameworkID != "z_framework" {
		t.Errorf("first summary should be z_framework, got %q", summaries[0].FrameworkID)
	}
	if summaries[1].FrameworkID != "a_framework" {
		t.Errorf("second summary should be a_framework, got %q", summaries[1].FrameworkID)
	}
}

// Test each individual framework constructor for data integrity.

func TestMITREATLAS_ControlDetails(t *testing.T) {
	f := MITREATLAS()
	if f.URL == "" {
		t.Error("ATLAS framework should have a URL")
	}

	// Verify every control has an ID and Name.
	for _, c := range f.Controls {
		if c.ID == "" {
			t.Error("control has empty ID")
		}
		if c.Name == "" {
			t.Errorf("control %s has empty Name", c.ID)
		}
		// Covered and partial controls must have features.
		if c.Status == StatusCovered || c.Status == StatusPartial {
			if len(c.Features) == 0 {
				t.Errorf("control %s (%s) has no features", c.ID, c.Status)
			}
		}
		// Partial controls must have a limitation.
		if c.Status == StatusPartial && c.Limitation == "" {
			t.Errorf("partial control %s has no limitation text", c.ID)
		}
	}
}

func TestOWASPMCPTop10_ControlDetails(t *testing.T) {
	f := OWASPMCPTop10()
	for _, c := range f.Controls {
		if c.ID == "" || c.Name == "" {
			t.Errorf("control has empty ID or Name: %+v", c)
		}
		if c.Evidence == "" {
			t.Errorf("control %s has no evidence", c.ID)
		}
		if c.Status == StatusPartial && c.Limitation == "" {
			t.Errorf("partial control %s has no limitation", c.ID)
		}
	}
}

func TestOWASPAgenticTop10_ControlDetails(t *testing.T) {
	f := OWASPAgenticTop10()
	for _, c := range f.Controls {
		if c.ID == "" || c.Name == "" {
			t.Errorf("control has empty ID or Name: %+v", c)
		}
		if c.Status == StatusPartial && c.Limitation == "" {
			t.Errorf("partial control %s has no limitation", c.ID)
		}
	}
}

func TestEUAIAct_ControlDetails(t *testing.T) {
	f := EUAIAct()
	if f.URL == "" {
		t.Error("EU AI Act framework should have a URL")
	}
	for _, c := range f.Controls {
		if c.ID == "" || c.Name == "" {
			t.Errorf("control has empty ID or Name: %+v", c)
		}
		if c.Status == StatusPartial && c.Limitation == "" {
			t.Errorf("partial control %s has no limitation", c.ID)
		}
	}
}

func TestSOC2TSC_ControlDetails(t *testing.T) {
	f := SOC2TSC()
	if f.URL == "" {
		t.Error("SOC2 TSC framework should have a URL")
	}
	for _, c := range f.Controls {
		if c.ID == "" || c.Name == "" {
			t.Errorf("control has empty ID or Name: %+v", c)
		}
		if c.Status == StatusPartial && c.Limitation == "" {
			t.Errorf("partial control %s has no limitation", c.ID)
		}
	}

	// Verify specific SOC2 controls exist.
	ids := make(map[string]bool)
	for _, c := range f.Controls {
		ids[c.ID] = true
	}
	for _, want := range []string{"SEC", "AVA", "PI", "CONF", "PRIV"} {
		if !ids[want] {
			t.Errorf("missing SOC2 control %q", want)
		}
	}
}

func TestCatalog_Deterministic(t *testing.T) {
	a := Catalog()
	b := Catalog()
	if len(a) != len(b) {
		t.Fatalf("Catalog() returned different lengths: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Errorf("Catalog()[%d].ID: %q vs %q", i, a[i].ID, b[i].ID)
		}
	}
}
