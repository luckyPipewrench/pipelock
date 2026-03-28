// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

import "testing"

func TestOWASPMCPTop10(t *testing.T) {
	f := OWASPMCPTop10()
	if len(f.Controls) != 10 {
		t.Fatalf("expected 10 controls, got %d", len(f.Controls))
	}
	if f.MappingVersion < 1 {
		t.Error("mapping version must be >= 1")
	}
	s := f.CoverageSummary()
	if s.Covered < 7 {
		t.Errorf("expected at least 7 covered, got %d", s.Covered)
	}
	if got := f.CoverageText(); got == "" {
		t.Error("CoverageText must not be empty")
	}
}

func TestOWASPAgenticTop10(t *testing.T) {
	f := OWASPAgenticTop10()
	if len(f.Controls) != 10 {
		t.Fatalf("expected 10 controls, got %d", len(f.Controls))
	}
	if f.MappingVersion < 1 {
		t.Error("mapping version must be >= 1")
	}
}

func TestMITREATLAS(t *testing.T) {
	f := MITREATLAS()
	if len(f.Controls) != 14 {
		t.Fatalf("expected 14 controls, got %d", len(f.Controls))
	}
	if f.MappingVersion < 1 {
		t.Error("mapping version must be >= 1")
	}
}

func TestEUAIAct(t *testing.T) {
	f := EUAIAct()
	if len(f.Controls) == 0 {
		t.Fatal("expected EU AI Act controls")
	}
	found12, found26 := false, false
	for _, c := range f.Controls {
		if c.ID == "A12" {
			found12 = true
		}
		if c.ID == "A26" {
			found26 = true
		}
	}
	if !found12 || !found26 {
		t.Fatalf("expected Article 12 and 26 controls, got A12=%v A26=%v", found12, found26)
	}
}

func TestSOC2TSC(t *testing.T) {
	f := SOC2TSC()
	if len(f.Controls) != 5 {
		t.Fatalf("expected 5 controls, got %d", len(f.Controls))
	}
	s := f.CoverageSummary()
	if s.Total != 5 {
		t.Fatalf("summary total = %d, want 5", s.Total)
	}
}

func TestCoverageSummaries(t *testing.T) {
	frameworks := Catalog()
	summaries := CoverageSummaries(frameworks)
	if len(summaries) != len(frameworks) {
		t.Fatalf("summaries length %d != frameworks length %d", len(summaries), len(frameworks))
	}
	for i, s := range summaries {
		if s.FrameworkID != frameworks[i].ID {
			t.Errorf("summary[%d] ID = %q, want %q", i, s.FrameworkID, frameworks[i].ID)
		}
		if s.Total == 0 {
			t.Errorf("summary[%d] total should be > 0", i)
		}
	}
}

func TestSortControls(t *testing.T) {
	controls := []ControlMapping{
		{ID: "C"},
		{ID: "A"},
		{ID: "B"},
	}
	sorted := SortControls(controls)
	if sorted[0].ID != "A" || sorted[1].ID != "B" || sorted[2].ID != "C" {
		t.Errorf("expected A,B,C order, got %s,%s,%s", sorted[0].ID, sorted[1].ID, sorted[2].ID)
	}
	// Original must not be mutated.
	if controls[0].ID != "C" {
		t.Error("SortControls must not mutate input")
	}
}

func TestCatalog(t *testing.T) {
	catalog := Catalog()
	if len(catalog) != 5 {
		t.Fatalf("catalog has %d frameworks, want 5", len(catalog))
	}
	ids := make(map[string]bool)
	for _, f := range catalog {
		if ids[f.ID] {
			t.Errorf("duplicate framework ID: %s", f.ID)
		}
		ids[f.ID] = true
		if f.MappingVersion < 1 {
			t.Errorf("framework %s has MappingVersion < 1", f.ID)
		}
	}
}
