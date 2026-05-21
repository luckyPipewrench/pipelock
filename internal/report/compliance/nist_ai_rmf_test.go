// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"strings"
	"testing"
)

func TestNISTAIRMF_StructuralInvariants(t *testing.T) {
	f := NISTAIRMF()
	if f.ID != "nist_ai_rmf" {
		t.Errorf("ID = %q, want nist_ai_rmf", f.ID)
	}
	if f.Name == "" {
		t.Error("Name must not be empty")
	}
	if f.MappingVersion < 1 {
		t.Errorf("MappingVersion = %d, must be >= 1", f.MappingVersion)
	}
	if f.URL == "" {
		t.Error("URL must not be empty")
	}
	if len(f.Controls) == 0 {
		t.Fatal("Controls slice empty")
	}

	// Every control needs an ID and Name, and a Status from the closed
	// set. Unknown statuses are aggregated as "not covered" by
	// CoverageSummary, which would silently hide a typo.
	validStatus := map[string]bool{
		StatusCovered: true, StatusPartial: true, StatusNotCovered: true,
	}
	seen := map[string]bool{}
	for _, c := range f.Controls {
		if c.ID == "" {
			t.Errorf("control has empty ID: %+v", c)
		}
		if c.Name == "" {
			t.Errorf("control %q has empty Name", c.ID)
		}
		if !validStatus[c.Status] {
			t.Errorf("control %q has invalid Status %q", c.ID, c.Status)
		}
		if seen[c.ID] {
			t.Errorf("duplicate control ID: %q", c.ID)
		}
		seen[c.ID] = true

		// Honesty rule: a control marked not_covered must have a
		// Limitation explaining why. Empty Limitation on not_covered
		// looks like an unfilled stub.
		if c.Status == StatusNotCovered && c.Limitation == "" {
			t.Errorf("control %q not_covered but Limitation is empty", c.ID)
		}
		// Honesty rule: covered/partial controls must claim at least
		// one Pipelock feature. Otherwise the report has nothing to
		// point at when asked "how is this covered?".
		if (c.Status == StatusCovered || c.Status == StatusPartial) && len(c.Features) == 0 {
			t.Errorf("control %q status %q but no Features", c.ID, c.Status)
		}
	}
}

// TestNISTAIRMF_NoFabricatedClaims guards against the class of overclaim
// that HIPAA caught on 2026-05-21 (claiming detection patterns that
// don't ship). Same guard applied to NIST so the next edit doesn't
// introduce parallel overclaims here.
func TestNISTAIRMF_NoFabricatedClaims(t *testing.T) {
	f := NISTAIRMF()
	type forbidden struct {
		phrase string
		why    string
	}
	bans := []forbidden{
		{"HTTPS-only", "Pipelock accepts both http and https schemes"},
		{"https-only", "Pipelock accepts both http and https schemes"},
		{"bias evaluation", "Bias eval is explicitly out of scope; do not claim coverage"},
		{"bias detection", "Bias detection is explicitly out of scope; do not claim coverage"},
	}
	for _, c := range f.Controls {
		for _, b := range bans {
			if strings.Contains(strings.ToLower(c.Evidence), strings.ToLower(b.phrase)) {
				t.Errorf("control %q Evidence contains forbidden phrase %q: %s", c.ID, b.phrase, b.why)
			}
		}
	}
}

func TestNISTAIRMF_GenAIOverlayPresent(t *testing.T) {
	// The NIST AI 600-1 Generative AI Profile is the half of AI RMF
	// that most directly justifies Pipelock's existence. The mapping
	// should explicitly carry at least three GenAI-prefixed controls
	// so readers can trace data privacy, information integrity, and
	// provenance back to specific Pipelock features.
	f := NISTAIRMF()
	gen := 0
	for _, c := range f.Controls {
		if len(c.ID) > 5 && c.ID[:5] == "GENAI" {
			gen++
		}
	}
	if gen < 3 {
		t.Errorf("NIST AI RMF mapping has %d GENAI_* controls, want >= 3", gen)
	}
}
