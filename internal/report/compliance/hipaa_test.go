// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"strings"
	"testing"
)

func TestHIPAASecurityRule_StructuralInvariants(t *testing.T) {
	f := HIPAASecurityRule()
	if f.ID != "hipaa_security" {
		t.Errorf("ID = %q, want hipaa_security", f.ID)
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
		if c.Status == StatusNotCovered && c.Limitation == "" {
			t.Errorf("control %q not_covered but Limitation is empty", c.ID)
		}
		if (c.Status == StatusCovered || c.Status == StatusPartial) && len(c.Features) == 0 {
			t.Errorf("control %q status %q but no Features", c.ID, c.Status)
		}
	}
}

// TestHIPAASecurityRule_NoFabricatedClaims guards against the class of
// overclaim Codex caught on 2026-05-21 (HTTPS-only enforcement, MRN
// detection). Add a phrase here when a future edit risks promising
// behavior the binary does not implement.
func TestHIPAASecurityRule_NoFabricatedClaims(t *testing.T) {
	f := HIPAASecurityRule()
	type forbidden struct {
		phrase string
		why    string
	}
	bans := []forbidden{
		{"HTTPS-only", "Pipelock accepts both http and https schemes; no HTTPS-only enforcement exists in scanner.go"},
		{"MRN", "No MRN pattern ships in DLP defaults; do not claim built-in MRN detection"},
		{"ICD-10", "No ICD-10 pattern ships in DLP defaults"},
		{"NPI", "No NPI pattern ships in DLP defaults"},
	}
	// Match case-insensitively so a future edit writing "Https-Only",
	// "Mrn", or "Icd-10" doesn't bypass the guard. Mirrors the NIST AI
	// RMF forbidden-phrase scan; keeping the two parallel guards aligned
	// prevents a class of cross-test divergence bypass.
	for _, c := range f.Controls {
		lowered := strings.ToLower(c.Evidence)
		for _, b := range bans {
			if strings.Contains(lowered, strings.ToLower(b.phrase)) {
				t.Errorf("control %q Evidence contains forbidden phrase %q: %s", c.ID, b.phrase, b.why)
			}
		}
	}
}

func TestHIPAASecurityRule_NoPhysicalSafeguardClaims(t *testing.T) {
	// Physical Safeguards (164.310) are out of scope for a network
	// proxy. The doc comment was edited 2026-05-21 to drop the
	// "Administrative + Physical + Technical" wording; assert that no
	// control body claims physical safeguard coverage either.
	f := HIPAASecurityRule()
	for _, c := range f.Controls {
		if strings.Contains(c.ID, "PHYS") || strings.Contains(strings.ToLower(c.Name), "physical") {
			t.Errorf("control %q (%q) claims physical safeguard coverage; out of scope for a network proxy", c.ID, c.Name)
		}
	}
}

func TestHIPAASecurityRule_HasOrganizationalNotCovered(t *testing.T) {
	// HIPAA mixes technical safeguards Pipelock can mediate with
	// organizational controls it cannot. The mapping is honest only if
	// at least one organizational control (BAA, workforce security)
	// is marked not_covered with a clear limitation. Hiding this
	// distinction would let a buyer assume Pipelock satisfies HIPAA
	// alone, which it does not and cannot.
	f := HIPAASecurityRule()
	notCovered := 0
	for _, c := range f.Controls {
		if c.Status == StatusNotCovered {
			notCovered++
		}
	}
	if notCovered < 1 {
		t.Error("HIPAA mapping must include at least one not_covered organizational control to be honest")
	}
}
