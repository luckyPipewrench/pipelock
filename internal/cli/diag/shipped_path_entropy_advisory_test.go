// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestShippedPathEntropyDefaultsProduceNoAdvisories pins the operability
// direction of shipping vendor route defaults: a fresh install must not greet
// the operator with advisories about routes Pipelock itself shipped. Every
// advisory in this analyzer asks the operator to own, review, narrow or remove
// an exemption they chose; none of those is an action they can take on a
// shipped default, and an instruction that cannot be followed teaches an
// operator to ignore the whole diagnostic.
func TestShippedPathEntropyDefaultsProduceNoAdvisories(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	if len(cfg.FetchProxy.Monitoring.PathEntropyExclusions) == 0 {
		t.Fatal("defaults ship no path_entropy_exclusions; this test is calibrated against a non-empty shipped set")
	}
	for _, f := range analyzeDoctorPathEntropyExclusions(cfg) {
		t.Errorf("fresh install emits a path-entropy advisory the operator cannot act on: %s || next: %s", f.Detail, f.Next)
	}

	// Calibration: the analyzer is NOT inert. An operator's own entry still
	// gets the full lifecycle treatment, so the silence above is scoping and
	// not a disabled check.
	operator := config.Defaults()
	operator.FetchProxy.Monitoring.PathEntropyExclusions = append(
		operator.FetchProxy.Monitoring.PathEntropyExclusions,
		config.PathEntropyExclusion{Host: "vendor.example", PathPrefix: "/assets/d/"},
	)
	got := analyzeDoctorPathEntropyExclusions(operator)
	if len(got) == 0 {
		t.Fatal("an operator-added entry with no reason/owner/expires produced no advisory; the analyzer is inert")
	}
	for _, f := range got {
		if !strings.Contains(f.Subject, "vendor.example") {
			t.Errorf("advisory targeted a shipped default rather than the operator entry: %s", f.Detail)
		}
	}
	// Each lifecycle field is a SEPARATE check, so assert each one by name. A
	// bare len(got) != 0 passes when only one of the three still fires, which
	// would let two of them silently go missing while the calibration above
	// still reported the analyzer as live.
	for _, field := range []string{"reason", "owner", "expires"} {
		want := "is missing advisory " + field
		found := false
		for _, f := range got {
			if strings.Contains(f.Detail, want) {
				found = true
				break
			}
		}
		if !found {
			var details []string
			for _, f := range got {
				details = append(details, f.Detail)
			}
			t.Errorf("operator entry produced no %q advisory; got:\n%s", field, strings.Join(details, "\n"))
		}
	}
}
