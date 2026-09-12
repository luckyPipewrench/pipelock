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
	// PROVENANCE, not resemblance. An operator who writes their own list owns
	// every entry in it, because ApplyDefaults fills the field only when it is
	// nil. So a config carrying a shipped route PLUS an operator route is
	// entirely operator-owned and every entry must get its advisories, and an
	// operator entry that merely duplicates a shipped route must not have its
	// governance stripped. Matching by host and prefix alone got both wrong.
	shipped := config.Defaults().FetchProxy.Monitoring.PathEntropyExclusions[0]

	explicitDuplicate := config.Defaults()
	explicitDuplicate.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{
		{Host: shipped.Host, PathPrefix: shipped.PathPrefix},
	}
	if len(analyzeDoctorPathEntropyExclusions(explicitDuplicate)) == 0 {
		t.Error("an operator entry duplicating a shipped route lost its lifecycle advisories; provenance was decided by resemblance")
	}

	// An expired operator entry on a shipped route must still be reported.
	expired := config.Defaults()
	expired.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{
		{Host: shipped.Host, PathPrefix: shipped.PathPrefix, Reason: "r", Owner: "o", Expires: "2020-01-01"},
	}
	sawExpiry := false
	for _, f := range analyzeDoctorPathEntropyExclusions(expired) {
		if strings.Contains(f.Detail, "expired on") {
			sawExpiry = true
		}
	}
	if !sawExpiry {
		t.Error("an EXPIRED operator entry on a shipped route was silenced; that is the worst case of matching by value")
	}

	// Adding one operator route alongside the shipped set makes the whole list
	// operator-owned, so the operator entry is advised.
	mixedList := config.Defaults()
	mixedList.FetchProxy.Monitoring.PathEntropyExclusions = append(
		append([]config.PathEntropyExclusion(nil), config.Defaults().FetchProxy.Monitoring.PathEntropyExclusions...),
		config.PathEntropyExclusion{Host: "vendor.example", PathPrefix: "/assets/d/"},
	)
	if len(analyzeDoctorPathEntropyExclusions(mixedList)) == 0 {
		t.Error("a list the operator extended produced no advisories; an added entry must not inherit shipped status")
	}

	// Case-insensitive host matching is still required for the inherited list.
	mixedCase := config.Defaults()
	upper := append([]config.PathEntropyExclusion(nil), config.Defaults().FetchProxy.Monitoring.PathEntropyExclusions...)
	upper[0].Host = strings.ToUpper(upper[0].Host)
	mixedCase.FetchProxy.Monitoring.PathEntropyExclusions = upper
	if !pathEntropyExclusionsAreInherited(mixedCase) {
		t.Error("an equivalent-cased spelling of the shipped list was not recognized as inherited")
	}
	for _, f := range analyzeDoctorPathEntropyExclusions(mixedCase) {
		t.Errorf("an equivalent-cased shipped list produced an advisory the operator cannot act on: %s", f.Detail)
	}

	operator := config.Defaults()
	operator.FetchProxy.Monitoring.PathEntropyExclusions = append(
		operator.FetchProxy.Monitoring.PathEntropyExclusions,
		config.PathEntropyExclusion{Host: "vendor.example", PathPrefix: "/assets/d/"},
	)
	got := analyzeDoctorPathEntropyExclusions(operator)
	if len(got) == 0 {
		t.Fatal("an operator-added entry with no reason/owner/expires produced no advisory; the analyzer is inert")
	}
	// Every entry in an operator-written list is operator-owned, including ones
	// naming a shipped route, so advisories on those are CORRECT here. What
	// matters is that the operator's own entry is among them.
	sawOperatorEntry := false
	for _, f := range got {
		if strings.Contains(f.Subject, "vendor.example") {
			sawOperatorEntry = true
		}
	}
	if !sawOperatorEntry {
		t.Error("the operator's own entry produced no advisory")
	}
	// Each lifecycle field is a SEPARATE check, so assert each one by name. A
	// bare len(got) != 0 passes when only one of the three still fires, which
	// would let two of them silently go missing while the calibration above
	// still reported the analyzer as live.
	for _, field := range []string{"reason", "owner", "expires"} {
		want := "is missing advisory " + field
		found := false
		for _, f := range got {
			if strings.Contains(f.Subject, "vendor.example") && strings.Contains(f.Detail, want) {
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
