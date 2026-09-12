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
	// The NEAR matches are the load-bearing cases. An unrelated host alone
	// cannot distinguish an exact (host, prefix) match from a matcher that keys
	// on host only, or on a prefix-of-a-prefix: either would silently suppress
	// a real operator exemption's advisories while this test still passed. Each
	// entry below differs from a SHIPPED one in exactly one field.
	shipped := config.Defaults().FetchProxy.Monitoring.PathEntropyExclusions[0]
	for _, near := range []config.PathEntropyExclusion{
		{Host: shipped.Host, PathPrefix: "/operator/d/"},
		{Host: "vendor.example", PathPrefix: shipped.PathPrefix},
		{Host: shipped.Host, PathPrefix: shipped.PathPrefix + "extra/"},
	} {
		if isShippedPathEntropyDefault(near) {
			t.Errorf("a near match was treated as shipped, so its lifecycle advisories are suppressed: %s%s", near.Host, near.PathPrefix)
		}
		cfg := config.Defaults()
		cfg.FetchProxy.Monitoring.PathEntropyExclusions = append(cfg.FetchProxy.Monitoring.PathEntropyExclusions, near)
		if len(analyzeDoctorPathEntropyExclusions(cfg)) == 0 {
			t.Errorf("near match %s%s produced no advisory; a broader matcher is swallowing operator entries", near.Host, near.PathPrefix)
		}
	}

	// Host matching is case-insensitive, so an EQUIVALENT spelling of a shipped
	// host is still shipped. Without this, a regression from EqualFold to strict
	// equality passes every case above while telling an operator to own and
	// renew a route Pipelock ships, under a host DNS considers identical.
	mixedCase := config.PathEntropyExclusion{Host: strings.ToUpper(shipped.Host), PathPrefix: shipped.PathPrefix}
	if !isShippedPathEntropyDefault(mixedCase) {
		t.Errorf("%s%s is an equivalent spelling of a shipped route but was not treated as shipped", mixedCase.Host, mixedCase.PathPrefix)
	}
	mixedCfg := config.Defaults()
	mixedCfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{mixedCase}
	for _, f := range analyzeDoctorPathEntropyExclusions(mixedCfg) {
		t.Errorf("an equivalent-cased shipped route produced an advisory the operator cannot act on: %s", f.Detail)
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
