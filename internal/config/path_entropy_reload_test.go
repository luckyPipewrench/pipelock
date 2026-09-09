// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// A reload that adds an exemption reduces detection coverage, and an operator
// running strict mode needs that surfaced rather than applied silently. A
// reload that only rewrites a reason or an owner is not a coverage change and
// must stay quiet, because a spurious downgrade warning is what strict mode
// refuses, so a noisy warning here would block a legitimate comment edit.

func pathEntropyReloadWarnings(t *testing.T, before, after []PathEntropyExclusion) []ReloadWarning {
	t.Helper()
	old := Defaults()
	old.FetchProxy.Monitoring.PathEntropyExclusions = before
	updated := Defaults()
	updated.FetchProxy.Monitoring.PathEntropyExclusions = after

	var out []ReloadWarning
	for _, w := range ValidateReload(old, updated) {
		if w.Field == "fetch_proxy.monitoring.path_entropy_exclusions" {
			out = append(out, w)
		}
	}
	return out
}

func joinWarnings(warnings []ReloadWarning) string {
	var b strings.Builder
	for _, w := range warnings {
		b.WriteString(w.Message)
		b.WriteString("\n")
	}
	return b.String()
}

var pathEntropyReloadEntry = PathEntropyExclusion{
	Scheme:     "https",
	Host:       "docs.vendor.example",
	PathPrefix: "/document/d/",
	Reason:     "service-issued document identifier",
	Owner:      "platform",
}

func TestPathEntropyExclusionsReloadWarnings(t *testing.T) {
	t.Parallel()

	second := PathEntropyExclusion{Scheme: "https", Host: "drive.vendor.example", PathPrefix: "/file/d/"}

	tests := []struct {
		name    string
		before  []PathEntropyExclusion
		after   []PathEntropyExclusion
		want    string
		wantNil bool
		why     string
	}{
		{
			name:  "adding an exemption warns that coverage dropped",
			after: []PathEntropyExclusion{pathEntropyReloadEntry},
			want:  "path entropy exclusions added: https://docs.vendor.example/document/d/",
			why:   "a reload that quietly reduces detection is the case this exists for",
		},
		{
			name:   "removing an exemption reports coverage restored",
			before: []PathEntropyExclusion{pathEntropyReloadEntry},
			want:   "path entropy exclusions removed: https://docs.vendor.example/document/d/",
		},
		{
			name:    "an unchanged list is silent",
			before:  []PathEntropyExclusion{pathEntropyReloadEntry},
			after:   []PathEntropyExclusion{pathEntropyReloadEntry},
			wantNil: true,
			why:     "idempotent reload must not manufacture a downgrade",
		},
		{
			name:    "reordering the same routes is silent",
			before:  []PathEntropyExclusion{pathEntropyReloadEntry, second},
			after:   []PathEntropyExclusion{second, pathEntropyReloadEntry},
			wantNil: true,
			why:     "entry order is authoring style, not policy",
		},
		{
			name:   "rewriting governance metadata is silent",
			before: []PathEntropyExclusion{pathEntropyReloadEntry},
			after: []PathEntropyExclusion{{
				Scheme:     "https",
				Host:       "docs.vendor.example",
				PathPrefix: "/document/d/",
				Reason:     "a corrected explanation",
				Owner:      "someone else",
				Expires:    "2030-01-01",
			}},
			wantNil: true,
			why:     "strict mode refuses downgrades, so a comment edit must not read as one",
		},
		{
			name:   "an omitted scheme matches an explicit https entry",
			before: []PathEntropyExclusion{pathEntropyReloadEntry},
			after: []PathEntropyExclusion{{
				Host:       "docs.vendor.example",
				PathPrefix: "/document/d/",
			}},
			wantNil: true,
			why:     "https is the default, so spelling it out is not a policy change",
		},
		{
			name:   "swapping one route for another reports both directions",
			before: []PathEntropyExclusion{pathEntropyReloadEntry},
			after:  []PathEntropyExclusion{second},
			want:   "added: https://drive.vendor.example/file/d/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pathEntropyReloadWarnings(t, tt.before, tt.after)
			joined := joinWarnings(got)
			if tt.wantNil {
				if len(got) != 0 {
					t.Fatalf("expected no path-entropy reload warning (%s), got:\n%s", tt.why, joined)
				}
				return
			}
			if !strings.Contains(joined, tt.want) {
				t.Fatalf("expected a warning containing %q (%s), got:\n%s", tt.want, tt.why, joined)
			}
		})
	}
}

// The swap case above asserts the added half; this pins that a swap reports the
// removal too, so replacing a route cannot look like a pure addition.
func TestPathEntropyExclusionsReloadSwapReportsRemoval(t *testing.T) {
	t.Parallel()

	got := joinWarnings(pathEntropyReloadWarnings(t,
		[]PathEntropyExclusion{pathEntropyReloadEntry},
		[]PathEntropyExclusion{{Scheme: "https", Host: "drive.vendor.example", PathPrefix: "/file/d/"}},
	))
	if !strings.Contains(got, "removed: https://docs.vendor.example/document/d/") {
		t.Fatalf("a swapped route did not report the removal, got:\n%s", got)
	}
}
