// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package egressevidence

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	coverageSiteA SiteID = "fixture.site.a"
	coverageSiteB SiteID = "fixture.site.b"
)

func coverageTestTime(offset int) time.Time {
	return time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(offset) * time.Second)
}

func coverageTestRegistry(t *testing.T, ids ...SiteID) *Registry {
	t.Helper()
	sites := make([]Site, 0, len(ids))
	for _, id := range ids {
		sites = append(sites, Site{
			ID: id, Plane: PlaneProxy, Transport: TransportForward,
			Location: LocationBody, View: ViewOriginal, Boundary: BoundaryUpstreamRequest,
		})
	}
	registry, err := NewRegistry(sites)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return registry
}

func coverageTestQuery(ids ...SiteID) CoverageQuery {
	return CoverageQuery{Start: coverageTestTime(0), End: coverageTestTime(10), Sites: ids}
}

func coverageTestSegment(id SiteID, start, end int, state CoverageState, reason CoverageReason) CoverageSegment {
	return CoverageSegment{SiteID: id, Start: coverageTestTime(start), End: coverageTestTime(end), State: state, Reason: reason}
}

func coverageTestGap(id SiteID, start, end int, state CoverageState, reason CoverageReason) CoverageGap {
	return CoverageGap{SiteID: id, Start: coverageTestTime(start), End: coverageTestTime(end), State: state, Reason: reason}
}

func TestCoverageAssessIndependentDeclarations(t *testing.T) {
	t.Parallel()
	r := coverageTestRegistry(t, coverageSiteA, coverageSiteB)
	tests := []struct {
		name     string
		query    CoverageQuery
		segments []CoverageSegment
		want     CoverageAssessment
	}{
		{
			name:  "all explicitly expected sites complete with no classification events",
			query: coverageTestQuery(coverageSiteB, coverageSiteA),
			segments: []CoverageSegment{
				coverageTestSegment(coverageSiteA, 0, 10, CoverageComplete, ""),
				coverageTestSegment(coverageSiteB, 0, 10, CoverageComplete, ""),
			},
			want: CoverageAssessment{State: CoverageComplete},
		},
		{
			name:  "zero declarations is unavailable for every expected site",
			query: coverageTestQuery(coverageSiteB, coverageSiteA),
			want: CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReasonMissingInterval),
				coverageTestGap(coverageSiteB, 0, 10, CoverageUnavailable, CoverageReasonMissingInterval),
			}},
		},
		{
			name:     "one covered site cannot satisfy another expected site",
			query:    coverageTestQuery(coverageSiteA, coverageSiteB),
			segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 10, CoverageComplete, "")},
			want: CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteB, 0, 10, CoverageUnavailable, CoverageReasonMissingInterval),
			}},
		},
		{
			name:  "leading interior and trailing intervals stay unavailable",
			query: coverageTestQuery(coverageSiteA),
			segments: []CoverageSegment{
				coverageTestSegment(coverageSiteA, 2, 4, CoverageComplete, ""),
				coverageTestSegment(coverageSiteA, 6, 8, CoverageComplete, ""),
			},
			want: CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteA, 0, 2, CoverageUnavailable, CoverageReasonMissingInterval),
				coverageTestGap(coverageSiteA, 4, 6, CoverageUnavailable, CoverageReasonMissingInterval),
				coverageTestGap(coverageSiteA, 8, 10, CoverageUnavailable, CoverageReasonMissingInterval),
			}},
		},
		{
			name:  "recovery cannot erase a declared restart gap",
			query: coverageTestQuery(coverageSiteA),
			segments: []CoverageSegment{
				coverageTestSegment(coverageSiteA, 5, 15, CoverageComplete, ""),
				coverageTestSegment(coverageSiteA, 0, 3, CoverageComplete, ""),
				coverageTestSegment(coverageSiteA, 3, 5, CoverageUnavailable, CoverageReasonRestartGap),
			},
			want: CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteA, 3, 5, CoverageUnavailable, CoverageReasonRestartGap),
			}},
		},
		{
			name:  "unobserved restart interval stays unavailable after recovery",
			query: coverageTestQuery(coverageSiteA),
			segments: []CoverageSegment{
				coverageTestSegment(coverageSiteA, 0, 3, CoverageComplete, ""),
				coverageTestSegment(coverageSiteA, 5, 10, CoverageComplete, ""),
			},
			want: CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteA, 3, 5, CoverageUnavailable, CoverageReasonMissingInterval),
			}},
		},
		{
			name:  "unavailable reasons preserve both sites and intervals",
			query: coverageTestQuery(coverageSiteB, coverageSiteA),
			segments: []CoverageSegment{
				coverageTestSegment(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReasonNotInstrumented),
				coverageTestSegment(coverageSiteB, 0, 4, CoverageUnavailable, CoverageReasonWriterUnavailable),
				coverageTestSegment(coverageSiteB, 4, 10, CoverageUnavailable, CoverageReasonReaderUnavailable),
			},
			want: CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReasonNotInstrumented),
				coverageTestGap(coverageSiteB, 0, 4, CoverageUnavailable, CoverageReasonWriterUnavailable),
				coverageTestGap(coverageSiteB, 4, 10, CoverageUnavailable, CoverageReasonReaderUnavailable),
			}},
		},
		{
			name:     "not instrumented is unavailable, not an exclusion",
			query:    coverageTestQuery(coverageSiteA),
			segments: []CoverageSegment{coverageTestSegment(coverageSiteA, -5, 15, CoverageUnavailable, CoverageReasonNotInstrumented)},
			want: CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReasonNotInstrumented),
			}},
		},
		{
			name:  "adjacent half open declarations cover query",
			query: coverageTestQuery(coverageSiteA),
			segments: []CoverageSegment{
				coverageTestSegment(coverageSiteA, 5, 15, CoverageComplete, ""),
				coverageTestSegment(coverageSiteA, -5, 5, CoverageComplete, ""),
			},
			want: CoverageAssessment{State: CoverageComplete},
		},
		{
			name:  "declarations touching endpoints do not cover query",
			query: coverageTestQuery(coverageSiteA),
			segments: []CoverageSegment{
				coverageTestSegment(coverageSiteA, -5, 0, CoverageComplete, ""),
				coverageTestSegment(coverageSiteA, 10, 15, CoverageComplete, ""),
			},
			want: CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReasonMissingInterval),
			}},
		},
		{
			name:  "explicit subset claims nothing about other registry sites",
			query: coverageTestQuery(coverageSiteA),
			segments: []CoverageSegment{
				coverageTestSegment(coverageSiteA, 0, 10, CoverageComplete, ""),
				coverageTestSegment(coverageSiteB, 0, 10, CoverageUnavailable, CoverageReasonWriterUnavailable),
			},
			want: CoverageAssessment{State: CoverageComplete},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			queryBefore := tc.query
			queryBefore.Sites = slices.Clone(tc.query.Sites)
			segmentsBefore := slices.Clone(tc.segments)
			got, err := r.Assess(tc.query, tc.segments)
			if err != nil {
				t.Fatalf("Assess: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Assess = %#v, want %#v", got, tc.want)
			}
			if !reflect.DeepEqual(tc.query, queryBefore) || !reflect.DeepEqual(tc.segments, segmentsBefore) {
				t.Fatal("Assess mutated its input")
			}
			permuted := slices.Clone(tc.segments)
			slices.Reverse(permuted)
			reversed, err := r.Assess(tc.query, permuted)
			if err != nil || !reflect.DeepEqual(reversed, got) {
				t.Fatalf("permuted Assess = %#v, %v; want %#v", reversed, err, got)
			}
		})
	}
}

func TestCoverageAssessRejectsInvalidQueries(t *testing.T) {
	t.Parallel()
	r := coverageTestRegistry(t, coverageSiteA)
	tests := []struct {
		name  string
		query CoverageQuery
	}{
		{name: "zero start", query: CoverageQuery{End: coverageTestTime(10), Sites: []SiteID{coverageSiteA}}},
		{name: "zero end", query: CoverageQuery{Start: coverageTestTime(0), Sites: []SiteID{coverageSiteA}}},
		{name: "empty interval", query: CoverageQuery{Start: coverageTestTime(0), End: coverageTestTime(0), Sites: []SiteID{coverageSiteA}}},
		{name: "reversed interval", query: CoverageQuery{Start: coverageTestTime(10), End: coverageTestTime(0), Sites: []SiteID{coverageSiteA}}},
		{name: "missing expected sites", query: coverageTestQuery()},
		{name: "unknown site", query: coverageTestQuery("fixture.unknown")},
		{name: "duplicate site", query: coverageTestQuery(coverageSiteA, coverageSiteA)},
		{name: "site limit", query: coverageTestQuery(make([]SiteID, MaxCoverageSites+1)...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.Assess(tc.query, nil)
			if err == nil || got.State == CoverageComplete {
				t.Fatalf("Assess = %#v, %v; want error without complete claim", got, err)
			}
		})
	}
	var absent *Registry
	if got, err := absent.Assess(coverageTestQuery(coverageSiteA), nil); err == nil || got.State == CoverageComplete {
		t.Fatalf("nil registry Assess = %#v, %v; want error", got, err)
	}
}

func TestCoverageAssessRejectsInvalidDeclarations(t *testing.T) {
	t.Parallel()
	r := coverageTestRegistry(t, coverageSiteA, coverageSiteB)
	valid := coverageTestSegment(coverageSiteA, 0, 10, CoverageComplete, "")
	tests := []struct {
		name     string
		segments []CoverageSegment
	}{
		{name: "unknown site outside query", segments: []CoverageSegment{coverageTestSegment("fixture.unknown", 20, 30, CoverageComplete, "")}},
		{name: "zero start", segments: []CoverageSegment{{SiteID: coverageSiteA, End: coverageTestTime(10), State: CoverageComplete}}},
		{name: "empty interval", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 0, CoverageComplete, "")}},
		{name: "reversed interval", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 10, 0, CoverageComplete, "")}},
		{name: "unknown state", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 10, "unknown", "")}},
		{name: "complete with gap reason", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 10, CoverageComplete, "unexpected_reason")}},
		{name: "unavailable without reason", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 10, CoverageUnavailable, "")}},
		{name: "out of scope without reason", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 10, CoverageOutOfScope, "")}},
		{name: "unknown symbolic reason", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 10, CoverageUnavailable, "fixture_unknown")}},
		{name: "raw reason text", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 10, CoverageUnavailable, "not a symbolic reason")}},
		{name: "oversized reason", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReason(strings.Repeat("a", 129)))}},
		{name: "duplicate declaration", segments: []CoverageSegment{valid, valid}},
		{name: "same state overlap", segments: []CoverageSegment{valid, coverageTestSegment(coverageSiteA, 5, 15, CoverageComplete, "")}},
		{name: "conflicting nested declaration", segments: []CoverageSegment{valid, coverageTestSegment(coverageSiteA, 2, 4, CoverageUnavailable, CoverageReasonWriterUnavailable)}},
		{name: "conflicting exact interval", segments: []CoverageSegment{valid, coverageTestSegment(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReasonReaderUnavailable)}},
		{name: "overlap outside query", segments: []CoverageSegment{coverageTestSegment(coverageSiteA, 20, 30, CoverageComplete, ""), coverageTestSegment(coverageSiteA, 25, 35, CoverageComplete, "")}},
		{name: "overlap at unselected known site", segments: []CoverageSegment{coverageTestSegment(coverageSiteB, 0, 10, CoverageComplete, ""), coverageTestSegment(coverageSiteB, 5, 15, CoverageComplete, "")}},
		{name: "segment limit", segments: make([]CoverageSegment, MaxCoverageSegments+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.Assess(coverageTestQuery(coverageSiteA), tc.segments)
			if err == nil || got.State == CoverageComplete {
				t.Fatalf("Assess = %#v, %v; want error without complete claim", got, err)
			}
		})
	}
}

func TestCoverageAssessAcceptsExactLimits(t *testing.T) {
	t.Parallel()
	ids := make([]SiteID, MaxCoverageSites)
	for i := range ids {
		ids[i] = SiteID(fmt.Sprintf("fixture.site.%03d", i))
	}
	r := coverageTestRegistry(t, ids...)
	segments := make([]CoverageSegment, 0, MaxCoverageSegments)
	perSite := MaxCoverageSegments / MaxCoverageSites
	for _, id := range ids {
		for j := range perSite {
			segments = append(segments, coverageTestSegment(id, j, j+1, CoverageComplete, ""))
		}
	}
	query := coverageTestQuery(ids...)
	query.End = coverageTestTime(perSite)
	got, err := r.Assess(query, segments)
	if err != nil || got.State != CoverageComplete || len(got.Gaps) != 0 {
		t.Fatalf("Assess at limits = %#v, %v; want complete", got, err)
	}
}

func TestCoverageAssessReasonStateCompatibility(t *testing.T) {
	t.Parallel()
	r := coverageTestRegistry(t, coverageSiteA)
	tests := []struct {
		reason CoverageReason
		state  CoverageState
	}{
		{CoverageReasonMissingInterval, CoverageUnavailable},
		{CoverageReasonNotInstrumented, CoverageUnavailable},
		{CoverageReasonCollectionDisabled, CoverageUnavailable},
		{CoverageReasonWriterUnavailable, CoverageUnavailable},
		{CoverageReasonReaderUnavailable, CoverageUnavailable},
		{CoverageReasonRestartGap, CoverageUnavailable},
		{CoverageReasonReloadGap, CoverageUnavailable},
	}
	for _, tc := range tests {
		t.Run(string(tc.reason), func(t *testing.T) {
			segment := coverageTestSegment(coverageSiteA, 0, 10, tc.state, tc.reason)
			got, err := r.Assess(coverageTestQuery(coverageSiteA), []CoverageSegment{segment})
			want := CoverageAssessment{State: tc.state, Gaps: []CoverageGap{
				coverageTestGap(coverageSiteA, 0, 10, tc.state, tc.reason),
			}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("matching state Assess = %#v, %v; want %#v", got, err, want)
			}
			for _, wrongState := range []CoverageState{CoverageComplete, CoverageUnavailable, CoverageOutOfScope} {
				if wrongState == tc.state {
					continue
				}
				segment.State = wrongState
				got, err := r.Assess(coverageTestQuery(coverageSiteA), []CoverageSegment{segment})
				if err == nil || got.State == CoverageComplete {
					t.Fatalf("mismatched state %q Assess = %#v, %v; want error", wrongState, got, err)
				}
			}
		})
	}
}

func TestCoverageAssessHookPlaneExclusion(t *testing.T) {
	t.Parallel()
	const hookID SiteID = "fixture.hook.arguments"
	r, err := NewRegistry([]Site{
		{
			ID: coverageSiteA, Plane: PlaneProxy, Transport: TransportForward,
			Location: LocationBody, View: ViewOriginal, Boundary: BoundaryUpstreamRequest,
		},
		{
			ID: hookID, Plane: PlaneHook, Transport: TransportHook,
			Location: LocationToolArguments, View: ViewOriginal, Boundary: BoundaryHookDecision,
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	query := coverageTestQuery(hookID)
	exclusion := coverageTestSegment(hookID, 0, 10, CoverageOutOfScope, CoverageReasonHookPlane)
	got, err := r.Assess(query, []CoverageSegment{exclusion})
	want := CoverageAssessment{State: CoverageOutOfScope, Gaps: []CoverageGap{
		coverageTestGap(hookID, 0, 10, CoverageOutOfScope, CoverageReasonHookPlane),
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("hook exclusion Assess = %#v, %v; want %#v", got, err, want)
	}
	for _, segment := range []CoverageSegment{
		coverageTestSegment(hookID, 0, 10, CoverageComplete, ""),
		coverageTestSegment(hookID, 0, 10, CoverageUnavailable, CoverageReasonNotInstrumented),
		coverageTestSegment(hookID, 0, 10, CoverageOutOfScope, "offline_scan"),
		coverageTestSegment(hookID, 0, 10, CoverageComplete, CoverageReasonHookPlane),
		coverageTestSegment(hookID, 0, 10, CoverageUnavailable, CoverageReasonHookPlane),
		coverageTestSegment(coverageSiteA, 0, 10, CoverageOutOfScope, CoverageReasonHookPlane),
	} {
		if got, err := r.Assess(query, []CoverageSegment{segment}); err == nil || got.State == CoverageComplete {
			t.Fatalf("invalid hook declaration %#v Assess = %#v, %v; want error", segment, got, err)
		}
	}
	got, err = r.Assess(query, nil)
	want = CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
		coverageTestGap(hookID, 0, 10, CoverageUnavailable, CoverageReasonMissingInterval),
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("missing hook declaration Assess = %#v, %v; want %#v", got, err, want)
	}
	got, err = r.Assess(coverageTestQuery(coverageSiteA, hookID), []CoverageSegment{exclusion})
	want = CoverageAssessment{State: CoverageUnavailable, Gaps: []CoverageGap{
		coverageTestGap(hookID, 0, 10, CoverageOutOfScope, CoverageReasonHookPlane),
		coverageTestGap(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReasonMissingInterval),
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("mixed hook/proxy Assess = %#v, %v; want %#v", got, err, want)
	}
	got, err = r.Assess(coverageTestQuery(coverageSiteA, hookID), []CoverageSegment{
		exclusion,
		coverageTestSegment(coverageSiteA, 0, 10, CoverageUnavailable, CoverageReasonWriterUnavailable),
	})
	want.Gaps[1].Reason = CoverageReasonWriterUnavailable
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("declared unavailable proxy and hook exclusion Assess = %#v, %v; want %#v", got, err, want)
	}
}

// Broad limitations of a future report's scope cannot waive collection at an
// explicitly expected proxy classification site. These former vocabulary values
// must remain rejected, including when relabeled as unavailable.
func TestCoverageAssessRejectsFormerScopeReasons(t *testing.T) {
	t.Parallel()
	r := coverageTestRegistry(t, coverageSiteA)
	for _, reason := range []CoverageReason{
		"response_plane", "offline_scan", "unmediated", "opaque_passthrough",
	} {
		t.Run(string(reason), func(t *testing.T) {
			for _, state := range []CoverageState{CoverageComplete, CoverageUnavailable, CoverageOutOfScope} {
				got, err := r.Assess(coverageTestQuery(coverageSiteA), []CoverageSegment{
					coverageTestSegment(coverageSiteA, 0, 10, state, reason),
				})
				if err == nil || got.State != "" || len(got.Gaps) != 0 {
					t.Fatalf("former scope reason %q with state %q Assess = %#v, %v; want error without coverage claim", reason, state, got, err)
				}
			}
		})
	}
}
