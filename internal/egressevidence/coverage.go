// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package egressevidence

import (
	"fmt"
	"slices"
	"time"
)

type CoverageState string

const (
	CoverageComplete    CoverageState = "complete"
	CoverageUnavailable CoverageState = "unavailable"
	CoverageOutOfScope  CoverageState = "out_of_scope"

	// MaxCoverageSites and MaxCoverageSegments bound the reducer's work and
	// output. Callers must narrow a query or explicitly report unavailable
	// coverage when these limits cannot be met; silently truncating input
	// would turn discarded declarations into misleading completeness.
	MaxCoverageSites    = 256
	MaxCoverageSegments = 4096
)

// CoverageReason is a closed, state-bound vocabulary for this candidate
// contract. Every expected proxy site is in scope: missing instrumentation is
// unavailable, never a scope exclusion. Only a registered hook-plane site may
// declare out_of_scope. Adding reasons or changing their meaning requires
// explicit contract review.
type CoverageReason string

const (
	CoverageReasonMissingInterval    CoverageReason = "missing_interval"
	CoverageReasonNotInstrumented    CoverageReason = "not_instrumented"
	CoverageReasonCollectionDisabled CoverageReason = "collection_disabled"
	CoverageReasonWriterUnavailable  CoverageReason = "writer_unavailable"
	CoverageReasonReaderUnavailable  CoverageReason = "reader_unavailable"
	CoverageReasonRestartGap         CoverageReason = "restart_gap"
	CoverageReasonReloadGap          CoverageReason = "reload_gap"
	CoverageReasonHookPlane          CoverageReason = "hook_plane"
)

func (reason CoverageReason) state() (CoverageState, bool) {
	switch reason {
	case CoverageReasonMissingInterval, CoverageReasonNotInstrumented,
		CoverageReasonCollectionDisabled, CoverageReasonWriterUnavailable,
		CoverageReasonReaderUnavailable, CoverageReasonRestartGap, CoverageReasonReloadGap:
		return CoverageUnavailable, true
	case CoverageReasonHookPlane:
		return CoverageOutOfScope, true
	default:
		return "", false
	}
}

// CoverageSegment represents an independently established capability/health
// interval. It is never inferred from classification-event counts. A recovered
// writer starts a new segment; it cannot overwrite an earlier unavailable one.
// Reasons are bounded symbolic references, not raw traffic or error messages.
//
// This additive contract foundation has no runtime collector: declarations are
// fixture inputs until separately instrumented and validated. Readers must
// authenticate and bind them to the queried run, configuration generation,
// agent, session and destination before calling Assess. A registry alone does
// not establish a complete census of production classification sites. This
// candidate contract covers expected proxy classification-site obligations:
// proxy segments must be complete or unavailable. Registered hook-plane sites
// may declare only out_of_scope with CoverageReasonHookPlane. Broader response,
// offline, unmediated, or opaque-transport limitations belong in a future
// query/report scope model; they cannot waive an expected proxy-site obligation.
type CoverageSegment struct {
	SiteID SiteID
	Start  time.Time
	End    time.Time
	State  CoverageState
	Reason CoverageReason
}

// CoverageQuery names every expected site for the requested scope explicitly.
// Every named site must cover the whole half-open interval [Start, End).
// Selecting some registry sites makes no claim about the others.
type CoverageQuery struct {
	Start time.Time
	End   time.Time
	Sites []SiteID
}

// CoverageGap retains the interval and reason for every non-complete part of a
// query, including explicit hook-plane exclusions alongside unavailable intervals.
type CoverageGap struct {
	SiteID SiteID
	Start  time.Time
	End    time.Time
	State  CoverageState
	Reason CoverageReason
}

type CoverageAssessment struct {
	// State is complete only if all expected sites cover the whole query.
	// Unavailable takes precedence over out_of_scope in a mixed result;
	// consumers must retain Gaps to disclose every hook-plane exclusion as well.
	State CoverageState
	Gaps  []CoverageGap
}

// Assess reduces independent coverage declarations over [Start, End). Missing
// sites and intervals, including unobserved restart periods, are unavailable
// even with zero classification events. Later recovery never fills an earlier
// gap. Explicit hook-plane exclusions remain visible even if another site or
// interval is unavailable. Complete means declared collection coverage only;
// it never proves that no secret escaped or that unmediated traffic was clean.
//
// All supplied declarations are validated, including those outside the query.
// Duplicate or overlapping intervals for a site are rejected, even when they
// agree, rather than selecting a winner that could erase contradictory evidence.
// Adjacent half-open intervals are allowed. Assess does not mutate its inputs,
// establish the declarations' authenticity, or instrument production traffic.
func (r *Registry) Assess(query CoverageQuery, segments []CoverageSegment) (CoverageAssessment, error) {
	if query.Start.IsZero() || !query.End.After(query.Start) || len(query.Sites) == 0 {
		return CoverageAssessment{}, fmt.Errorf("invalid coverage query")
	}
	if len(query.Sites) > MaxCoverageSites || len(segments) > MaxCoverageSegments {
		return CoverageAssessment{}, fmt.Errorf("coverage input exceeds reducer limits")
	}
	selected := make(map[SiteID]struct{}, len(query.Sites))
	for _, id := range query.Sites {
		if _, ok := r.Lookup(id); !ok {
			return CoverageAssessment{}, fmt.Errorf("unknown coverage site")
		}
		if _, duplicate := selected[id]; duplicate {
			return CoverageAssessment{}, fmt.Errorf("duplicate coverage site")
		}
		selected[id] = struct{}{}
	}

	bySite := make(map[SiteID][]CoverageSegment)
	var declaredSites []SiteID
	for _, segment := range segments {
		site, ok := r.Lookup(segment.SiteID)
		if !ok {
			return CoverageAssessment{}, fmt.Errorf("unknown coverage segment site")
		}
		if err := validateCoverageSegment(segment); err != nil {
			return CoverageAssessment{}, err
		}
		// Proxy sites name expected collection obligations and cannot be
		// excluded. Only hook sites may declare the explicit hook exclusion;
		// this never provides evidence of collected hook decisions.
		if site.Plane == PlaneHook {
			if segment.State != CoverageOutOfScope || segment.Reason != CoverageReasonHookPlane {
				return CoverageAssessment{}, fmt.Errorf("hook coverage must declare the hook-plane exclusion")
			}
		} else if segment.State == CoverageOutOfScope {
			return CoverageAssessment{}, fmt.Errorf("expected proxy coverage cannot be excluded")
		}
		if _, exists := bySite[segment.SiteID]; !exists {
			declaredSites = append(declaredSites, segment.SiteID)
		}
		bySite[segment.SiteID] = append(bySite[segment.SiteID], segment)
	}
	slices.Sort(declaredSites)
	for _, id := range declaredSites {
		rows := bySite[id]
		slices.SortFunc(rows, func(a, b CoverageSegment) int { return a.Start.Compare(b.Start) })
		for i := 1; i < len(rows); i++ {
			if rows[i].Start.Before(rows[i-1].End) {
				return CoverageAssessment{}, fmt.Errorf("overlapping coverage declarations for a site")
			}
		}
	}

	result := CoverageAssessment{State: CoverageComplete}
	ids := slices.Clone(query.Sites)
	slices.Sort(ids)
	for _, id := range ids {
		cursor := query.Start
		for _, row := range bySite[id] {
			if !row.End.After(query.Start) || !row.Start.Before(query.End) {
				continue
			}
			start, end := row.Start, row.End
			if start.Before(query.Start) {
				start = query.Start
			}
			if end.After(query.End) {
				end = query.End
			}
			if start.After(cursor) {
				result.addGap(id, cursor, start, CoverageUnavailable, CoverageReasonMissingInterval)
			}
			if row.State != CoverageComplete {
				result.addGap(id, start, end, row.State, row.Reason)
			}
			cursor = end
		}
		if cursor.Before(query.End) {
			result.addGap(id, cursor, query.End, CoverageUnavailable, CoverageReasonMissingInterval)
		}
	}
	return result, nil
}

func validateCoverageSegment(segment CoverageSegment) error {
	if segment.Start.IsZero() || !segment.End.After(segment.Start) {
		return fmt.Errorf("invalid coverage interval")
	}
	switch segment.State {
	case CoverageComplete:
		if segment.Reason != "" {
			return fmt.Errorf("complete coverage has a gap reason")
		}
	case CoverageUnavailable, CoverageOutOfScope:
		state, known := segment.Reason.state()
		if !known {
			return fmt.Errorf("invalid coverage gap reason")
		}
		if state != segment.State {
			return fmt.Errorf("coverage state and reason disagree")
		}
	default:
		return fmt.Errorf("invalid coverage state")
	}
	return nil
}

func (a *CoverageAssessment) addGap(id SiteID, start, end time.Time, state CoverageState, reason CoverageReason) {
	a.Gaps = append(a.Gaps, CoverageGap{SiteID: id, Start: start, End: end, State: state, Reason: reason})
	if state == CoverageUnavailable || a.State == CoverageComplete {
		a.State = state
	}
}
