// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"errors"
	"strings"
	"testing"
)

// Wire-form field labels reused across tests. These match the snake_case
// strings emitted by Floors.Validate so the operator can locate the
// offending field in YAML.
const (
	fieldMinSessions = "min_sessions"
	fieldMinEvents   = "min_events"
	fieldMinWindows  = "min_windows"
)

// TestDefaultFloors_Locked is the contract-against-drift guard for the
// floor defaults. Parallel to TestDefaultWilsonAlpha_Locked: if anyone
// bumps these constants, this test fails and the reviewer must justify
// the change in the PR.
func TestDefaultFloors_Locked(t *testing.T) {
	t.Parallel()

	got := DefaultFloors()
	want := Floors{MinSessions: 5, MinEvents: 20, MinWindows: 3}
	if got != want {
		t.Fatalf("DefaultFloors drift detected: got %+v, want %+v", got, want)
	}

	// Also pin the underlying constants so a refactor that replaces the
	// struct literal with the constants doesn't silently shift values.
	if DefaultMinSessions != 5 {
		t.Fatalf("DefaultMinSessions drift detected: got %d, want 5", DefaultMinSessions)
	}
	if DefaultMinEvents != 20 {
		t.Fatalf("DefaultMinEvents drift detected: got %d, want 20", DefaultMinEvents)
	}
	if DefaultMinWindows != 3 {
		t.Fatalf("DefaultMinWindows drift detected: got %d, want 3", DefaultMinWindows)
	}
}

// TestThresholds_Locked is the drift guard for the Wilson confidence
// thresholds. Same logic as TestDefaultFloors_Locked: bumping these
// values changes audit semantics across every install of pipelock.
func TestThresholds_Locked(t *testing.T) {
	t.Parallel()

	if TauStable != 0.85 {
		t.Fatalf("TauStable drift detected: got %v, want 0.85", TauStable)
	}
	if TauBrittle != 0.50 {
		t.Fatalf("TauBrittle drift detected: got %v, want 0.50", TauBrittle)
	}
}

// TestFloors_Resolved exercises the "config omitted → defaults" layer.
// Zero-valued fields take the corresponding default; non-zero fields
// pass through unchanged; negative fields pass through (Resolved is not
// a sanitizer - Validate is).
func TestFloors_Resolved(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   Floors
		want Floors
	}{
		{
			name: "all_zero_fills_all_defaults",
			in:   Floors{},
			want: DefaultFloors(),
		},
		{
			name: "partial_zero_only_min_sessions_filled",
			in:   Floors{MinSessions: 0, MinEvents: 15, MinWindows: 2},
			want: Floors{MinSessions: DefaultMinSessions, MinEvents: 15, MinWindows: 2},
		},
		{
			name: "partial_zero_only_min_events_filled",
			in:   Floors{MinSessions: 7, MinEvents: 0, MinWindows: 4},
			want: Floors{MinSessions: 7, MinEvents: DefaultMinEvents, MinWindows: 4},
		},
		{
			name: "partial_zero_only_min_windows_filled",
			in:   Floors{MinSessions: 7, MinEvents: 25, MinWindows: 0},
			want: Floors{MinSessions: 7, MinEvents: 25, MinWindows: DefaultMinWindows},
		},
		{
			name: "all_set_non_default_pass_through",
			in:   Floors{MinSessions: 10, MinEvents: 50, MinWindows: 7},
			want: Floors{MinSessions: 10, MinEvents: 50, MinWindows: 7},
		},
		{
			name: "all_set_to_defaults_pass_through",
			in:   DefaultFloors(),
			want: DefaultFloors(),
		},
		{
			name: "negative_min_sessions_passes_through",
			in:   Floors{MinSessions: -1, MinEvents: 25, MinWindows: 4},
			want: Floors{MinSessions: -1, MinEvents: 25, MinWindows: 4},
		},
		{
			name: "negative_min_events_passes_through",
			in:   Floors{MinSessions: 7, MinEvents: -2, MinWindows: 4},
			want: Floors{MinSessions: 7, MinEvents: -2, MinWindows: 4},
		},
		{
			name: "negative_min_windows_passes_through",
			in:   Floors{MinSessions: 7, MinEvents: 25, MinWindows: -3},
			want: Floors{MinSessions: 7, MinEvents: 25, MinWindows: -3},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.Resolved(); got != tc.want {
				t.Fatalf("Floors{%+v}.Resolved() = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestFloors_Validate exercises every negative-field path and confirms
// non-negative configs validate clean. The error must wrap
// ErrNegativeFloor and name the offending field in snake_case so the
// operator can locate it in YAML.
func TestFloors_Validate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		in        Floors
		wantErr   bool
		wantField string
	}{
		{
			name:    "all_zero_validates_clean",
			in:      Floors{},
			wantErr: false,
		},
		{
			name:    "all_positive_validates_clean",
			in:      DefaultFloors(),
			wantErr: false,
		},
		{
			name:    "mixed_zero_and_positive_validates_clean",
			in:      Floors{MinSessions: 0, MinEvents: 25, MinWindows: 3},
			wantErr: false,
		},
		{
			name:      "negative_min_sessions",
			in:        Floors{MinSessions: -1, MinEvents: 20, MinWindows: 3},
			wantErr:   true,
			wantField: fieldMinSessions,
		},
		{
			name:      "negative_min_events",
			in:        Floors{MinSessions: 5, MinEvents: -1, MinWindows: 3},
			wantErr:   true,
			wantField: fieldMinEvents,
		},
		{
			name:      "negative_min_windows",
			in:        Floors{MinSessions: 5, MinEvents: 20, MinWindows: -1},
			wantErr:   true,
			wantField: fieldMinWindows,
		},
		{
			name:      "two_negatives_reports_first_field",
			in:        Floors{MinSessions: -1, MinEvents: -2, MinWindows: 3},
			wantErr:   true,
			wantField: fieldMinSessions,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.in.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Floors{%+v}.Validate() = nil; want error wrapping ErrNegativeFloor", tc.in)
				}
				if !errors.Is(err, ErrNegativeFloor) {
					t.Fatalf("Floors{%+v}.Validate() = %v; want errors.Is(err, ErrNegativeFloor)", tc.in, err)
				}
				if !strings.Contains(err.Error(), tc.wantField) {
					t.Fatalf("Floors{%+v}.Validate() error %q does not contain field name %q",
						tc.in, err.Error(), tc.wantField)
				}
				return
			}
			if err != nil {
				t.Fatalf("Floors{%+v}.Validate() = %v; want nil", tc.in, err)
			}
		})
	}
}

// TestFloorsPass_AllEightCombinations is the canonical (T/F)^3 boolean
// table: for each combination of (sessions-pass, events-pass,
// windows-pass), assert FloorsPass returns true iff all three are true.
//
// Pass means count >= floor (sessions=5, events=20, windows=3 from
// DefaultFloors). Fail means count = floor - 1.
func TestFloorsPass_AllEightCombinations(t *testing.T) {
	t.Parallel()

	floors := DefaultFloors()

	const (
		passSessions = 5
		failSessions = 4
		passEvents   = 20
		failEvents   = 19
		passWindows  = 3
		failWindows  = 2
	)

	cases := []struct {
		name     string
		observed int
		sessions int
		windows  int
		want     bool
	}{
		{"FFF_all_fail", failEvents, failSessions, failWindows, false},
		{"FFT_only_windows_pass", failEvents, failSessions, passWindows, false},
		{"FTF_only_sessions_pass", failEvents, passSessions, failWindows, false},
		{"FTT_events_fail", failEvents, passSessions, passWindows, false},
		{"TFF_only_events_pass", passEvents, failSessions, failWindows, false},
		{"TFT_sessions_fail", passEvents, failSessions, passWindows, false},
		{"TTF_windows_fail", passEvents, passSessions, failWindows, false},
		{"TTT_all_pass", passEvents, passSessions, passWindows, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FloorsPass(tc.observed, tc.sessions, tc.windows, floors)
			if got != tc.want {
				t.Fatalf("FloorsPass(observed=%d, sessions=%d, windows=%d, %+v) = %v, want %v",
					tc.observed, tc.sessions, tc.windows, floors, got, tc.want)
			}
		})
	}
}

// TestFloorsPass_NegativeInputsReturnFalse confirms each input position
// independently triggers the defensive false return on a negative value
// even when the other two would otherwise pass.
func TestFloorsPass_NegativeInputsReturnFalse(t *testing.T) {
	t.Parallel()

	floors := DefaultFloors()

	cases := []struct {
		name     string
		observed int
		sessions int
		windows  int
	}{
		{"negative_observed", -1, 5, 3},
		{"negative_sessions", 20, -1, 3},
		{"negative_windows", 20, 5, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := FloorsPass(tc.observed, tc.sessions, tc.windows, floors); got {
				t.Fatalf("FloorsPass(observed=%d, sessions=%d, windows=%d, %+v) = true; want false on negative input",
					tc.observed, tc.sessions, tc.windows, floors)
			}
		})
	}
}

// TestConfidence_String pins the wire-form labels for every defined
// Confidence level plus the default "unknown" branch. These strings ship
// in metrics labels and audit-log values - renaming is a downstream-
// breaking change.
func TestConfidence_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		level Confidence
		want  string
	}{
		{ConfidenceNeverConfirmed, "never_confirmed"},
		{ConfidenceBrittle, "brittle"},
		{ConfidenceStable, "stable"},
		// Out-of-range int casts must hit the default branch.
		{Confidence(99), "unknown"},
		{Confidence(-1), "unknown"},
		{confidenceSentinel, "unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			if got := tc.level.String(); got != tc.want {
				t.Fatalf("Confidence(%d).String() = %q, want %q", tc.level, got, tc.want)
			}
		})
	}
}

// TestClassify_VerdictMatrix walks the classification table from the
// design's Wilson edge-case spec. Every row pins both the inputs and
// the expected verdict so a future change to either the floor logic
// or the threshold bands surfaces as a fail with row context.
//
// Wilson values referenced (computed at DefaultWilsonAlpha = 0.05):
//
//	k=100 n=100 → 0.963 (well above TauStable 0.85)
//	k=25  n=25  → 0.867 (just above TauStable)
//	k=20  n=20  → 0.839 (between TauBrittle and TauStable)
//	k=24  n=35  → 0.520 (just above TauBrittle 0.50)
//	k=23  n=35  → 0.492 (just below TauBrittle)
//	k=20  n=100 → 0.133 (well below TauBrittle, but events floor passes)
func TestClassify_VerdictMatrix(t *testing.T) {
	t.Parallel()

	floors := DefaultFloors()

	cases := []struct {
		name        string
		observed    int
		opportunity int
		sessions    int
		windows     int
		want        Confidence
	}{
		{
			name:        "wilson_well_above_tau_stable_floors_pass",
			observed:    100,
			opportunity: 100,
			sessions:    100,
			windows:     100,
			want:        ConfidenceStable,
		},
		{
			name:        "wilson_just_above_tau_stable_floors_pass",
			observed:    25,
			opportunity: 25,
			sessions:    5,
			windows:     3,
			want:        ConfidenceStable,
		},
		{
			name:        "wilson_in_brittle_band_floors_pass",
			observed:    20,
			opportunity: 20,
			sessions:    5,
			windows:     3,
			want:        ConfidenceBrittle,
		},
		{
			name:        "wilson_just_above_tau_brittle_floors_pass",
			observed:    24,
			opportunity: 35,
			sessions:    5,
			windows:     3,
			want:        ConfidenceBrittle,
		},
		{
			name:        "wilson_just_below_tau_brittle_floors_pass",
			observed:    23,
			opportunity: 35,
			sessions:    5,
			windows:     3,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "wilson_well_below_tau_brittle_floors_pass",
			observed:    20,
			opportunity: 100,
			sessions:    5,
			windows:     3,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "wilson_stable_but_session_floor_fails",
			observed:    100,
			opportunity: 100,
			sessions:    4, // < MinSessions=5
			windows:     100,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "wilson_stable_but_events_floor_fails",
			observed:    19, // < MinEvents=20
			opportunity: 19,
			sessions:    100,
			windows:     100,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "wilson_stable_but_windows_floor_fails",
			observed:    100,
			opportunity: 100,
			sessions:    100,
			windows:     2, // < MinWindows=3
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "wilson_brittle_but_session_floor_fails",
			observed:    20,
			opportunity: 20,
			sessions:    4,
			windows:     3,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "all_zero_inputs",
			observed:    0,
			opportunity: 0,
			sessions:    0,
			windows:     0,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "negative_observed_short_circuits_to_never_confirmed",
			observed:    -1,
			opportunity: 100,
			sessions:    100,
			windows:     100,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "negative_sessions_short_circuits_to_never_confirmed",
			observed:    100,
			opportunity: 100,
			sessions:    -1,
			windows:     100,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "negative_windows_short_circuits_to_never_confirmed",
			observed:    100,
			opportunity: 100,
			sessions:    100,
			windows:     -1,
			want:        ConfidenceNeverConfirmed,
		},
		{
			name:        "exact_floor_thresholds_with_stable_wilson",
			observed:    20, // == MinEvents
			opportunity: 20,
			sessions:    5,                 // == MinSessions
			windows:     3,                 // == MinWindows
			want:        ConfidenceBrittle, // wilson(20,20)=0.839 → brittle band
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.observed, tc.opportunity, tc.sessions, tc.windows, floors)
			if got != tc.want {
				t.Fatalf("Classify(observed=%d, opportunity=%d, sessions=%d, windows=%d, %+v) = %s, want %s",
					tc.observed, tc.opportunity, tc.sessions, tc.windows,
					floors, got, tc.want)
			}
		})
	}
}

// TestClassify_FloorAndCount fixes the Wilson math to a known-stable
// case (k=100, n=100 → wilson ≈ 0.963 ≥ TauStable) and walks every
// floor pass/fail combination. The ONLY combination that yields
// ConfidenceStable is all-three-floors-pass; every other row is
// ConfidenceNeverConfirmed regardless of how high Wilson climbs.
//
// This is the AND-composition contract test the kickoff calls out:
// floors win over Wilson, never the other way around.
func TestClassify_FloorAndCount(t *testing.T) {
	t.Parallel()

	floors := DefaultFloors()

	const (
		// All values pass their respective floor when the row is
		// "T" for that position; all values fail when the row is "F".
		// Wilson is always (observed=opportunity), but observed
		// itself acts as the events-floor input - passEvents=100
		// clears the 20-event floor, failEvents=19 falls just short.
		passEvents   = 100
		failEvents   = 19
		passSessions = 100
		failSessions = 4
		passWindows  = 100
		failWindows  = 2
		// Opportunity is fixed so wilson(observed, opportunity) is
		// either >> TauStable (when observed=passEvents=100) or
		// near-1 with smaller n (when observed=failEvents=19,
		// wilson(19,19)≈0.832 - still high, still confirms the
		// floor-wins-over-Wilson contract).
		opportunityHigh = 100
		opportunityLow  = 19
	)

	cases := []struct {
		name     string
		observed int
		oppor    int
		sessions int
		windows  int
		want     Confidence
	}{
		{"FFF_all_floors_fail", failEvents, opportunityLow, failSessions, failWindows, ConfidenceNeverConfirmed},
		{"FFT_only_windows_pass", failEvents, opportunityLow, failSessions, passWindows, ConfidenceNeverConfirmed},
		{"FTF_only_sessions_pass", failEvents, opportunityLow, passSessions, failWindows, ConfidenceNeverConfirmed},
		{"FTT_events_fail", failEvents, opportunityLow, passSessions, passWindows, ConfidenceNeverConfirmed},
		{"TFF_only_events_pass", passEvents, opportunityHigh, failSessions, failWindows, ConfidenceNeverConfirmed},
		{"TFT_sessions_fail", passEvents, opportunityHigh, failSessions, passWindows, ConfidenceNeverConfirmed},
		{"TTF_windows_fail", passEvents, opportunityHigh, passSessions, failWindows, ConfidenceNeverConfirmed},
		{"TTT_all_floors_pass", passEvents, opportunityHigh, passSessions, passWindows, ConfidenceStable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.observed, tc.oppor, tc.sessions, tc.windows, floors)
			if got != tc.want {
				t.Fatalf("Classify(observed=%d, opportunity=%d, sessions=%d, windows=%d, %+v) = %s, want %s",
					tc.observed, tc.oppor, tc.sessions, tc.windows,
					floors, got, tc.want)
			}
		})
	}
}
