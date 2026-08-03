// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestVerificationStatus_ZeroValueIsNotPass(t *testing.T) {
	var s VerificationStatus
	if s == StatusPass {
		t.Fatal("zero value of VerificationStatus must not be StatusPass")
	}
	if s.String() != "unknown" {
		t.Fatalf("zero value String() = %q, want %q", s.String(), "unknown")
	}
}

func TestVerificationStatus_String(t *testing.T) {
	tests := []struct {
		status VerificationStatus
		want   string
	}{
		{StatusUnknown, "unknown"},
		{StatusPass, "pass"},
		{StatusFail, "fail"},
		{StatusNotApplicable, "not_applicable"},
		{StatusNotMeasured, "not_measured"},
		{VerificationStatus(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerificationStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status VerificationStatus
		want   bool
	}{
		{StatusPass, true},
		{StatusFail, true},
		{StatusNotApplicable, false},
		{StatusNotMeasured, false},
		{StatusUnknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.want {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseVerificationStatus(t *testing.T) {
	tests := []struct {
		input string
		want  VerificationStatus
	}{
		{"pass", StatusPass},
		{"PASS", StatusPass},
		{" Pass ", StatusPass},
		{"fail", StatusFail},
		{"not_applicable", StatusNotApplicable},
		{"not_measured", StatusNotMeasured},
		{"", StatusUnknown},
		{"garbage", StatusUnknown},
		{"PASSED", StatusUnknown}, // not a valid value
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseVerificationStatus(tt.input); got != tt.want {
				t.Errorf("ParseVerificationStatus(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestVerificationStatus_JSONRoundTrip(t *testing.T) {
	for _, s := range []VerificationStatus{
		StatusUnknown, StatusPass, StatusFail, StatusNotApplicable, StatusNotMeasured,
	} {
		t.Run(s.String(), func(t *testing.T) {
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var got VerificationStatus
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got != s {
				t.Errorf("round-trip: got %v, want %v", got, s)
			}
		})
	}
}

func TestVerificationStatus_UnmarshalUnknownString(t *testing.T) {
	var s VerificationStatus
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if s != StatusUnknown {
		t.Errorf("unknown JSON string → %v, want StatusUnknown", s)
	}
}

func TestVerificationStatus_UnmarshalInvalidJSON(t *testing.T) {
	var s VerificationStatus
	// A JSON number is not a string — should resolve to unknown, not error.
	if err := json.Unmarshal([]byte(`42`), &s); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if s != StatusUnknown {
		t.Errorf("invalid JSON type → %v, want StatusUnknown", s)
	}
}

func TestVerificationResult_Validate_NotApplicableNeedsReason(t *testing.T) {
	r := VerificationResult{Status: StatusNotApplicable}
	if err := r.Validate(); !errors.Is(err, ErrMissingApplicabilityReason) {
		t.Fatalf("Validate() = %v, want ErrMissingApplicabilityReason", err)
	}

	r.Reason = "host has no network namespace"
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() with reason = %v, want nil", err)
	}
}

func TestVerificationResult_Validate_WhitespaceReasonRejected(t *testing.T) {
	r := VerificationResult{Status: StatusNotApplicable, Reason: "   "}
	if err := r.Validate(); !errors.Is(err, ErrMissingApplicabilityReason) {
		t.Fatalf("whitespace-only reason should be rejected, got %v", err)
	}
}

func TestVerificationResult_Validate_OtherStatusesNoReason(t *testing.T) {
	for _, s := range []VerificationStatus{StatusPass, StatusFail, StatusNotMeasured, StatusUnknown} {
		t.Run(s.String(), func(t *testing.T) {
			r := VerificationResult{Status: s}
			if err := r.Validate(); err != nil {
				t.Fatalf("Validate() = %v for %v with no reason", err, s)
			}
		})
	}
}

func TestAggregateResults_Basic(t *testing.T) {
	results := []VerificationResult{
		{Status: StatusPass},
		{Status: StatusPass},
		{Status: StatusFail},
		{Status: StatusNotApplicable, Reason: "host mode"},
		{Status: StatusNotMeasured},
	}
	s := AggregateResults(results)

	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
	if s.Passed != 2 {
		t.Errorf("Passed = %d, want 2", s.Passed)
	}
	if s.Failed != 1 {
		t.Errorf("Failed = %d, want 1", s.Failed)
	}
	if s.NotApplicable != 1 {
		t.Errorf("NotApplicable = %d, want 1", s.NotApplicable)
	}
	if s.NotMeasured != 1 {
		t.Errorf("NotMeasured = %d, want 1", s.NotMeasured)
	}
	if s.Measured != 3 {
		t.Errorf("Measured = %d, want 3 (pass+fail only)", s.Measured)
	}
	// 2/3 = 66%
	if s.PassPercentage != 66 {
		t.Errorf("PassPercentage = %d, want 66", s.PassPercentage)
	}
}

func TestAggregateResults_NotMeasuredExcludedFromPercentage(t *testing.T) {
	// 1 pass, 1 not_measured. If NOT_MEASURED were in the denominator,
	// percentage would be 50%. Correctly: 100% (1/1 measured).
	results := []VerificationResult{
		{Status: StatusPass},
		{Status: StatusNotMeasured},
	}
	s := AggregateResults(results)
	if s.PassPercentage != 100 {
		t.Fatalf("PassPercentage = %d, want 100 (not_measured excluded from denominator)", s.PassPercentage)
	}
	if s.NotMeasured != 1 {
		t.Fatalf("NotMeasured = %d, want 1", s.NotMeasured)
	}
}

func TestAggregateResults_AllNotMeasured(t *testing.T) {
	results := []VerificationResult{
		{Status: StatusNotMeasured},
		{Status: StatusNotMeasured},
	}
	s := AggregateResults(results)
	if s.Measured != 0 {
		t.Errorf("Measured = %d, want 0", s.Measured)
	}
	if s.PassPercentage != 0 {
		t.Errorf("PassPercentage = %d, want 0 (no measured results)", s.PassPercentage)
	}
}

func TestAggregateResults_UnknownStatusCountedSeparately(t *testing.T) {
	results := []VerificationResult{
		{Status: StatusPass},
		{Status: StatusUnknown},
	}
	s := AggregateResults(results)
	if s.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", s.Unknown)
	}
	if s.Measured != 1 {
		t.Errorf("Measured = %d, want 1 (unknown excluded)", s.Measured)
	}
	if s.PassPercentage != 100 {
		t.Errorf("PassPercentage = %d, want 100", s.PassPercentage)
	}
}

func TestAggregateResults_Empty(t *testing.T) {
	s := AggregateResults(nil)
	if s.Total != 0 || s.Measured != 0 || s.PassPercentage != 0 {
		t.Errorf("empty aggregate: Total=%d Measured=%d Pct=%d", s.Total, s.Measured, s.PassPercentage)
	}
}

func TestVerificationSummary_HonestPercentage(t *testing.T) {
	tests := []struct {
		name           string
		results        []VerificationResult
		wantPct        int
		wantUnmeasured bool
		wantMeasured   bool
	}{
		{
			name:           "clean",
			results:        []VerificationResult{{Status: StatusPass}, {Status: StatusFail}},
			wantPct:        50,
			wantUnmeasured: false,
			wantMeasured:   true,
		},
		{
			name:           "with unmeasured",
			results:        []VerificationResult{{Status: StatusPass}, {Status: StatusNotMeasured}},
			wantPct:        100,
			wantUnmeasured: true,
			wantMeasured:   true,
		},
		{
			name:           "no measured",
			results:        []VerificationResult{{Status: StatusNotMeasured}},
			wantPct:        0,
			wantUnmeasured: true,
			wantMeasured:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := AggregateResults(tt.results)
			pct, hasUnmeasured, hasMeasured := s.HonestPercentage()
			if pct != tt.wantPct || hasUnmeasured != tt.wantUnmeasured || hasMeasured != tt.wantMeasured {
				t.Errorf("HonestPercentage() = (%d, %v, %v), want (%d, %v, %v)",
					pct, hasUnmeasured, hasMeasured, tt.wantPct, tt.wantUnmeasured, tt.wantMeasured)
			}
		})
	}
}

func TestVerificationSummary_FormatPercentage(t *testing.T) {
	tests := []struct {
		name    string
		results []VerificationResult
		want    string
	}{
		{
			name:    "clean",
			results: []VerificationResult{{Status: StatusPass}, {Status: StatusPass}, {Status: StatusFail}},
			want:    "66% (2/3 measured)",
		},
		{
			name: "with unmeasured",
			results: []VerificationResult{
				{Status: StatusPass}, {Status: StatusPass}, {Status: StatusFail}, {Status: StatusNotMeasured},
			},
			want: "66% (2/3 measured; 1 not measured)",
		},
		{
			name:    "no measured",
			results: []VerificationResult{{Status: StatusNotApplicable, Reason: "n/a"}},
			want:    "no measured results",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := AggregateResults(tt.results)
			if got := s.FormatPercentage(); got != tt.want {
				t.Errorf("FormatPercentage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerificationResult_JSONRoundTrip(t *testing.T) {
	r := VerificationResult{
		Status: StatusNotApplicable,
		Reason: "air-gapped host",
		Detail: "no network namespace",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got VerificationResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Status != r.Status || got.Reason != r.Reason || got.Detail != r.Detail {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, r)
	}
}

func TestVerificationSummary_JSONFields(t *testing.T) {
	results := []VerificationResult{
		{Status: StatusPass},
		{Status: StatusNotMeasured},
	}
	s := AggregateResults(results)
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal map: %v", err)
	}
	// Verify the not_measured field is present in JSON output.
	if _, ok := m["not_measured"]; !ok {
		t.Fatal("not_measured field missing from JSON output")
	}
	if v := m["not_measured"].(float64); v != 1 {
		t.Errorf("not_measured = %v, want 1", v)
	}
}

// TestVerificationStatus_NegativeValueDoesNotPanic covers the lower bound.
//
// VerificationStatus is an int-based type reachable from JSON and from
// arithmetic, so a negative value is not hypothetical. A one-sided bounds check
// indexed out of range and panicked, which turns a bad status into a crash of
// whatever was rendering the report.
func TestVerificationStatus_NegativeValueDoesNotPanic(t *testing.T) {
	for _, s := range []VerificationStatus{-1, -100, VerificationStatus(len(statusStrings)), 9999} {
		got := s.String()
		if got != "unknown" {
			t.Errorf("VerificationStatus(%d).String() = %q, want %q", int(s), got, "unknown")
		}
		if s.IsTerminal() {
			t.Errorf("VerificationStatus(%d) must not be terminal", int(s))
		}
		// It must also survive the JSON path, which is how an out-of-range
		// value actually reaches String() in production.
		b, err := s.MarshalJSON()
		if err != nil {
			t.Errorf("MarshalJSON(%d): %v", int(s), err)
		}
		if string(b) != `"unknown"` {
			t.Errorf("MarshalJSON(%d) = %s, want \"unknown\"", int(s), b)
		}
	}
}
