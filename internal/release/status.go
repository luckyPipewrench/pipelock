// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// VerificationStatus is the four-value vocabulary for release and benchmark
// verification results.
//
// The zero value is StatusUnknown, which is NOT a passing state. An unset,
// missing, or unparseable status must never resolve to PASS.
type VerificationStatus int

const (
	// StatusUnknown is the zero value. It is not PASS and must not appear
	// in honest output. Its existence ensures that an uninitialised struct
	// field never silently reads as success.
	StatusUnknown VerificationStatus = iota

	// StatusPass means the check ran and succeeded.
	StatusPass

	// StatusFail means the check ran and did not succeed.
	StatusFail

	// StatusNotApplicable means the customer path genuinely cannot apply
	// to this check. A recorded Reason is mandatory; an applicability
	// claim with no stated reason is rejected.
	StatusNotApplicable

	// StatusNotMeasured means the check IS applicable but no valid
	// measurement was obtained. This must NEVER be folded into the
	// numerator or denominator of a success percentage.
	StatusNotMeasured
)

// statusStrings maps each VerificationStatus to its stable JSON/wire string.
// Keep in sync with ParseVerificationStatus.
var statusStrings = [...]string{
	StatusUnknown:       "unknown",
	StatusPass:          "pass",
	StatusFail:          "fail",
	StatusNotApplicable: "not_applicable",
	StatusNotMeasured:   "not_measured",
}

// String returns the stable wire representation.
func (s VerificationStatus) String() string {
	// Two-sided bound. VerificationStatus is an int-based type reachable from
	// JSON and from arithmetic, so a negative value is not hypothetical, and a
	// one-sided check indexes out of range and panics. A status this code
	// cannot name renders as unknown, which is also the fail-closed reading.
	if s >= 0 && int(s) < len(statusStrings) {
		return statusStrings[s]
	}
	return "unknown"
}

// IsTerminal reports whether the status represents a completed measurement
// that can participate in percentage calculations. Only PASS and FAIL are
// terminal. NOT_APPLICABLE and NOT_MEASURED are excluded from percentages
// (for different reasons: N/A genuinely does not apply; NOT_MEASURED has no
// valid data).
func (s VerificationStatus) IsTerminal() bool {
	return s == StatusPass || s == StatusFail
}

// MarshalJSON encodes the status as a JSON string.
func (s VerificationStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes a JSON string into a VerificationStatus.
// Unknown strings resolve to StatusUnknown (fail-closed).
func (s *VerificationStatus) UnmarshalJSON(data []byte) error {
	// A payload that is not a JSON string is not an error here, it is simply a
	// status we cannot name, and an unnameable status must decode to unknown
	// rather than abort the surrounding record. Unmarshalling into the empty
	// string on failure keeps that intent without discarding a checked error:
	// ParseVerificationStatus maps "" to StatusUnknown, which is the same
	// fail-closed result, so there is no error to swallow.
	var raw string
	if json.Unmarshal(data, &raw) != nil {
		raw = ""
	}
	*s = ParseVerificationStatus(raw)
	return nil
}

// ParseVerificationStatus maps a wire string to its typed value.
// Unrecognised strings return StatusUnknown (fail-closed: never PASS).
func ParseVerificationStatus(raw string) VerificationStatus {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pass":
		return StatusPass
	case "fail":
		return StatusFail
	case "not_applicable":
		return StatusNotApplicable
	case "not_measured":
		return StatusNotMeasured
	default:
		return StatusUnknown
	}
}

// ErrMissingApplicabilityReason is returned when a NOT_APPLICABLE result
// does not carry a reason explaining why the path cannot apply.
var ErrMissingApplicabilityReason = errors.New("not_applicable status requires a reason")

// VerificationResult pairs a status with an optional reason and detail.
// For StatusNotApplicable the Reason field is mandatory.
type VerificationResult struct {
	Status VerificationStatus `json:"status"`
	Reason string             `json:"reason,omitempty"`
	Detail string             `json:"detail,omitempty"`
}

// Validate checks internal consistency. A NOT_APPLICABLE result without a
// reason is rejected.
func (r VerificationResult) Validate() error {
	if r.Status == StatusNotApplicable && strings.TrimSpace(r.Reason) == "" {
		return ErrMissingApplicabilityReason
	}
	return nil
}

// AggregateResults computes honest summary statistics over a set of results.
//
// Percentage is computed ONLY over terminal (PASS + FAIL) results. If any
// result is NOT_MEASURED the set is flagged and the unmeasured count is
// reported separately — a percentage over a set containing unmeasured
// records would be dishonest.
//
// Unknown statuses are counted and treated as non-passing (they contribute
// to the total but not to any success metric).
func AggregateResults(results []VerificationResult) VerificationSummary {
	var s VerificationSummary
	s.Total = len(results)
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Passed++
		case StatusFail:
			s.Failed++
		case StatusNotApplicable:
			s.NotApplicable++
		case StatusNotMeasured:
			s.NotMeasured++
		default:
			s.Unknown++
		}
	}
	s.Measured = s.Passed + s.Failed
	if s.Measured > 0 {
		s.PassPercentage = (s.Passed * 100) / s.Measured
	}
	return s
}

// VerificationSummary holds aggregated counts from AggregateResults.
type VerificationSummary struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	NotApplicable int `json:"not_applicable"`
	NotMeasured   int `json:"not_measured"`
	Unknown       int `json:"unknown"`

	// Measured is Passed + Failed: the denominator for PassPercentage.
	Measured int `json:"measured"`

	// PassPercentage is (Passed * 100) / Measured. It is zero when
	// Measured is zero. It is NEVER computed over unmeasured records.
	PassPercentage int `json:"pass_percentage"`
}

// HonestPercentage returns the pass percentage and reports whether it is
// fully trustworthy. When NotMeasured > 0 the percentage is technically
// correct (computed only over measured records) but the caller should
// surface the gap. When Measured == 0 the percentage is meaningless.
func (s VerificationSummary) HonestPercentage() (pct int, hasUnmeasured bool, hasMeasured bool) {
	return s.PassPercentage, s.NotMeasured > 0, s.Measured > 0
}

// FormatPercentage returns a human-readable percentage string that honestly
// discloses unmeasured gaps. Examples:
//
//	"75% (3/4 measured; 2 not measured)"
//	"100% (5/5 measured)"
//	"no measured results"
func (s VerificationSummary) FormatPercentage() string {
	if s.Measured == 0 {
		return "no measured results"
	}
	base := fmt.Sprintf("%d%% (%d/%d measured", s.PassPercentage, s.Passed, s.Measured)
	if s.NotMeasured > 0 {
		return base + fmt.Sprintf("; %d not measured)", s.NotMeasured)
	}
	return base + ")"
}
