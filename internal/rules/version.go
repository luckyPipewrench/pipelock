// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// CalVer represents a calendar version in YYYY.MM.patch format.
// Numeric comparison per segment is required because variable-width
// patch numbers make string comparison unsafe (e.g., "9" > "10").
type CalVer struct {
	Year  int
	Month int
	Patch int
}

// ParseCalVer parses a CalVer string in YYYY.MM.patch format.
// It validates that the year is exactly 4 digits, the month is 01-12,
// and the patch is a non-negative integer.
func ParseCalVer(s string) (CalVer, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return CalVer{}, fmt.Errorf("calver: expected 3 segments, got %d in %q", len(parts), s)
	}

	// Year: must be exactly 4 digits, no leading zeros for sub-1000 years.
	yearStr := parts[0]
	if len(yearStr) != 4 {
		return CalVer{}, fmt.Errorf("calver: year must be exactly 4 digits, got %q", yearStr)
	}

	year, err := strconv.Atoi(yearStr)
	if err != nil {
		return CalVer{}, fmt.Errorf("calver: invalid year %q: %w", yearStr, err)
	}

	// Reject leading zeros: a 4-digit year starting with 0 (like "0026") is invalid.
	if yearStr[0] == '0' {
		return CalVer{}, fmt.Errorf("calver: year must not have leading zero, got %q", yearStr)
	}

	// Month: must be 01-12.
	monthStr := parts[1]

	month, err := strconv.Atoi(monthStr)
	if err != nil {
		return CalVer{}, fmt.Errorf("calver: invalid month %q: %w", monthStr, err)
	}

	if month < 1 || month > 12 {
		return CalVer{}, fmt.Errorf("calver: month must be 1-12, got %d", month)
	}

	// Patch: must be a non-negative integer.
	patchStr := parts[2]

	patch, err := strconv.Atoi(patchStr)
	if err != nil {
		return CalVer{}, fmt.Errorf("calver: invalid patch %q: %w", patchStr, err)
	}

	if patch < 0 {
		return CalVer{}, fmt.Errorf("calver: patch must be non-negative, got %d", patch)
	}

	return CalVer{Year: year, Month: month, Patch: patch}, nil
}

// Compare returns -1 if v < other, 0 if equal, or 1 if v > other.
// Comparison is numeric per segment: year, then month, then patch.
func (v CalVer) Compare(other CalVer) int {
	if v.Year != other.Year {
		return cmpInt(v.Year, other.Year)
	}

	if v.Month != other.Month {
		return cmpInt(v.Month, other.Month)
	}

	return cmpInt(v.Patch, other.Patch)
}

// String returns the CalVer in YYYY.MM.patch format with zero-padded month.
func (v CalVer) String() string {
	return fmt.Sprintf("%04d.%02d.%d", v.Year, v.Month, v.Patch)
}

// cmpInt returns -1, 0, or 1 for integer comparison.
func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
