// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"
)

func TestParseCalVer(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name string
		in   string
		want CalVer
	}{
		{"basic", "2026.03.1", CalVer{Year: 2026, Month: 3, Patch: 1}},
		{"january zero patch", "2026.01.0", CalVer{Year: 2026, Month: 1, Patch: 0}},
		{"december high patch", "2026.12.99", CalVer{Year: 2026, Month: 12, Patch: 99}},
		{"far future", "2030.06.42", CalVer{Year: 2030, Month: 6, Patch: 42}},
	}

	for _, tc := range valid {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseCalVer(tc.in)
			if err != nil {
				t.Fatalf("ParseCalVer(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseCalVer(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}

	invalid := []struct {
		name string
		in   string
	}{
		{"empty string", ""},
		{"two segments", "2026.03"},
		{"four segments", "2026.03.1.0"},
		{"non-numeric year", "abcd.03.1"},
		{"non-numeric month", "2026.ab.1"},
		{"non-numeric patch", "2026.03.x"},
		{"month zero", "2026.00.1"},
		{"month thirteen", "2026.13.1"},
		{"negative patch", "2026.03.-1"},
		{"leading zeros on year", "0026.03.1"},
		{"three-digit year", "202.03.1"},
		{"five-digit year", "20260.03.1"},
		{"trailing dot", "2026.03.1."},
		{"leading dot", ".2026.03.1"},
		{"spaces", " 2026.03.1 "},
	}

	for _, tc := range invalid {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseCalVer(tc.in)
			if err == nil {
				t.Errorf("ParseCalVer(%q) expected error, got nil", tc.in)
			}
		})
	}
}

func TestCalVerCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{"equal", "2026.03.1", "2026.03.1", 0},
		{"year less", "2025.03.1", "2026.03.1", -1},
		{"year greater", "2027.03.1", "2026.03.1", 1},
		{"month less", "2026.02.1", "2026.03.1", -1},
		{"month greater", "2026.04.1", "2026.03.1", 1},
		{"patch less", "2026.03.0", "2026.03.1", -1},
		{"patch greater", "2026.03.2", "2026.03.1", 1},
		// String comparison trap: "9" > "10" lexicographically, but 9 < 10 numerically.
		{"string comparison trap", "2026.03.9", "2026.03.10", -1},
		{"high patch vs low patch", "2026.03.10", "2026.03.9", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := ParseCalVer(tc.a)
			if err != nil {
				t.Fatalf("ParseCalVer(%q): %v", tc.a, err)
			}
			b, err := ParseCalVer(tc.b)
			if err != nil {
				t.Fatalf("ParseCalVer(%q): %v", tc.b, err)
			}
			got := a.Compare(b)
			if got != tc.want {
				t.Errorf("%s.Compare(%s) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestCalVerString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    CalVer
		want string
	}{
		{"basic", CalVer{Year: 2026, Month: 3, Patch: 1}, "2026.03.1"},
		{"january", CalVer{Year: 2026, Month: 1, Patch: 0}, "2026.01.0"},
		{"december", CalVer{Year: 2026, Month: 12, Patch: 99}, "2026.12.99"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.v.String()
			if got != tc.want {
				t.Errorf("CalVer%+v.String() = %q, want %q", tc.v, got, tc.want)
			}
		})
	}
}

func TestCalVerRoundTrip(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"2026.03.1",
		"2026.01.0",
		"2026.12.99",
		"2030.06.42",
	}

	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			v, err := ParseCalVer(in)
			if err != nil {
				t.Fatalf("ParseCalVer(%q): %v", in, err)
			}
			got := v.String()
			if got != in {
				t.Errorf("round-trip: ParseCalVer(%q).String() = %q", in, got)
			}
		})
	}
}
