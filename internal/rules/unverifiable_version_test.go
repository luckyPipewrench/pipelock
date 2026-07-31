// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"testing"
)

// TestErrUnverifiableVersionOnlyMarksTheUnknownCase is load-bearing for the
// operator CLI. Install downgrades ONLY this sentinel to a warning, so if a
// genuinely-unmet requirement also matched it, the CLI would quietly install a
// bundle the running release does not satisfy -- turning a refusal into a
// warning for the wrong case.
func TestErrUnverifiableVersionOnlyMarksTheUnknownCase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		minVersion     string
		curVersion     string
		wantErr        bool
		wantUnverified bool
	}{
		// Cannot be checked either way: safe to downgrade to a warning.
		{"source build", "3.0.0", "0.0.0-dev.unknown", true, true},
		{"devel", "3.0.0", "devel", true, true},
		{"unset", "3.0.0", "", true, true},
		{"git describe", "3.0.0", "2.0.0-147-gf1c242a0", true, true},
		{"git describe always bare commit", "3.0.0", "9cc0fe5", true, true},

		// Checked and genuinely NOT met: must never be downgraded.
		{"release below min", "3.0.0", "2.9.0", true, false},
		{"major below min", "2.0.0", "1.9.9", true, false},

		// Checked and malformed: fails closed, and is not the unknown case.
		{"malformed version", "3.0.0", "not-a-version", true, false},
		{"short hex version", "3.0.0", "abc123", true, false},

		// Requirement satisfied: no error at all.
		{"release meets min", "2.0.0", "3.0.0", false, false},
		{"dirty tag meets its own min", "2.3.0", "2.3.0-dirty", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckMinPipelock(tc.minVersion, tc.curVersion, false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckMinPipelock(%q, %q) error = %v, wantErr = %v",
					tc.minVersion, tc.curVersion, err, tc.wantErr)
			}
			if got := errors.Is(err, ErrUnverifiableVersion); got != tc.wantUnverified {
				t.Errorf("errors.Is(err, ErrUnverifiableVersion) = %v, want %v (err = %v)",
					got, tc.wantUnverified, err)
			}
		})
	}
}
