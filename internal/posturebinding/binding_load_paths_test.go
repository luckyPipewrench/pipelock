// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posturebinding

import (
	"path/filepath"
	"strings"
	"testing"
)

// A relative PIPELOCK_POSTURE_PROOF is refused rather than resolved against
// whatever directory the process happens to be in. Resolving it would make the
// proof a runtime attacker or a stray working directory could redirect, and
// the outcome would look attested. The refusal must carry both the invalid
// availability and an error, since callers that require containment evidence
// branch on availability while ordinary callers branch on the error.
func TestLoadRuntime_RejectsRelativeProofPath(t *testing.T) {
	for _, path := range []string{"proof.json", "./proof.json", "../proof.json", "relative/dir/proof.json"} {
		t.Run(path, func(t *testing.T) {
			t.Setenv(RuntimeProofEnv, path)

			result, err := loadRuntime(nil)
			if err == nil {
				t.Fatalf("loadRuntime with %s=%q returned no error; a relative proof path must be refused", RuntimeProofEnv, path)
			}
			if result.Availability != AvailabilityInvalid {
				t.Errorf("availability = %q, want %q", result.Availability, AvailabilityInvalid)
			}
			if result.Cause == nil {
				t.Error("result.Cause is nil; the refusal must be explainable to an operator")
			}
			if !strings.Contains(err.Error(), "absolute path") {
				t.Errorf("error = %v, want it to name the absolute-path requirement", err)
			}
			if result.HasContainmentAttestation() {
				t.Error("a refused relative path reported a containment attestation")
			}
		})
	}
}

// Surrounding whitespace must not smuggle a relative path past the absolute
// check, and a wholly blank value falls back to the default path rather than
// being treated as a configured one.
func TestLoadRuntime_TrimsProofPathBeforeDeciding(t *testing.T) {
	t.Run("padded relative path is still refused", func(t *testing.T) {
		t.Setenv(RuntimeProofEnv, "  proof.json  ")
		result, err := loadRuntime(nil)
		if err == nil {
			t.Fatal("a whitespace-padded relative path was accepted")
		}
		if result.Availability != AvailabilityInvalid {
			t.Errorf("availability = %q, want %q", result.Availability, AvailabilityInvalid)
		}
	})

	t.Run("blank value falls back to the default path", func(t *testing.T) {
		t.Setenv(RuntimeProofEnv, "   ")
		result, err := loadRuntime(nil)
		if result.Path != DefaultContainRunProofPath {
			t.Errorf("path = %q, want the default %q", result.Path, DefaultContainRunProofPath)
		}
		// Checking the path alone would pass even if the fallback had taken
		// the refusal branch and returned that same path as invalid. Assert
		// it did NOT, without asserting which valid outcome it reached: the
		// default proof file may or may not exist on the host running this.
		if err != nil {
			t.Errorf("loadRuntime after a blank value = error %v, want the fallback to be accepted", err)
		}
		if result.Availability == AvailabilityInvalid {
			t.Errorf("availability = %q, want the fallback not to be treated as a refused path", result.Availability)
		}
	})
}

// An empty path is "no proof configured", which is absent and not an error.
// Reporting it as invalid would make an unconfigured deployment look like a
// tampered one; reporting an error would break callers that do not require
// containment evidence.
func TestLoadFile_EmptyPathIsAbsentWithoutError(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"", "   ", "\t"} {
		result, err := loadFile(path, nil)
		if err != nil {
			t.Errorf("loadFile(%q) = error %v, want nil", path, err)
		}
		if result.Availability != AvailabilityAbsent {
			t.Errorf("loadFile(%q) availability = %q, want %q", path, result.Availability, AvailabilityAbsent)
		}
		if result.HasContainmentAttestation() {
			t.Errorf("loadFile(%q) reported a containment attestation", path)
		}
	}
}

// A missing proof file is absent, not invalid: nothing was tampered with, the
// file simply is not there.
func TestLoadFile_MissingPathIsAbsentWithoutError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "absent-proof.json")
	result, err := loadFile(path, nil)
	if err != nil {
		t.Fatalf("loadFile on a missing path = error %v, want nil", err)
	}
	if result.Availability != AvailabilityAbsent {
		t.Errorf("availability = %q, want %q", result.Availability, AvailabilityAbsent)
	}
	if result.Path != path {
		t.Errorf("path = %q, want %q", result.Path, path)
	}
}
