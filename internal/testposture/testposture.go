// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package testposture isolates a test binary from the host's containment
// posture state.
package testposture

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
)

// PinAbsent points posturebinding.RuntimeProofEnv at a file that does not exist,
// inside a temporary directory, and returns a cleanup function that removes the
// directory and restores the previous override.
//
// Packages that build a server, guard, or receipt emitter call
// posturebinding.LoadRuntime, which without an override reads an absolute path
// under /var/lib/pipelock. A clean CI runner has no such directory, so the proof
// reads as absent and construction proceeds. `pipelock contain install` creates
// it owned by pipelock-proxy and unreadable by other users, so on a machine with
// containment installed the read fails instead and tests fail for a reason
// unrelated to the code under test. Pinning an absent proof reproduces the CI
// state, so both environments assert the same behavior.
//
// The proof file is deliberately never created. An absent proof yields the zero
// binding, which is the state under test. Writing a synthetic proof would
// instead move every caller into the attested-containment path and silently
// change what those tests cover.
//
// cleanup is returned even when pinning fails, so a caller can defer it
// unconditionally. Callers run as TestMain, before any test has run, so an error
// here is returned rather than reported through testing.TB. The override is
// process-wide, so callers must pin once per binary rather than per test.
func PinAbsent() (cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "pipelock-test-posture-*")
	if err != nil {
		return func() {}, fmt.Errorf("creating posture temp dir: %w", err)
	}

	prior, hadPrior := os.LookupEnv(posturebinding.RuntimeProofEnv)
	restore := func() {
		if hadPrior {
			_ = os.Setenv(posturebinding.RuntimeProofEnv, prior)
		} else {
			_ = os.Unsetenv(posturebinding.RuntimeProofEnv)
		}
		_ = os.RemoveAll(dir)
	}

	return restore, pinInto(dir)
}

// dirMode grants the owner alone access to the pinned directory. os.MkdirTemp
// already creates it this way; setting it explicitly states the requirement
// rather than inheriting it from the standard library's current behavior.
const dirMode os.FileMode = 0o700

// pinInto prepares dir and points the override at an absent proof inside it.
//
// filepath.Abs resolves the relative path os.MkdirTemp returns when TMPDIR is
// relative, which LoadRuntime rejects rather than resolving against an ambiguous
// working directory.
func pinInto(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err == nil {
		err = os.Chmod(dir, dirMode)
	}
	if err == nil {
		err = os.Setenv(posturebinding.RuntimeProofEnv, filepath.Join(absDir, "absent-proof.json"))
	}
	if err != nil {
		return fmt.Errorf("pinning %s: %w", posturebinding.RuntimeProofEnv, err)
	}
	return nil
}
