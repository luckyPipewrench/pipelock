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

// dirMode matches the repository's directory permission convention.
const dirMode os.FileMode = 0o750

// PinAbsent points posturebinding.RuntimeProofEnv at a file that does not exist,
// inside a temporary directory, and returns a cleanup function that removes it.
//
// Packages that build a server, guard, or receipt emitter call
// posturebinding.LoadRuntime, which without an override reads an absolute path
// under /var/lib/pipelock. A clean CI runner has no such directory, so the proof
// reads as absent and construction proceeds. `pipelock contain install` creates
// it 0o750 owned by pipelock-proxy, so on a machine with containment installed
// the read fails instead and tests fail for a reason unrelated to the code under
// test. Pinning an absent proof reproduces the CI state, so both environments
// assert the same behavior.
//
// The proof file is deliberately never created. An absent proof yields the zero
// binding, which is the state under test. Writing a synthetic proof would
// instead move every caller into the attested-containment path and silently
// change what those tests cover.
//
// The temporary directory is normalized to an absolute path because
// os.MkdirTemp returns a relative path when TMPDIR is relative, and LoadRuntime
// rejects a relative override rather than resolving it against an ambiguous
// working directory. Callers run as TestMain, before any test has run, so an
// error here is returned rather than reported through testing.TB.
func PinAbsent() (cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "pipelock-test-posture-*")
	if err != nil {
		return func() {}, fmt.Errorf("creating posture temp dir: %w", err)
	}

	// cleanup is returned even when pinning fails, so a caller can defer it
	// unconditionally and cannot leak the directory by handling the error first.
	return func() { _ = os.RemoveAll(dir) }, pinInto(dir)
}

// pinInto prepares dir and points the override at an absent proof inside it.
//
// os.MkdirTemp creates 0o700, so the mode is widened to the repository's
// directory convention. filepath.Abs resolves the relative path os.MkdirTemp
// returns when TMPDIR is relative, which LoadRuntime would otherwise reject.
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
