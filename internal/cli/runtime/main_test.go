// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
)

// TestMain pins the posture proof path into a temporary directory so this
// package's tests never read the host's containment state.
//
// Without the override, posturebinding.LoadRuntime falls back to the absolute
// DefaultContainRunProofPath under /var/lib/pipelock, which `pipelock contain
// install` creates 0o750 and owns as pipelock-proxy. A clean CI runner has no
// such directory, so the proof reads as absent and server construction takes
// its no-attested-containment path; a developer machine with containment
// installed cannot traverse it, so the same construction fails with a
// permission error and every server- or guard-building test in this package
// fails for a reason unrelated to the code under test.
//
// The pinned path names a file that is deliberately never created. An absent
// proof yields the zero binding, which is exactly the state CI runs in, so the
// tests assert the same behavior on both. Writing a synthetic proof here would
// instead silently move every test into the attested-containment path and
// change what they cover.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pipelock-runtime-test-posture-*")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv(posturebinding.RuntimeProofEnv, filepath.Join(dir, "absent-proof.json")); err != nil {
		panic(err)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
