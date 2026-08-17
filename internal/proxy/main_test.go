// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
)

// TestMain pins the posture proof path into a temporary directory so this
// package's tests never read the host's containment state.
//
// buildReceiptEmitterStage calls posturebinding.LoadRuntime, which without an
// override reads the absolute DefaultContainRunProofPath under
// /var/lib/pipelock. That directory does not exist on a clean CI runner, so the
// proof reads as absent and the emitter is built; `pipelock contain install`
// creates it 0o750 owned by pipelock-proxy, so on a developer machine the read
// fails and the stage returns an error instead. The receipt reload tests then
// fail reporting a nil emitter, which names the symptom rather than the cause
// and sends the reader looking for a receipt bug that is not there.
//
// The pinned path names a file that is deliberately never created, matching the
// absent-proof state CI runs in. See internal/cli/runtime/main_test.go, which
// pins the same variable for the same reason.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pipelock-proxy-test-posture-*")
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
