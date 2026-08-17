// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"os"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testposture"
)

// TestMain isolates this package's tests from the host's containment posture
// state. buildReceiptEmitterStage calls posturebinding.LoadRuntime, and when
// that read fails the stage returns an error, so the receipt reload tests fail
// reporting a nil emitter rather than the underlying cause. See
// testposture.PinAbsent.
func TestMain(m *testing.M) {
	cleanup, err := testposture.PinAbsent()
	if err != nil {
		panic(err)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}
