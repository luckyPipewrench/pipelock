// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testposture"
)

// TestMain isolates this package's tests from the host's containment posture
// state. Server and guard construction here call posturebinding.LoadRuntime;
// testposture.PinAbsent documents why an absent proof is the state under test.
func TestMain(m *testing.M) {
	cleanup, err := testposture.PinAbsent()
	if err != nil {
		panic(err)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}
