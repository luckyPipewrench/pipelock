// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "pipelock-diag-test-xdg-*")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("XDG_DATA_HOME", tmp); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}
