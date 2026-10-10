// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package scanner

import (
	"os"
	"path/filepath"
)

// openFixtureNonblocking opens path read-only. Platforms without Unix FIFOs
// have no open that can block on a missing writer.
func openFixtureNonblocking(path string) (*os.File, error) {
	return os.Open(filepath.Clean(path))
}
