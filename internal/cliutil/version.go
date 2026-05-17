// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import "strings"

// Build metadata, set at build time via ldflags. Defaults are used when
// building with plain "go build" (without the Makefile).
var (
	Version   = "0.1.0-dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
	GoVersion = "unknown"
)

// DisplayVersion normalizes build metadata for human-facing banners.
func DisplayVersion() string {
	if Version == "" {
		return "dev"
	}
	return "v" + strings.TrimPrefix(Version, "v")
}
