// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"runtime/debug"
	"strings"
)

const defaultVersion = "0.1.0-dev"

// Build metadata, set at build time via ldflags. Defaults are used when
// building with plain "go build" (without the Makefile).
var (
	Version   = defaultVersion
	BuildDate = "unknown"
	GitCommit = "unknown"
	GoVersion = "unknown"

	readBuildInfo = debug.ReadBuildInfo
)

func init() {
	resolveVersionFromBuildInfo()
}

func resolveVersionFromBuildInfo() {
	if Version != defaultVersion {
		return
	}
	info, ok := readBuildInfo()
	if !ok || info == nil {
		return
	}
	if info.Main.Version == "" || info.Main.Version == "(devel)" {
		return
	}
	Version = strings.TrimPrefix(info.Main.Version, "v")
}

// DisplayVersion normalizes build metadata for human-facing banners.
func DisplayVersion() string {
	if Version == "" {
		return "dev"
	}
	return "v" + strings.TrimPrefix(Version, "v")
}
