// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const (
	defaultVersion       = "0.0.0-dev.unknown"
	sourceRevisionLength = 12
)

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
	// A real module version (go install pkg@vX.Y.Z, or a pseudo-version) is
	// authoritative and carries no VCS settings. When VCS settings ARE present
	// we are building from a source tree, so prefer the truthful commit-derived
	// version over any module version Go may have attached.
	if info.Main.Version != "" && info.Main.Version != "(devel)" && !hasVCSBuildSettings(info.Settings) {
		Version = strings.TrimPrefix(info.Main.Version, "v")
		return
	}
	Version = sourceVersionFromBuildSettings(info.Settings)
}

func hasVCSBuildSettings(settings []debug.BuildSetting) bool {
	for _, setting := range settings {
		if setting.Key == "vcs" || strings.HasPrefix(setting.Key, "vcs.") {
			return true
		}
	}
	return false
}

func sourceVersionFromBuildSettings(settings []debug.BuildSetting) string {
	revision := ""
	commitDate := ""
	// Default to dirty: never imply a clean tree from missing, duplicated, or
	// unparseable vcs.modified. Only an explicit vcs.modified=false clears it.
	dirty := true
	revisionSeen := false
	commitTimeSeen := false
	modifiedSeen := false

	for _, setting := range settings {
		switch setting.Key {
		case "vcs.revision":
			if revisionSeen {
				revision = ""
				continue
			}
			revisionSeen = true
			if isLowerHex(setting.Value) {
				revision = setting.Value
				if len(revision) > sourceRevisionLength {
					revision = revision[:sourceRevisionLength]
				}
			}
		case "vcs.time":
			if commitTimeSeen {
				commitDate = ""
				continue
			}
			commitTimeSeen = true
			commitTime, err := time.Parse(time.RFC3339, setting.Value)
			if err == nil {
				commitDate = commitTime.UTC().Format("20060102")
			}
		case "vcs.modified":
			if modifiedSeen {
				dirty = true
				continue
			}
			modifiedSeen = true
			modified, err := strconv.ParseBool(setting.Value)
			dirty = err != nil || modified
		}
	}

	if revision == "" {
		if modifiedSeen && dirty {
			return defaultVersion + ".dirty"
		}
		return defaultVersion
	}
	if commitDate == "" {
		commitDate = "unknown-date"
	}

	version := fmt.Sprintf("0.0.0-dev.%s.g%s", commitDate, revision)
	if dirty {
		version += ".dirty"
	}
	return version
}

func isLowerHex(s string) bool {
	if len(s) < sourceRevisionLength {
		return false
	}
	for _, char := range s {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// DisplayVersion normalizes build metadata for human-facing banners.
func DisplayVersion() string {
	if Version == "" {
		return "dev"
	}
	return "v" + strings.TrimPrefix(Version, "v")
}
