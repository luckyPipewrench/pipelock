// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"runtime/debug"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/rules"
)

func TestDisplayVersionForStartupBanner(t *testing.T) {
	old := Version
	oldReadBuildInfo := readBuildInfo
	t.Cleanup(func() { Version = old })
	t.Cleanup(func() { readBuildInfo = oldReadBuildInfo })

	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "prefixed release", version: "v2.5.0", want: "Pipelock v2.5.0"},
		{name: "bare release", version: "2.5.0", want: "Pipelock v2.5.0"},
		{name: "prefixed rc", version: "v2.5.0-rc1", want: "Pipelock v2.5.0-rc1"},
		{name: "dev empty", version: "", want: "Pipelock dev"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version = tt.version
			banner := "Pipelock " + DisplayVersion() + " starting"
			if !strings.Contains(banner, tt.want) {
				t.Fatalf("banner %q does not contain %q", banner, tt.want)
			}
			if strings.Contains(banner, "Pipelock vv") {
				t.Fatalf("double-v banner: %q", banner)
			}
			if strings.Contains(banner, "Pipelock v starting") {
				t.Fatalf("empty version banner: %q", banner)
			}
		})
	}
}

func TestResolveVersionFromBuildInfo(t *testing.T) {
	oldVersion := Version
	oldReadBuildInfo := readBuildInfo
	t.Cleanup(func() {
		Version = oldVersion
		readBuildInfo = oldReadBuildInfo
	})

	tests := []struct {
		name       string
		version    string
		ok         bool
		want       string
		display    string
		checkMinOK string
	}{
		{
			name:       "module version",
			version:    "v3.0.0",
			ok:         true,
			want:       "3.0.0",
			display:    "v3.0.0",
			checkMinOK: "1.4.0",
		},
		{
			name:       "module version with build metadata",
			version:    "v3.0.0+metadata",
			ok:         true,
			want:       "3.0.0+metadata",
			display:    "v3.0.0+metadata",
			checkMinOK: "1.4.0",
		},
		{
			name:    "module pseudo-version",
			version: "v0.0.0-20260709120000-abcdefabcdef",
			ok:      true,
			want:    "0.0.0-20260709120000-abcdefabcdef",
			display: "v0.0.0-20260709120000-abcdefabcdef",
		},
		{
			name:    "devel version",
			version: "(devel)",
			ok:      true,
			want:    defaultVersion,
			display: "v" + defaultVersion,
		},
		{
			name:    "missing build info",
			version: "v3.0.0",
			ok:      false,
			want:    defaultVersion,
			display: "v" + defaultVersion,
		},
		{
			name:    "empty module version",
			version: "",
			ok:      true,
			want:    defaultVersion,
			display: "v" + defaultVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version = defaultVersion
			readBuildInfo = func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: tt.version}}, tt.ok
			}

			resolveVersionFromBuildInfo()

			if Version != tt.want {
				t.Fatalf("Version = %q, want %q", Version, tt.want)
			}
			if got := DisplayVersion(); got != tt.display {
				t.Fatalf("DisplayVersion() = %q, want %q", got, tt.display)
			}
			if tt.checkMinOK != "" {
				if err := rules.CheckMinPipelock(tt.checkMinOK, Version); err != nil {
					t.Fatalf("CheckMinPipelock() error = %v", err)
				}
			}
		})
	}
}

func TestResolveVersionFromBuildInfoKeepsLDFLagsVersion(t *testing.T) {
	oldVersion := Version
	oldReadBuildInfo := readBuildInfo
	t.Cleanup(func() {
		Version = oldVersion
		readBuildInfo = oldReadBuildInfo
	})

	Version = "9.9.9"
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		panic("readBuildInfo should not be consulted when Version is set by ldflags")
	}

	resolveVersionFromBuildInfo()

	if Version != "9.9.9" {
		t.Fatalf("Version = %q, want 9.9.9", Version)
	}
	if got := DisplayVersion(); got != "v9.9.9" {
		t.Fatalf("DisplayVersion() = %q, want v9.9.9", got)
	}
}
