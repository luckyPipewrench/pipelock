// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
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
		name     string
		version  string
		settings []debug.BuildSetting
		ok       bool
		want     string
	}{
		{
			name:    "clean VCS source build",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2eabcdef0123456789abcdef012345"},
				{Key: "vcs.time", Value: "2026-07-22T01:30:00+02:00"},
				{Key: "vcs.modified", Value: "false"},
			},
			ok:   true,
			want: "0.0.0-dev.20260721.g680cd0614d2e",
		},
		{
			name:    "dirty VCS source build",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2eabcdef"},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.modified", Value: "true"},
			},
			ok:   true,
			want: "0.0.0-dev.20260721.g680cd0614d2e.dirty",
		},
		{
			name:    "Go synthesized source pseudo-version uses VCS settings",
			version: "v1.5.1-0.20260721120000-680cd0614d2e+dirty",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2eabcdef"},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.modified", Value: "true"},
			},
			ok:   true,
			want: "0.0.0-dev.20260721.g680cd0614d2e.dirty",
		},
		{
			name:    "revision without commit time",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2e"},
			},
			ok:   true,
			want: "0.0.0-dev.unknown-date.g680cd0614d2e.dirty",
		},
		{
			name:    "clean revision without commit time",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2e"},
				{Key: "vcs.modified", Value: "false"},
			},
			ok:   true,
			want: "0.0.0-dev.unknown-date.g680cd0614d2e",
		},
		{
			name:    "devel version without VCS settings",
			version: "(devel)",
			ok:      true,
			want:    defaultVersion,
		},
		{
			name:    "empty module version uses VCS settings",
			version: "",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abcdef1234567890"},
				{Key: "vcs.time", Value: "2026-06-10T08:00:00Z"},
			},
			ok:   true,
			want: "0.0.0-dev.20260610.gabcdef123456.dirty",
		},
		{
			name:    "malformed uppercase revision",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680CD0614D2E"},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
			},
			ok:   true,
			want: defaultVersion,
		},
		{
			name:    "malformed non-hex revision",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2z"},
			},
			ok:   true,
			want: defaultVersion,
		},
		{
			name:    "malformed short revision",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2"},
				{Key: "vcs.modified", Value: "false"},
			},
			ok:   true,
			want: defaultVersion,
		},
		{
			name:    "malformed commit time",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2e"},
				{Key: "vcs.time", Value: "yesterday"},
			},
			ok:   true,
			want: "0.0.0-dev.unknown-date.g680cd0614d2e.dirty",
		},
		{
			name:    "malformed modified value",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2e"},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.modified", Value: "dirty"},
			},
			ok:   true,
			want: "0.0.0-dev.20260721.g680cd0614d2e.dirty",
		},
		{
			name:    "conflicting modified settings are not clean",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2e"},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.modified", Value: "true"},
				{Key: "vcs.modified", Value: "false"},
			},
			ok:   true,
			want: "0.0.0-dev.20260721.g680cd0614d2e.dirty",
		},
		{
			name:    "duplicate VCS settings degrade to unknown dirty",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2eabcdef"},
				{Key: "vcs.revision", Value: "abcdef1234567890"},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.time", Value: "2026-07-22T23:59:59Z"},
				{Key: "vcs.modified", Value: "false"},
				{Key: "vcs.modified", Value: "false"},
			},
			ok:   true,
			want: defaultVersion + ".dirty",
		},
		{
			name:    "dirty without usable revision",
			version: "(devel)",
			settings: []debug.BuildSetting{
				{Key: "vcs.modified", Value: "true"},
			},
			ok:   true,
			want: defaultVersion + ".dirty",
		},
		{
			name:    "tagged installed module version unchanged",
			version: "v3.0.0+metadata",
			ok:      true,
			want:    "3.0.0+metadata",
		},
		{
			name:    "installed module pseudo-version unchanged",
			version: "v0.0.0-20260709120000-abcdefabcdef",
			ok:      true,
			want:    "0.0.0-20260709120000-abcdefabcdef",
		},
		{
			name:    "missing build info",
			version: "v3.0.0",
			ok:      false,
			want:    defaultVersion,
		},
		{
			name:    "empty module version without VCS settings",
			version: "",
			ok:      true,
			want:    defaultVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version = defaultVersion
			readBuildInfo = func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{
					Main:     debug.Module{Version: tt.version},
					Settings: tt.settings,
				}, tt.ok
			}

			resolveVersionFromBuildInfo()

			if Version != tt.want {
				t.Fatalf("Version = %q, want %q", Version, tt.want)
			}
			if got := DisplayVersion(); got != "v"+tt.want {
				t.Fatalf("DisplayVersion() = %q, want %q", got, "v"+tt.want)
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

func TestIsProductReleaseTag(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		// Valid final releases
		{"v0.0.0", true},
		{"v1.2.3", true},
		{"v10.20.30", true},
		{"v3.2.0", true},

		// Valid prereleases (the exact case that was broken: preflight passes, cosign must too)
		{"v3.2.0-rc1", true},
		{"v3.2.0-alpha.1", true},
		{"v3.2.0-0.3.7", true},
		{"v1.0.0-beta.11", true},
		{"v1.0.0-x.7.z.92", true},
		{"v1.2.3-" + strings.Repeat("a", 122), true}, // 128 chars after stripping v

		// Invalid: build metadata (+ is invalid in OCI tags)
		{"v1.2.3+build", false},
		{"v1.2.3-rc1+meta", false},
		{"v1.2.3-" + strings.Repeat("a", 123), false}, // exceeds OCI tag limit

		// Invalid: missing v prefix
		{"1.2.3", false},

		// Invalid: leading zeros
		{"v01.2.3", false},
		{"v1.02.3", false},
		{"v1.2.03", false},

		// Invalid: too few/many segments
		{"v1.2", false},
		{"v1.2.3.4", false},

		// Invalid: non-product prefixes
		{"verifier-v0.2.0", false},

		// Invalid: misc
		{"", false},
		{"v", false},
		{"vx.y.z", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := IsProductReleaseTag(tt.tag); got != tt.want {
				t.Fatalf("IsProductReleaseTag(%q) = %v, want %v", tt.tag, got, tt.want)
			}
		})
	}
}

// TestProductReleaseTag_PrereleaseAccepted guards the release-policy decision
// that prerelease tags are valid product releases.
func TestProductReleaseTag_PrereleaseAccepted(t *testing.T) {
	prereleases := []string{"v3.2.0-rc1", "v1.0.0-alpha.1", "v2.0.0-beta.2"}

	for _, tag := range prereleases {
		t.Run(tag, func(t *testing.T) {
			if !IsProductReleaseTag(tag) {
				t.Fatalf("IsProductReleaseTag(%q) = false; prerelease must pass release policy", tag)
			}
		})
	}
}

// TestProductReleaseTag_ParityWithReleaseSurfaces binds the shell format/length
// guards to Go and requires the Action to verify the exact downloaded tag.
func TestProductReleaseTag_ParityWithReleaseSurfaces(t *testing.T) {
	// Locate repo root from the test file's package path.
	// internal/cliutil -> ../../ is the repo root.
	root := filepath.Join("..", "..")
	findLines := func(content, prefix string) []string {
		var matches []string
		for _, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, prefix) {
				matches = append(matches, trimmed)
			}
		}
		return matches
	}

	t.Run("check-release-ready.sh", func(t *testing.T) {
		path := filepath.Join(root, "scripts", "check-release-ready.sh")
		data, err := os.ReadFile(path) // #nosec G304 -- path is a compile-time constant relative to the repo root
		if err != nil {
			t.Fatalf("reading check-release-ready.sh: %v", err)
		}
		content := string(data)
		const patternMarker = "release_tag_re='"
		start := strings.Index(content, patternMarker)
		if start < 0 {
			t.Fatal("check-release-ready.sh does not assign release_tag_re")
		}
		rest := content[start+len(patternMarker):]
		end := strings.IndexByte(rest, '\'')
		if end < 0 {
			t.Fatal("check-release-ready.sh has an unterminated release_tag_re")
		}
		if got := rest[:end]; got != ProductReleaseTagPattern {
			t.Fatalf("check-release-ready.sh release_tag_re diverges from canonical.\n  got:  %s\n  want: %s", got, ProductReleaseTagPattern)
		}

		wantMax := "max_product_release_version_length=" + strconv.Itoa(MaxProductReleaseVersionLength)
		if got := findLines(content, "max_product_release_version_length="); len(got) != 1 || got[0] != wantMax {
			t.Fatalf("check-release-ready.sh OCI length assignment diverges: got %q, want [%q]", got, wantMax)
		}
		const lengthGuard = `if [ "${#VER}" -gt "$max_product_release_version_length" ]; then`
		if got := findLines(content, `if [ "${#VER}" -gt `); len(got) != 1 || got[0] != lengthGuard {
			t.Fatalf("check-release-ready.sh OCI length guard diverges: got %q, want [%q]", got, lengthGuard)
		}
	})

	t.Run("action.yml exact cosign identity", func(t *testing.T) {
		path := filepath.Join(root, "action.yml")
		data, err := os.ReadFile(path) // #nosec G304 -- path is a compile-time constant relative to the repo root
		if err != nil {
			t.Fatalf("reading action.yml: %v", err)
		}
		content := string(data)
		const want = `--certificate-identity "https://github.com/luckyPipewrench/pipelock/.github/workflows/release.yaml@refs/tags/v${VERSION}" \`
		if got := findLines(content, `--certificate-identity `); len(got) != 1 || got[0] != want {
			t.Fatalf("action.yml exact cosign identity diverges: got %q, want [%q]", got, want)
		}
		if strings.Contains(content, "--certificate-identity-regexp") {
			t.Fatal("action.yml still uses a broad cosign certificate identity regexp")
		}
	})
}

func TestSourceVersionFromBuildSettingsArtifactSafety(t *testing.T) {
	artifactPattern := regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
	tests := []struct {
		name     string
		settings []debug.BuildSetting
	}{
		{name: "absent settings"},
		{
			name: "clean dated revision",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2eabcdef"},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.modified", Value: "false"},
			},
		},
		{
			name: "dirty dated revision",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2eabcdef"},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.modified", Value: "true"},
			},
		},
		{
			name: "overlong revision",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: strings.Repeat("a", 1024)},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.modified", Value: "false"},
			},
		},
		{
			name: "malformed fields",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "NOT-A-REVISION"},
				{Key: "vcs.time", Value: "not-a-time"},
				{Key: "vcs.modified", Value: "not-a-bool"},
			},
		},
		{
			name: "duplicate fields",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "680cd0614d2eabcdef"},
				{Key: "vcs.revision", Value: strings.Repeat("f", 128)},
				{Key: "vcs.time", Value: "2026-07-21T23:59:59Z"},
				{Key: "vcs.time", Value: "not-a-time"},
				{Key: "vcs.modified", Value: "false"},
				{Key: "vcs.modified", Value: "false"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := sourceVersionFromBuildSettings(tt.settings)
			if len(version) > 63 {
				t.Fatalf("version length = %d, want at most 63: %q", len(version), version)
			}
			if !artifactPattern.MatchString(version) {
				t.Fatalf("version is not OCI tag/Kubernetes label safe: %q", version)
			}
		})
	}
}
