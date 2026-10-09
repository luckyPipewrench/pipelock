// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestHasExactBuildIdentity(t *testing.T) {
	originalVersion, originalCommit := Version, GitCommit
	t.Cleanup(func() {
		Version = originalVersion
		GitCommit = originalCommit
	})

	tests := []struct {
		name     string
		version  string
		commit   string
		expected bool
	}{
		{name: "release stamps", version: "3.5.0", commit: "abcdef012345", expected: true},
		{name: "described source stamps", version: "3.5.0-101-gabcdef0", commit: "abcdef0", expected: true},
		{name: "missing version", commit: "abcdef012345"},
		{name: "unknown version", version: "unknown", commit: "abcdef012345"},
		{name: "default version", version: defaultVersion, commit: "abcdef012345"},
		{name: "dirty default version", version: defaultVersion + ".dirty", commit: "abcdef012345"},
		{name: "missing revision", version: "3.5.0"},
		{name: "unknown revision", version: "3.5.0", commit: "unknown"},
		{name: "whitespace unknown revision", version: "3.5.0", commit: " unknown "},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			Version = test.version
			GitCommit = test.commit
			if got := HasExactBuildIdentity(); got != test.expected {
				t.Fatalf("HasExactBuildIdentity() = %v, want %v", got, test.expected)
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
		// Exactly two exact identities: the current repository and its
		// pipelab-org home after the move, each bound to the downloaded tag.
		const want = `--certificate-identity "https://github.com/${owner}/pipelock/.github/workflows/release.yaml@refs/tags/v${VERSION}" \`
		if got := findLines(content, `--certificate-identity `); len(got) != 1 || got[0] != want {
			t.Fatalf("action.yml exact cosign identity diverges: got %q, want [%q]", got, want)
		}
		const owners = `for owner in luckyPipewrench pipelab-org; do`
		if got := findLines(content, `for owner in `); len(got) != 1 || got[0] != owners {
			t.Fatalf("action.yml cosign signer owners diverge: got %q, want [%q]", got, owners)
		}
		if got := findLines(content, `if [ "$verified" != true ]; then`); len(got) != 1 {
			t.Fatalf("action.yml must fail closed when no identity verifies: got %q", got)
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

// Exercise the actual action loop under the runner's shell flags. Text parity
// alone cannot prove that rejected signatures stop installation.
func TestActionCosignVerification(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required to exercise the action's verification loop")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start := strings.Index(source, "            verified=false")
	if start < 0 {
		// Still execute the loop if its initial state changes; the rejection
		// cases must catch an initialization that would accept failures.
		start = strings.Index(source, "            verified=")
	}
	if start < 0 {
		t.Fatal("action verification initialization not found")
	}
	end := strings.Index(source[start:], "            echo \"Cosign signature verified.\"")
	if end < 0 {
		t.Fatal("action verification success marker not found")
	}
	loop := source[start : start+end]
	const mock = `calls=0
cosign() {
  calls=$((calls+1))
  printf 'IDENTITY:%s\nISSUER:%s\n' "$7" "$9"
  echo "Verified OK (output alone must not grant trust)"
  if [ "$calls" -eq 1 ]; then return "$FIRST_STATUS"; fi
  return "$SECOND_STATUS"
}
`
	tests := []struct {
		name          string
		first, second string
		wantSuccess   bool
		wantCalls     int
	}{
		{"original signer", "0", "1", true, 1},
		{"organization signer", "1", "0", true, 2},
		{"both reject", "1", "1", false, 2},
		{"usage error", "2", "2", false, 2},
		{"command disappears", "127", "127", false, 2},
		{"process killed", "137", "137", false, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// #nosec G204 -- executes the checked-in action loop with a local mock, not external input.
			cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", mock+loop+"\necho ACTION_CONTINUED\n")
			cmd.Env = append(os.Environ(),
				"FIRST_STATUS="+tt.first, "SECOND_STATUS="+tt.second,
				"VERSION=3.7.0-beta.1", "COSIGN_PEM=certificate.pem",
				"COSIGN_SIG=signature.sig", "INSTALL_DIR=release",
				"verified=true")
			out, runErr := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("action loop timed out: %v", ctx.Err())
			}
			output := string(out)
			if (runErr == nil) != tt.wantSuccess || strings.Contains(output, "ACTION_CONTINUED") != tt.wantSuccess {
				t.Fatalf("success = %v, want %v: %v\n%s", runErr == nil, tt.wantSuccess, runErr, output)
			}
			if got := strings.Count(output, "IDENTITY:"); got != tt.wantCalls {
				t.Fatalf("cosign calls = %d, want %d\n%s", got, tt.wantCalls, output)
			}
			owners := []string{"luckyPipewrench", "pipelab-org"}
			for _, owner := range owners[:tt.wantCalls] {
				want := "IDENTITY:https://github.com/" + owner + "/pipelock/.github/workflows/release.yaml@refs/tags/v3.7.0-beta.1\n"
				if !strings.Contains(output, want) {
					t.Fatalf("missing exact identity %q\n%s", want, output)
				}
			}
			if got := strings.Count(output, "ISSUER:https://token.actions.githubusercontent.com\n"); got != tt.wantCalls {
				t.Fatalf("issuer calls = %d, want %d\n%s", got, tt.wantCalls, output)
			}
		})
	}
}
