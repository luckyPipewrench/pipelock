// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMonotonicStateSurfaceRegistry(t *testing.T) {
	root := repoRoot(t)
	surfaces := []struct {
		name       string
		source     string
		testSource string
		mustHave   []string
	}{
		{
			name:       "license CRL high-water",
			source:     "internal/license/crl_highwater.go",
			testSource: "internal/license/crl_deletable_both_poc_test.go",
			mustHave: []string{
				"crlHighWaterContextPath",
				"high-water missing while CRL context is present",
				"ResetCRLHighWater",
				"delete-both CRL high-water replay succeeded",
			},
		},
		{
			name:       "rules freshness",
			source:     "internal/rules/freshness.go",
			testSource: "internal/rules/freshness_test.go",
			mustHave: []string{
				"installedFreshnessContextPresent",
				"freshness state missing while freshness context is present",
				"ResetFreshnessStateFromInstalledBundles",
				"DeleteAllWithInstalledV2ContextFailsClosed",
			},
		},
		{
			name:       "conductor remote kill replay",
			source:     "enterprise/conductor/emergency/remote_kill.go",
			testSource: "enterprise/conductor/emergency/remote_kill_test.go",
			mustHave: []string{
				"remoteKillReplayContextPresent",
				"replay state missing while follower context is present",
				"ResetRemoteKillReplayState",
				"RejectsReplayAfterPrimaryAndSecondaryDeletion",
			},
		},
		{
			name:       "conductor enrollment marker",
			source:     "internal/cli/runtime/conductor_enrollment.go",
			testSource: "internal/cli/runtime/conductor_enrollment_test.go",
			mustHave: []string{
				"parse conductor enrollment marker",
				"marker.OrgID == cfg.OrgID",
				"CorruptMarkerConsumedTokenCanRecoverWithNewToken",
			},
		},
	}

	for _, surface := range surfaces {
		t.Run(surface.name, func(t *testing.T) {
			source := readRepoFile(t, root, surface.source) + "\n" + readRepoFile(t, root, surface.testSource)
			for _, needle := range surface.mustHave {
				if !strings.Contains(source, needle) {
					t.Fatalf("%s missing monotonic-state registry proof %q", surface.name, needle)
				}
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readRepoFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- test reads repository files by fixed relative path
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}
