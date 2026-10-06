// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreflightStateMarker_DamagedAndLegacyState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		setup   func(*testing.T, string)
		wantErr string
	}{
		{"symlink index", func(t *testing.T, dir string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, stateMarkerIndexDir)); err != nil {
				t.Fatal(err)
			}
		}, "regular directory"},
		{"bundle without marker after interrupted anchor", func(t *testing.T, dir string) {
			if err := WriteBundle(filepath.Join(dir, "bundle.json"), NewBundle(preflightCheckpoint("proxy", 4, "a"), Proof{Backend: LocalBackend})); err != nil {
				t.Fatal(err)
			}
		}, ""},
		{"corrupt legacy without index", func(t *testing.T, dir string) {
			writePreflightFile(t, filepath.Join(dir, legacyStateMarker), []byte("broken"))
		}, "legacy"},
		{"legacy duplicate without index", func(t *testing.T, dir string) {
			data, err := json.Marshal(preflightMarker("proxy", 4, "a"))
			if err != nil {
				t.Fatal(err)
			}
			writePreflightFile(t, filepath.Join(dir, legacyStateMarker), data)
		}, "already anchored"},
		{"symlink latest with index", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, stateMarkerIndexDir), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("missing", filepath.Join(dir, legacyStateMarker)); err != nil {
				t.Fatal(err)
			}
		}, "regular file"},
		{"directory latest with index", func(t *testing.T, dir string) {
			for _, name := range []string{stateMarkerIndexDir, legacyStateMarker} {
				if err := os.Mkdir(filepath.Join(dir, name), 0o750); err != nil {
					t.Fatal(err)
				}
			}
		}, "regular file"},
		{"corrupt regular latest with index is recoverable", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, stateMarkerIndexDir), 0o750); err != nil {
				t.Fatal(err)
			}
			writePreflightFile(t, filepath.Join(dir, legacyStateMarker), []byte("broken"))
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tc.setup(t, dir)
			err := PreflightStateMarker(dir, preflightCheckpoint("proxy", 4, "a"))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("preflight = %v, want %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			marker := preflightMarker("proxy", 4, "a")
			marker.LogIndex = 10
			writeErr := WriteStateMarker(dir, marker)
			if (err != nil) != (writeErr != nil) {
				t.Fatalf("preflight = %v, write = %v", err, writeErr)
			}
		})
	}
}

func writePreflightFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIsStateMarkerIndexPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		want bool
	}{
		{stateMarkerIndexDir, true},
		{stateMarkerIndexDir + "/bundle.json", true},
		{stateMarkerIndexDir + "/nested/bundle.json", true},
		{"./" + stateMarkerIndexDir + "/bundle.json", true},
		{"bundles/bundle.json", false},
		{stateMarkerIndexDir + "-backup/bundle.json", false},
		{"nested/" + stateMarkerIndexDir + "/bundle.json", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			if got := IsStateMarkerIndexPath(tc.path); got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}
