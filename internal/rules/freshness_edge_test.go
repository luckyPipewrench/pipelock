// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreshnessState_PrimaryOnlyBackfillFailuresFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{
			name: "secondary state parent is file",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, ".pipelock-state"), []byte("not a directory"), 0o600); err != nil {
					t.Fatalf("write secondary parent blocker: %v", err)
				}
			},
			want: "load freshness secondary state",
		},
		{
			name: "context path is directory",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.MkdirAll(freshnessContextPath(dir), 0o750); err != nil {
					t.Fatalf("mkdir context path blocker: %v", err)
				}
			},
			want: "backfill freshness context",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			state := &FreshnessState{HighestSeen: map[string]uint64{"community:test-bundle": 9}}
			if err := writeFreshnessStateFile(filepath.Join(dir, freshnessFilename), dir, state); err != nil {
				t.Fatalf("write primary freshness state: %v", err)
			}
			tc.setup(t, dir)

			_, err := LoadFreshnessState(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadFreshnessState error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFreshnessState_SecondaryOnlyContextBackfillFailureFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state := &FreshnessState{HighestSeen: map[string]uint64{"standard:pipelock-standard": 31}}
	if err := writeFreshnessStateFile(freshnessSecondaryPath(dir), dir, state); err != nil {
		t.Fatalf("write secondary freshness state: %v", err)
	}
	if err := os.Mkdir(freshnessContextPath(dir), 0o750); err != nil {
		t.Fatalf("mkdir context path blocker: %v", err)
	}

	_, err := LoadFreshnessState(dir)
	if err == nil || !strings.Contains(err.Error(), "backfill freshness context") {
		t.Fatalf("LoadFreshnessState error = %v, want context backfill failure", err)
	}
}

func TestFreshnessState_LengthMismatchBetweenCopiesFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := writeFreshnessStateFile(filepath.Join(dir, freshnessFilename), dir, &FreshnessState{
		HighestSeen: map[string]uint64{
			"community:test-bundle": 10,
			"standard:pipelock":     1,
		},
	}); err != nil {
		t.Fatalf("write primary freshness state: %v", err)
	}
	if err := writeFreshnessStateFile(freshnessSecondaryPath(dir), dir, &FreshnessState{
		HighestSeen: map[string]uint64{"community:test-bundle": 10},
	}); err != nil {
		t.Fatalf("write secondary freshness state: %v", err)
	}

	_, err := LoadFreshnessState(dir)
	if err == nil || !strings.Contains(err.Error(), "freshness state mismatch") {
		t.Fatalf("LoadFreshnessState length mismatch error = %v, want mismatch", err)
	}
}

func TestReadFreshnessStateFile_EmptyStateInitializesRollbackMap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, freshnessFilename)
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write empty freshness state: %v", err)
	}

	state, found, err := readFreshnessStateFile(path, dir, "freshness state")
	if err != nil {
		t.Fatalf("readFreshnessStateFile: %v", err)
	}
	if !found {
		t.Fatal("readFreshnessStateFile found=false, want true")
	}
	RecordVersion(state, TierCommunity, "test-bundle", 3)
	if got := state.HighestSeen["community:test-bundle"]; got != 3 {
		t.Fatalf("recorded rollback floor = %d, want 3", got)
	}
}

func TestWriteFreshnessContext_MkdirFailureFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".pipelock-state"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write context parent blocker: %v", err)
	}

	err := writeFreshnessContext(dir)
	if err == nil || !strings.Contains(err.Error(), "create freshness context dir") {
		t.Fatalf("writeFreshnessContext error = %v, want mkdir failure", err)
	}
}

func TestInstalledFreshnessContextPresent_FailClosedEdges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		want    bool
		wantErr string
	}{
		{
			name: "empty existing directory has no installed v2 context",
		},
		{
			name: "bundle directory without lock is ignored",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(dir, "no-lock"), 0o750); err != nil {
					t.Fatalf("mkdir no-lock bundle: %v", err)
				}
			},
		},
		{
			name: "lock without bundle fails closed",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				bundleDir := filepath.Join(dir, "missing-bundle")
				if err := os.Mkdir(bundleDir, 0o750); err != nil {
					t.Fatalf("mkdir bundle dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(bundleDir, lockFilename), []byte("unsigned: true\n"), 0o600); err != nil {
					t.Fatalf("write lock: %v", err)
				}
			},
			wantErr: "read bundle for freshness context",
		},
		{
			name: "malformed bundle fails closed",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				bundleDir := filepath.Join(dir, "bad-bundle")
				if err := os.Mkdir(bundleDir, 0o750); err != nil {
					t.Fatalf("mkdir bundle dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(bundleDir, lockFilename), []byte("unsigned: true\n"), 0o600); err != nil {
					t.Fatalf("write lock: %v", err)
				}
				if err := os.WriteFile(filepath.Join(bundleDir, bundleFilename), []byte("{{{{"), 0o600); err != nil {
					t.Fatalf("write malformed bundle: %v", err)
				}
			},
			wantErr: "parse bundle for freshness context",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			got, err := installedFreshnessContextPresent(dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("installedFreshnessContextPresent error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("installedFreshnessContextPresent: %v", err)
			}
			if got != tc.want {
				t.Fatalf("installedFreshnessContextPresent = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResetFreshnessStateFromInstalledBundles_SkipsDirsWithoutLocks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	validDir := filepath.Join(dir, "aaa-valid")
	if err := os.Mkdir(validDir, 0o750); err != nil {
		t.Fatalf("mkdir valid bundle dir: %v", err)
	}
	writeUnsignedBundle(t, validDir, testBundleV2("aaa-valid", TierCommunity, 44, []Rule{
		testDLPRule("dlp-valid", confidenceHigh, StatusStable),
	}))
	if err := os.Mkdir(filepath.Join(dir, "zzz-no-lock"), 0o750); err != nil {
		t.Fatalf("mkdir lockless bundle dir: %v", err)
	}

	if err := ResetFreshnessStateFromInstalledBundles(dir); err != nil {
		t.Fatalf("ResetFreshnessStateFromInstalledBundles: %v", err)
	}
	loaded, err := LoadFreshnessState(dir)
	if err != nil {
		t.Fatalf("LoadFreshnessState: %v", err)
	}
	if got := loaded.HighestSeen["community:aaa-valid"]; got != 44 {
		t.Fatalf("reset floor = %d, want 44", got)
	}
	if len(loaded.HighestSeen) != 1 {
		t.Fatalf("HighestSeen = %#v, want only valid bundle floor", loaded.HighestSeen)
	}
}

func TestResetFreshnessStateFromInstalledBundles_FailClosedEdges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		wantErr string
	}{
		{
			name: "lock without bundle",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				bundleDir := filepath.Join(dir, "zzz-missing-bundle")
				if err := os.Mkdir(bundleDir, 0o750); err != nil {
					t.Fatalf("mkdir bad bundle dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(bundleDir, lockFilename), []byte("unsigned: true\n"), 0o600); err != nil {
					t.Fatalf("write bad lock: %v", err)
				}
			},
			wantErr: "read bundle for freshness reset",
		},
		{
			name: "malformed bundle",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				bundleDir := filepath.Join(dir, "zzz-malformed-bundle")
				if err := os.Mkdir(bundleDir, 0o750); err != nil {
					t.Fatalf("mkdir bad bundle dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(bundleDir, lockFilename), []byte("unsigned: true\n"), 0o600); err != nil {
					t.Fatalf("write bad lock: %v", err)
				}
				if err := os.WriteFile(filepath.Join(bundleDir, bundleFilename), []byte("{{{{"), 0o600); err != nil {
					t.Fatalf("write malformed bundle: %v", err)
				}
			},
			wantErr: "parse bundle for freshness reset",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			validDir := filepath.Join(dir, "aaa-valid")
			if err := os.Mkdir(validDir, 0o750); err != nil {
				t.Fatalf("mkdir valid bundle dir: %v", err)
			}
			writeUnsignedBundle(t, validDir, testBundleV2("aaa-valid", TierCommunity, 7, []Rule{
				testDLPRule("dlp-valid", confidenceHigh, StatusStable),
			}))
			tc.setup(t, dir)

			err := ResetFreshnessStateFromInstalledBundles(dir)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ResetFreshnessStateFromInstalledBundles error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
