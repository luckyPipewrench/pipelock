//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWriteFileUnderDirSyncFailures(t *testing.T) {
	t.Run("file_sync_failure_does_not_publish_bundle", func(t *testing.T) {
		dir := t.TempDir()
		rootFD, err := openAnchorDir(dir)
		if err != nil {
			t.Fatalf("openAnchorDir: %v", err)
		}
		defer func() { _ = unix.Close(rootFD) }()

		syncErr := errors.New("injected file sync failure")
		err = writeFileUnderDirWithSync(rootFD, "bundle.json", []byte("bundle"), func(*os.File) error {
			return syncErr
		}, unix.Fsync)
		if !errors.Is(err, syncErr) || !strings.Contains(err.Error(), "sync anchor bundle") {
			t.Fatalf("writeFileUnderDirWithSync file sync error = %v, want wrapped file sync failure", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "bundle.json")); !os.IsNotExist(statErr) {
			t.Fatalf("published bundle stat err = %v, want not exist", statErr)
		}
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatalf("read receipt directory: %v", readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("entries after sync failure = %v, want none", entries)
		}
	})

	t.Run("directory_sync_failure_is_reported_after_file_sync", func(t *testing.T) {
		dir := t.TempDir()
		rootFD, err := openAnchorDir(dir)
		if err != nil {
			t.Fatalf("openAnchorDir: %v", err)
		}
		defer func() { _ = unix.Close(rootFD) }()

		dirSyncErr := errors.New("injected directory sync failure")
		fileSynced := false
		err = writeFileUnderDirWithSync(rootFD, "bundle.json", []byte("bundle"), func(file *os.File) error {
			fileSynced = true
			return file.Sync()
		}, func(int) error {
			publishedFD, openErr := unix.Openat(rootFD, "bundle.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if openErr != nil {
				t.Fatalf("open published bundle during directory sync: %v", openErr)
			}
			publishedFile := os.NewFile(uintptr(publishedFD), "bundle.json")
			got, readErr := io.ReadAll(publishedFile)
			_ = publishedFile.Close()
			if readErr != nil {
				t.Fatalf("read published bundle during directory sync: %v", readErr)
			}
			if string(got) != "bundle" {
				t.Fatalf("published bundle during directory sync = %q, want bundle", got)
			}
			return dirSyncErr
		})
		if !fileSynced {
			t.Fatal("file sync was not called before directory sync")
		}
		if !errors.Is(err, dirSyncErr) || !strings.Contains(err.Error(), "sync anchor bundle directory") {
			t.Fatalf("writeFileUnderDirWithSync directory sync error = %v, want wrapped directory sync failure", err)
		}
	})

	t.Run("nested_write_syncs_leaf_then_each_parent", func(t *testing.T) {
		dir := t.TempDir()
		rootFD, err := openAnchorDir(dir)
		if err != nil {
			t.Fatalf("openAnchorDir: %v", err)
		}
		defer func() { _ = unix.Close(rootFD) }()

		var synced []string
		err = writeFileUnderDirWithSync(rootFD, filepath.Join("one", "two", "bundle.json"), []byte("bundle"), func(file *os.File) error {
			return file.Sync()
		}, func(fd int) error {
			dupFD, dupErr := unix.Dup(fd)
			if dupErr != nil {
				return dupErr
			}
			dupFile := os.NewFile(uintptr(dupFD), "anchor-sync-test")
			info, statErr := dupFile.Stat()
			_ = dupFile.Close()
			if statErr != nil {
				return statErr
			}
			for name, path := range map[string]string{
				"two":              filepath.Join(dir, "one", "two"),
				"one":              filepath.Join(dir, "one"),
				filepath.Base(dir): dir,
			} {
				pathInfo, pathErr := os.Stat(path)
				if pathErr != nil {
					return pathErr
				}
				if os.SameFile(info, pathInfo) {
					synced = append(synced, name)
					break
				}
			}
			return unix.Fsync(fd)
		})
		if err != nil {
			t.Fatalf("writeFileUnderDirWithSync: %v", err)
		}
		if want := []string{"two", "one", filepath.Base(dir)}; !slices.Equal(synced, want) {
			t.Fatalf("directory sync order = %v, want %v", synced, want)
		}
	})

	t.Run("nested_sync_failure_still_attempts_each_parent", func(t *testing.T) {
		dir := t.TempDir()
		rootFD, err := openAnchorDir(dir)
		if err != nil {
			t.Fatalf("openAnchorDir: %v", err)
		}
		defer func() { _ = unix.Close(rootFD) }()

		leafSyncErr := errors.New("injected leaf directory sync failure")
		syncCalls := 0
		err = writeFileUnderDirWithSync(rootFD, filepath.Join("one", "two", "bundle.json"), []byte("bundle"), func(file *os.File) error {
			return file.Sync()
		}, func(fd int) error {
			syncCalls++
			if syncCalls == 1 {
				return leafSyncErr
			}
			return unix.Fsync(fd)
		})
		if !errors.Is(err, leafSyncErr) {
			t.Fatalf("writeFileUnderDirWithSync error = %v, want leaf directory sync failure", err)
		}
		if syncCalls != 3 {
			t.Fatalf("directory sync calls after leaf failure = %d, want 3", syncCalls)
		}
	})

	t.Run("first_directory_sync_error_wins", func(t *testing.T) {
		dir := t.TempDir()
		rootFD, err := openAnchorDir(dir)
		if err != nil {
			t.Fatalf("openAnchorDir: %v", err)
		}
		defer func() { _ = unix.Close(rootFD) }()

		leafSyncErr := errors.New("injected leaf directory sync failure")
		parentSyncErr := errors.New("injected parent directory sync failure")
		syncCalls := 0
		err = writeFileUnderDirWithSync(rootFD, filepath.Join("one", "two", "bundle.json"), []byte("bundle"), func(file *os.File) error {
			return file.Sync()
		}, func(fd int) error {
			syncCalls++
			switch syncCalls {
			case 1:
				return leafSyncErr
			case 2:
				return parentSyncErr
			default:
				return unix.Fsync(fd)
			}
		})
		if !errors.Is(err, leafSyncErr) {
			t.Fatalf("writeFileUnderDirWithSync error = %v, want leaf directory sync failure", err)
		}
		if errors.Is(err, parentSyncErr) {
			t.Fatalf("writeFileUnderDirWithSync error = %v, want first sync error only", err)
		}
		if syncCalls != 3 {
			t.Fatalf("directory sync calls = %d, want 3", syncCalls)
		}
	})
}

func TestWriteStateMarkerFileSyncsReceiptRoot(t *testing.T) {
	dir := t.TempDir()
	marker := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Unix(1, 0).UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}
	data, err := json.Marshal(marker)
	if err != nil {
		t.Fatalf("marshal marker: %v", err)
	}

	rootSyncErr := errors.New("injected receipt root sync failure")
	rootSyncCalled := false
	err = writeStateMarkerFileWithSync(dir, marker, append(data, '\n'), func(rootFD int) error {
		rootSyncCalled = true
		var stat unix.Stat_t
		if statErr := unix.Fstatat(rootFD, stateMarkerIndexDir, &stat, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
			t.Fatalf("inspect marker index during root sync: %v", statErr)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			t.Fatalf("marker index mode during root sync = %#o, want directory", stat.Mode)
		}
		return rootSyncErr
	})
	if !rootSyncCalled {
		t.Fatal("receipt root sync was not called")
	}
	if !errors.Is(err, rootSyncErr) || !strings.Contains(err.Error(), "sync anchor-state parent directory") {
		t.Fatalf("writeStateMarkerFileWithSync error = %v, want wrapped receipt root sync failure", err)
	}
	path, pathErr := StateMarkerPath(dir, marker)
	if pathErr != nil {
		t.Fatalf("StateMarkerPath: %v", pathErr)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("published marker after root sync failure: %v", statErr)
	}

	t.Run("write_error_wins_over_root_sync_error", func(t *testing.T) {
		failureDir := t.TempDir()
		if writeErr := writeStateMarkerFileWithSync(failureDir, marker, append(data, '\n'), unix.Fsync); writeErr != nil {
			t.Fatalf("write initial marker: %v", writeErr)
		}

		rootSyncErr := errors.New("injected receipt root sync failure")
		rootSyncCalled := false
		err := writeStateMarkerFileWithSync(failureDir, marker, append(data, '\n'), func(int) error {
			rootSyncCalled = true
			return rootSyncErr
		})
		if !rootSyncCalled {
			t.Fatal("receipt root sync was not called after write failure")
		}
		if !errors.Is(err, errStateMarkerExists) {
			t.Fatalf("writeStateMarkerFileWithSync error = %v, want existing marker error", err)
		}
		if errors.Is(err, rootSyncErr) {
			t.Fatalf("writeStateMarkerFileWithSync error = %v, must not include root sync error", err)
		}
	})
}
