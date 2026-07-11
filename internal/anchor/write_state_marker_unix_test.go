// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package anchor

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWriteStateMarkerRejectsTempFileWriteFailure(t *testing.T) {
	if raceEnabled {
		t.Skip("RLIMIT_FSIZE is process-wide and can interfere with the race test harness")
	}
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	restoreLimit := func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
	}
	t.Cleanup(func() {
		restoreLimit()
		signal.Reset(syscall.SIGXFSZ)
	})
	limited := old
	limited.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatalf("Setrlimit: %v", err)
	}

	dir := t.TempDir()
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	})
	restoreLimit()
	if err == nil || !strings.Contains(err.Error(), "write anchor-state temp file") {
		t.Fatalf("WriteStateMarker err = %v, want temp write failure", err)
	}
	matches, globErr := filepath.Glob(filepath.Join(dir, "anchor-state.d", ".anchor-state-*.tmp"))
	if globErr != nil {
		t.Fatalf("Glob temp markers: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary marker files remained after write failure: %v", matches)
	}
}

func TestWriteStateMarkerRejectsUnwritableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatalf("Chmod unwritable dir: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(dir, 0o700)
	})
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "create anchor-state directory") {
		t.Fatalf("WriteStateMarker err = %v, want create directory failure", err)
	}
}

func TestWriteStateMarkerRejectsSymlinkRoot(t *testing.T) {
	outside := t.TempDir()
	root := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(outside, root); err != nil {
		t.Fatalf("Symlink root: %v", err)
	}
	err := WriteStateMarker(root, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "create anchor-state directory") {
		t.Fatalf("WriteStateMarker err = %v, want symlink root refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "anchor-state.d")); !os.IsNotExist(statErr) {
		t.Fatalf("symlink target anchor-state.d stat err = %v, want not exist", statErr)
	}
}

func TestWriteStateMarkerRejectsFileAtIndexDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.d"), []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile index blocker: %v", err)
	}
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "not a regular directory") {
		t.Fatalf("WriteStateMarker err = %v, want index directory refusal", err)
	}
}

func TestWriteStateMarkerRejectsUnreadableIndexDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	dir := t.TempDir()
	indexDir := filepath.Join(dir, "anchor-state.d")
	if err := os.Mkdir(indexDir, 0o750); err != nil {
		t.Fatalf("Mkdir index: %v", err)
	}
	if err := os.Chmod(indexDir, 0); err != nil {
		t.Fatalf("Chmod index: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(indexDir, 0o750)
	})
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "inspect anchor-state directory") {
		t.Fatalf("WriteStateMarker err = %v, want unreadable index refusal", err)
	}
}

func TestWriteStateMarkerFileRejectsMissingIdentity(t *testing.T) {
	err := writeStateMarkerFile(t.TempDir(), StateMarker{
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}, []byte("{}\n"))
	if err == nil || !strings.Contains(err.Error(), "session_id is empty") {
		t.Fatalf("writeStateMarkerFile err = %v, want identity failure", err)
	}
}

func TestWriteFileUnderDirRejectsInvalidAndBlockedPaths(t *testing.T) {
	root := t.TempDir()
	rootFD, err := openAnchorDir(root)
	if err != nil {
		t.Fatalf("openAnchorDir: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(rootFD) })

	for _, rel := range []string{"", ".", filepath.Join("..", "bundle.json")} {
		t.Run(rel, func(t *testing.T) {
			if err := writeFileUnderDir(rootFD, rel, []byte("bundle")); err == nil {
				t.Fatalf("writeFileUnderDir(%q) err = nil, want rejection", rel)
			}
		})
	}

	if err := os.WriteFile(filepath.Join(root, "blocked"), []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	if err := writeFileUnderDir(rootFD, filepath.Join("blocked", "bundle.json"), []byte("bundle")); err == nil || !strings.Contains(err.Error(), "open anchor bundle directory") {
		t.Fatalf("writeFileUnderDir blocked parent err = %v, want open directory failure", err)
	}
}

func TestWriteFileUnderDirRejectsUnwritableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o500); err != nil { // #nosec G302 -- test needs searchable but unwritable directory permissions.
		t.Fatalf("Chmod root: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(root, 0o700)
	})
	rootFD, err := openAnchorDir(root)
	if err != nil {
		t.Fatalf("openAnchorDir: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(rootFD) })
	if err := writeFileUnderDir(rootFD, filepath.Join("nested", "bundle.json"), []byte("bundle")); err == nil || !strings.Contains(err.Error(), "create anchor bundle directory") {
		t.Fatalf("writeFileUnderDir unwritable root err = %v, want mkdir failure", err)
	}
}
