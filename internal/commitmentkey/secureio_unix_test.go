// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package commitmentkey

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSecurePathsRejectUnsafeOrSymlinkedParents(t *testing.T) {
	t.Run("unsafe_parent_blocks_initialize", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "unsafe")
		if err := os.Mkdir(parent, 0o750); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := unix.Chmod(parent, 0o770); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = unix.Chmod(parent, 0o750) })
		path := filepath.Join(parent, "keyring.json")
		if _, err := Initialize(path, time.Now()); !errors.Is(err, ErrUnsafePermission) {
			t.Fatalf("Initialize error = %v, want ErrUnsafePermission", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused initialize created target: %v", err)
		}
	})

	t.Run("symlink_parent_blocks_initialize", func(t *testing.T) {
		dir := t.TempDir()
		realParent := filepath.Join(dir, "real")
		if err := os.Mkdir(realParent, 0o750); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		linkParent := filepath.Join(dir, "linked")
		if err := os.Symlink(realParent, linkParent); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		path := filepath.Join(linkParent, "keyring.json")
		if _, err := Initialize(path, time.Now()); !errors.Is(err, ErrSymlink) {
			t.Fatalf("Initialize error = %v, want ErrSymlink", err)
		}
		if _, err := os.Lstat(filepath.Join(realParent, "keyring.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused initialize wrote through parent symlink: %v", err)
		}
	})
}

func TestSecureParentRulesCoverBackupRestoreAndLock(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	if _, err := Initialize(keyringPath, time.Now()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	unsafeParent := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafeParent, 0o750); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := unix.Chmod(unsafeParent, 0o770); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = unix.Chmod(unsafeParent, 0o750) })

	t.Run("backup_destination", func(t *testing.T) {
		destination := filepath.Join(unsafeParent, "backup.json")
		if _, err := Backup(keyringPath, destination); !errors.Is(err, ErrUnsafePermission) {
			t.Fatalf("Backup error = %v, want ErrUnsafePermission", err)
		}
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused backup created destination: %v", err)
		}
	})

	backupPath := filepath.Join(dir, "backup.json")
	if _, err := Backup(keyringPath, backupPath); err != nil {
		t.Fatalf("Backup fixture: %v", err)
	}
	t.Run("restore_destination", func(t *testing.T) {
		destination := filepath.Join(unsafeParent, "restore.json")
		if _, err := Restore(backupPath, destination); !errors.Is(err, ErrUnsafePermission) {
			t.Fatalf("Restore error = %v, want ErrUnsafePermission", err)
		}
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused restore created destination: %v", err)
		}
	})

	t.Run("lock_parent", func(t *testing.T) {
		if err := withLifecycleLock(filepath.Join(unsafeParent, "keyring.json"), func() error {
			t.Fatal("callback ran below unsafe parent")
			return nil
		}); !errors.Is(err, ErrUnsafePermission) {
			t.Fatalf("withLifecycleLock error = %v, want ErrUnsafePermission", err)
		}
	})
}

func TestSecureLockRejectsUnsafeOpenedFile(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	lockPath := keyringPath + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := unix.Chmod(lockPath, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	called := false
	err := withLifecycleLock(keyringPath, func() error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrUnsafePermission) {
		t.Fatalf("withLifecycleLock error = %v, want ErrUnsafePermission", err)
	}
	if called {
		t.Fatal("callback ran with unsafe opened lock file")
	}
}

func TestReadPrivateViewRequiresSecureOpenedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "view.txt")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got, err := ReadPrivateView(path); err != nil || string(got) != "private" {
		t.Fatalf("ReadPrivateView = %q, %v", got, err)
	}
	if err := unix.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := ReadPrivateView(path); !errors.Is(err, ErrUnsafePermission) {
		t.Fatalf("ReadPrivateView mode 0644 error = %v, want ErrUnsafePermission", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restore mode: %v", err)
	}
	link := filepath.Join(dir, "view-link.txt")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := ReadPrivateView(link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("ReadPrivateView symlink error = %v, want ErrSymlink", err)
	}
}

func TestReadPrivateViewUnreadableFileFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-000 files")
	}
	path := filepath.Join(t.TempDir(), "unreadable-view.txt")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := ReadPrivateView(path); !errors.Is(err, ErrUnsafePermission) || !strings.Contains(err.Error(), "cannot open") {
		t.Fatalf("ReadPrivateView unreadable error = %v, want fail-closed open refusal", err)
	}
}

func TestReadPrivateViewRejectsOpenedFileOwnedByAnotherUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is the expected owner for root-run commands")
	}
	if _, err := ReadPrivateView("/etc/passwd"); !errors.Is(err, ErrUnsafePermission) || !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ReadPrivateView foreign owner error = %v, want owner refusal", err)
	}
}

func TestLoadRejectsNonRegularOpenedObjectBeforeReading(t *testing.T) {
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "fixture.json")
	if _, err := Initialize(fixturePath, time.Now()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	fixture, err := os.ReadFile(filepath.Clean(fixturePath))
	if err != nil {
		t.Fatalf("ReadFile fixture: %v", err)
	}
	fifoPath := filepath.Join(dir, "keyring.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	writerDone := make(chan error, 1)
	go func() {
		f, openErr := os.OpenFile(filepath.Clean(fifoPath), os.O_WRONLY, 0)
		if openErr != nil {
			writerDone <- openErr
			return
		}
		_, writeErr := f.Write(fixture)
		closeErr := f.Close()
		if writeErr != nil {
			writerDone <- writeErr
			return
		}
		writerDone <- closeErr
	}()
	if _, err := Load(fifoPath); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("Load FIFO error = %v, want ErrInvalidKeyring", err)
	}
	if err := <-writerDone; err != nil && !errors.Is(err, unix.EPIPE) {
		t.Fatalf("FIFO writer: %v", err)
	}
}

func TestSecureIOReachableErrorPaths(t *testing.T) {
	t.Run("unsafe parent writes", func(t *testing.T) {
		unsafeParent := filepath.Join(t.TempDir(), "unsafe")
		if err := os.Mkdir(unsafeParent, 0o750); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := unix.Chmod(unsafeParent, 0o770); err != nil {
			t.Fatalf("Chmod unsafe: %v", err)
		}
		if err := writeSecureNew(filepath.Join(unsafeParent, "new.json"), []byte("x")); !errors.Is(err, ErrUnsafePermission) {
			t.Fatalf("writeSecureNew unsafe parent = %v", err)
		}
		if err := writeSecureReplace(filepath.Join(unsafeParent, "replace.json"), []byte("x")); !errors.Is(err, ErrUnsafePermission) {
			t.Fatalf("writeSecureReplace unsafe parent = %v", err)
		}
		if err := unix.Chmod(unsafeParent, 0o750); err != nil {
			t.Fatalf("restore parent mode: %v", err)
		}
		if err := writeSecureReplace(filepath.Join(unsafeParent, "missing.json"), []byte("x")); err == nil {
			t.Fatal("writeSecureReplace created missing target")
		}
	})

	t.Run("invalid write descriptors", func(t *testing.T) {
		dir := t.TempDir()
		fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
		if err != nil {
			t.Fatalf("Open directory: %v", err)
		}
		defer func() { _ = unix.Close(fd) }()
		if err := writeSecureAt(fd, "missing/child.json", []byte("x"), false); err == nil {
			t.Fatal("writeSecureAt with invalid destination succeeded")
		}
		if err := writeSecureAt(-1, "child.json", []byte("x"), false); err == nil {
			t.Fatal("writeSecureAt with invalid parent descriptor succeeded")
		}
		if _, _, err := createSecureTemp(-1); err == nil {
			t.Fatal("createSecureTemp with invalid descriptor succeeded")
		}
		if err := chmodSecure(-1, "test file"); err == nil {
			t.Fatal("chmodSecure accepted invalid descriptor")
		}
	})

	t.Run("write and sync failures", func(t *testing.T) {
		closed, err := os.CreateTemp(t.TempDir(), "closed-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		if err := closed.Close(); err != nil {
			t.Fatalf("Close temp: %v", err)
		}
		if err := writeAndSync(closed, []byte("x")); err == nil {
			t.Fatal("writeAndSync accepted closed file")
		}
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe: %v", err)
		}
		defer func() { _ = reader.Close() }()
		defer func() { _ = writer.Close() }()
		if err := writeAndSync(writer, []byte("x")); err == nil || !strings.Contains(err.Error(), "sync") {
			t.Fatalf("writeAndSync pipe error = %v, want sync refusal", err)
		}
		if err := syncDescriptor(-1, "invalid descriptor"); err == nil {
			t.Fatal("syncDescriptor accepted invalid descriptor")
		}
	})

	t.Run("invalid paths and opened descriptors", func(t *testing.T) {
		if _, _, err := openSecureParent(string(filepath.Separator), false); err == nil {
			t.Fatal("openSecureParent accepted a path without a file component")
		}
		if err := validateOpenedDirectory(-1, "invalid"); err == nil {
			t.Fatal("validateOpenedDirectory accepted invalid descriptor")
		}
		filePath := filepath.Join(t.TempDir(), "regular")
		if err := os.WriteFile(filePath, nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		fileFD, err := unix.Open(filePath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("Open file: %v", err)
		}
		defer func() { _ = unix.Close(fileFD) }()
		if err := validateOpenedDirectory(fileFD, filePath); err == nil {
			t.Fatal("validateOpenedDirectory accepted regular file")
		}
		if _, err := validateOpenedFile(-1, "commitment keyring", ErrInvalidKeyring); err == nil {
			t.Fatal("validateOpenedFile accepted invalid descriptor")
		}
	})

	t.Run("oversized private view", func(t *testing.T) {
		oversizedView := filepath.Join(t.TempDir(), "oversized-view")
		view, err := os.OpenFile(filepath.Clean(oversizedView), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("OpenFile oversized view: %v", err)
		}
		if err := view.Truncate(maxPrivateViewBytes + 1); err != nil {
			_ = view.Close()
			t.Fatalf("Truncate: %v", err)
		}
		if err := view.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := ReadPrivateView(oversizedView); err == nil {
			t.Fatal("ReadPrivateView accepted oversized file")
		}
	})

	t.Run("read-only parent", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can create below mode-0500 directories")
		}
		readOnlyParent := filepath.Join(t.TempDir(), "read-only")
		if err := os.Mkdir(readOnlyParent, 0o750); err != nil {
			t.Fatalf("Mkdir read-only: %v", err)
		}
		if err := unix.Chmod(readOnlyParent, 0o500); err != nil {
			t.Fatalf("Chmod read-only: %v", err)
		}
		t.Cleanup(func() { _ = unix.Chmod(readOnlyParent, 0o750) })
		if _, _, err := openSecureParent(filepath.Join(readOnlyParent, "missing", "keyring.json"), true); err == nil {
			t.Fatal("openSecureParent created below read-only parent")
		}
	})
}

func TestMapOpenError(t *testing.T) {
	path := filepath.Join("tmp", "keyring.json")
	if err := mapOpenError("commitment keyring", path, unix.ELOOP); !errors.Is(err, ErrSymlink) || !strings.Contains(err.Error(), filepath.Clean(path)) {
		t.Fatalf("ELOOP error = %v, want cleaned ErrSymlink", err)
	}
	if err := mapOpenError("commitment keyring", path, unix.EACCES); !errors.Is(err, ErrUnsafePermission) || !errors.Is(err, unix.EACCES) {
		t.Fatalf("EACCES error = %v, want ErrUnsafePermission wrapping EACCES", err)
	}
	if err := mapOpenError("commitment keyring", path, unix.ENOENT); errors.Is(err, ErrSymlink) || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("ENOENT error = %v, want ordinary wrapped error", err)
	}
}

func TestNoFollowSymlinkErrnoSelection(t *testing.T) {
	loop := errors.New("synthetic ELOOP")
	link := errors.New("synthetic EMLINK")
	fileType := errors.New("synthetic EFTYPE")

	// Each case is a platform's DECLARED errno set, mirroring what the
	// nofollow_errno_*.go files construct. The selector must surface every
	// errno the set declares and nothing else. Asserting on the declared set
	// rather than on a platform NAME is what keeps this test from going
	// vacuous: a previous version switched on a label string, so renaming that
	// label silently dropped EMLINK from the selection while this test kept
	// passing against its own hardcoded label.
	for _, test := range []struct {
		name   string
		errnos noFollowErrnos
		want   []error
		absent []error
	}{
		{
			name:   "loop_only",
			errnos: noFollowErrnos{loop: loop},
			want:   []error{loop},
			absent: []error{link, fileType},
		},
		{
			name:   "loop_and_link",
			errnos: noFollowErrnos{loop: loop, link: link},
			want:   []error{loop, link},
			absent: []error{fileType},
		},
		{
			name:   "loop_and_file_type",
			errnos: noFollowErrnos{loop: loop, fileType: fileType},
			want:   []error{loop, fileType},
			absent: []error{link},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := noFollowSymlinkErrorsFor(test.errnos)
			for _, err := range test.want {
				if !isNoFollowSymlinkError(err, selected) {
					t.Fatalf("declared errno %v was not selected", err)
				}
			}
			for _, err := range test.absent {
				if isNoFollowSymlinkError(err, selected) {
					t.Fatalf("undeclared errno %v was selected", err)
				}
			}
			if isNoFollowSymlinkError(unix.ENOENT, selected) {
				t.Fatal("selected ordinary ENOENT as a symlink refusal")
			}
		})
	}
}

// TestPlatformDeclaresItsSymlinkErrnos pins that the platform file compiled into
// THIS build actually declares a usable errno set, so a platform file that
// forgets or mis-declares its errnos cannot ship a guard that recognizes
// nothing. The selector test above uses synthetic errnos and therefore cannot
// see a real platform file going empty.
func TestPlatformDeclaresItsSymlinkErrnos(t *testing.T) {
	if len(noFollowSymlinkErrors) == 0 {
		t.Fatal("platform declared no O_NOFOLLOW symlink errnos")
	}
	if !isNoFollowSymlinkError(unix.ELOOP, noFollowSymlinkErrors) {
		t.Fatal("platform does not recognize ELOOP as a symlink refusal")
	}
}

func TestReadPrivateViewRejectsFIFOWithoutConsumingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "view.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	writerDone := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY, 0)
		if err != nil {
			writerDone <- err
			return
		}
		_, err = f.Write([]byte("private"))
		closeErr := f.Close()
		if err != nil {
			writerDone <- err
			return
		}
		writerDone <- closeErr
	}()
	if _, err := ReadPrivateView(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("ReadPrivateView FIFO error = %v", err)
	}
	if err := <-writerDone; err != nil && !errors.Is(err, unix.EPIPE) {
		t.Fatalf("FIFO writer: %v", err)
	}
}

// TestParentStickyBitDistinguishesSharedFromUnsafe pins the exact semantics of
// the writable-parent check. A group- or world-writable parent lets another
// user rename or replace the keyring between validation and use, which is the
// substitution attack the check exists to stop. The sticky bit removes that
// ability, so a shared temporary directory such as /tmp mode 1777 is safe while
// the same mode without the sticky bit is not. Without this test the
// distinction is only implicitly covered, and dropping either half would go
// unnoticed until CI fails everywhere or the check silently stops protecting.
func TestParentStickyBitDistinguishesSharedFromUnsafe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    uint32
		wantErr bool
	}{
		{"world_writable_with_sticky_is_allowed", 0o1777, false},
		{"world_writable_without_sticky_is_refused", 0o0777, true},
		{"group_writable_without_sticky_is_refused", 0o0770, true},
		{"owner_only_is_allowed", 0o0700, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "parent")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			if err := unix.Chmod(parent, tc.mode); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			t.Cleanup(func() { _ = unix.Chmod(parent, 0o700) })

			_, err := Initialize(filepath.Join(parent, "keyring.json"), time.Now())
			if tc.wantErr {
				if !errors.Is(err, ErrUnsafePermission) {
					t.Fatalf("mode %04o: error = %v, want ErrUnsafePermission", tc.mode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("mode %04o: Initialize returned %v, want success", tc.mode, err)
			}
		})
	}
}
