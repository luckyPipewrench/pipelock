// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMappedFilePathWhitespace(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ordinary.bin", "two  spaces.bin", "tab\tname.bin", "trailing.bin "} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(pinnedContent), 0o600); err != nil {
				t.Fatal(err)
			}
			h := startServer(t, modeServe, loopbackAny, envHold+"="+path, envHoldMmap+"=1")
			conn := dialAccepted(t, h, "")
			pin := basePin(t)
			pin.MappedFiles = []FilePin{{Path: path, SHA256: sha256Hex([]byte(pinnedContent))}}
			if _, err := NewVerifier().VerifyConn(conn, pin); err != nil {
				t.Fatalf("VerifyConn refused a held mapping: %v", err)
			}
			obs, err := NewVerifier().Observe(context.Background(), conn)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range obs.Files {
				if file.Path == path && file.SHA256 == pin.MappedFiles[0].SHA256 {
					return
				}
			}
			t.Fatalf("Observe did not report the exact held file %q with its digest: %+v", path, obs.Files)
		})
	}
}

func TestMapsIdentityOfRealFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "module.bin")
	if err := os.WriteFile(path, []byte("module contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	_, ino, _, _ := fileIdentity(fi)
	link, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(int(f.Fd()))))
	if err != nil {
		t.Fatal(err)
	}

	got, ok := mapsIdentityOf(f, fi.Size())
	if !ok {
		t.Fatal("mapsIdentityOf found no mapping of an open regular file")
	}
	if got.ino != ino || got.path != link || !got.mapped {
		t.Fatalf("mapsIdentityOf = %+v, want ino %d path %q mapped", got, ino, link)
	}

	empty := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := os.Open(filepath.Clean(empty))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Close() }()
	if _, ok := mapsIdentityOf(e, 0); ok {
		t.Fatal("an empty file must have no maps identity")
	}
}

func TestHeldMatches(t *testing.T) {
	t.Parallel()
	const statDev, superDev, ino = uint64(0x39), uint64(0x1d), uint64(69624981)
	const path = "/opt/vendor/app/native.node"
	mapsID := heldFile{dev: superDev, ino: ino, path: path, mapped: true}
	tests := []struct {
		name   string
		held   heldFile
		mapsOK bool
		want   bool
	}{
		{name: "descriptor by stat identity", held: heldFile{dev: statDev, ino: ino, path: path}, mapsOK: true, want: true},
		{name: "descriptor with another inode", held: heldFile{dev: statDev, ino: ino + 1, path: path}, mapsOK: true},
		{name: "mapping by maps identity", held: heldFile{dev: superDev, ino: ino, path: path, mapped: true}, mapsOK: true, want: true},
		{name: "mapping compared by stat device is not a match", held: heldFile{dev: statDev, ino: ino, path: path, mapped: true}, mapsOK: true},
		{name: "same device and inode in another subvolume", held: heldFile{dev: superDev, ino: ino, path: "/var/tmp/other.node", mapped: true}, mapsOK: true},
		{name: "mapping without a maps identity", held: heldFile{dev: superDev, ino: ino, path: path, mapped: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := heldMatches(tt.held, statDev, ino, mapsID, tt.mapsOK); got != tt.want {
				t.Fatalf("heldMatches = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestVerifyConnMappedFileWhenMapsDeviceDiffers models btrfs and overlayfs,
// where the device in a maps line is not the device stat reports for the same
// file. It replaces the package maps-identity seam, so it does not run in
// parallel.
func TestVerifyConnMappedFileWhenMapsDeviceDiffers(t *testing.T) {
	const content = "native module"
	superDev := unix.Mkdev(0, 0x1d)

	restore := mapsIdentity
	t.Cleanup(func() { mapsIdentity = restore })

	for _, tc := range []struct {
		name      string
		ownerPath func(pinned string) string
		wantErr   error
	}{
		{name: "owner maps the pinned file", ownerPath: func(p string) string { return p }},
		{name: "owner maps a same-numbered file elsewhere", ownerPath: func(string) string { return "/var/tmp/other.node" }, wantErr: ErrApplicationMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeProc(t)
			path := f.pinnedFile(content)
			statDev, ino := fileIdent(t, path)
			if statDev == superDev {
				t.Skip("host stat device equals the modeled superblock device")
			}
			mapsIdentity = func(*os.File, int64) (heldFile, bool) {
				return heldFile{dev: superDev, ino: ino, path: path, mapped: true}, true
			}
			f.write(strconv.Itoa(fakePID)+"/maps", mapsLine(superDev, ino, tc.ownerPath(path)))
			f.pin.MappedFiles = []FilePin{{Path: path, SHA256: sha256Hex([]byte(content))}}

			_, err := f.verify()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("VerifyConn = %v; a mapping reported under the superblock device must verify", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) || !strings.Contains(err.Error(), "mapped_files[0]") {
				t.Fatalf("VerifyConn = %v, want %v naming mapped_files[0]", err, tc.wantErr)
			}
		})
	}
}
