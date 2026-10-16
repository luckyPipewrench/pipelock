// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveManifestFailsClosed(t *testing.T) {
	const name = "manifest.json"
	tests := []struct {
		name  string
		setup func(t *testing.T) string // returns the directory to write into
		want  string                    // empty means success expected
		is    func(error) bool
		left  []string // exact directory entries expected after a failure
	}{
		{name: "writable directory round-trips", setup: func(t *testing.T) string { return t.TempDir() }},
		{
			name: "missing directory", setup: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") },
			want: "creating temp file", is: func(err error) bool { return errors.Is(err, fs.ErrNotExist) },
		},
		{name: "destination occupied by a directory", setup: func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, name, "child"), 0o750); err != nil {
				t.Fatal(err)
			}
			return dir
		}, want: "renaming temp file", is: func(err error) bool { var le *os.LinkError; return errors.As(err, &le) }, left: []string{name}},
		{name: "read-only directory", setup: func(t *testing.T) string {
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("directory write permission is not enforced here")
			}
			dir := filepath.Join(t.TempDir(), "ro")
			if err := os.Mkdir(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restore so TempDir cleanup can remove it
			return dir
		}, want: "creating temp file", is: func(err error) bool { return errors.Is(err, fs.ErrPermission) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t)
			path := filepath.Join(dir, name)
			m := &Manifest{Version: ManifestVersion, Entries: map[string]string{"/usr/bin/tool": strings.Repeat("ab", 32)}}
			err := SaveManifest(path, m)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("SaveManifest: %v", err)
				}
				loaded, loadErr := LoadManifest(path)
				if loadErr != nil {
					t.Fatalf("LoadManifest after save: %v", loadErr)
				}
				if loaded.Version != m.Version || len(loaded.Entries) != 1 || loaded.Entries["/usr/bin/tool"] != m.Entries["/usr/bin/tool"] {
					t.Fatalf("round-trip = %+v, want %+v", loaded, m)
				}
				info, statErr := os.Stat(path)
				if statErr != nil {
					t.Fatal(statErr)
				}
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
					t.Fatalf("manifest mode = %o, want 600", info.Mode().Perm())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("SaveManifest error = %v, want %q", err, tt.want)
			}
			if !tt.is(err) {
				t.Fatalf("SaveManifest error %v does not carry the expected cause", err)
			}
			entries, dirErr := os.ReadDir(dir)
			if dirErr != nil {
				if errors.Is(dirErr, fs.ErrNotExist) && len(tt.left) == 0 {
					return
				}
				t.Fatal(dirErr)
			}
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if strings.Join(names, ",") != strings.Join(tt.left, ",") {
				t.Fatalf("directory after failed save = %v, want exactly %v", names, tt.left)
			}
		})
	}
}
