// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRefuseOutputAliases covers the guard that stops a command output path from
// naming a protected input. The writers involved replace their target, so an
// aliased path would overwrite key material and still report success.
func TestRefuseOutputAliases(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(keyPath, []byte("key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Feature-detect rather than assume: an unprivileged Windows agent cannot
	// create these, and a fixture that cannot be built is not a failure of the
	// code under test.
	linkToKey := filepath.Join(dir, "link-to-key")
	if err := os.Symlink(keyPath, linkToKey); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	hardLinkToKey := filepath.Join(dir, "hardlink-to-key")
	if err := os.Link(keyPath, hardLinkToKey); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}
	protected := map[string]string{"--key": keyPath}

	for _, tc := range []struct {
		name    string
		outputs map[string]string
		wantErr string
	}{
		{name: "output names the key", outputs: map[string]string{"--out": keyPath}, wantErr: "--out must not name --key"},
		{name: "second output names the key", outputs: map[string]string{"--ledger": keyPath}, wantErr: "--ledger must not name --key"},
		{name: "output symlinks to the key", outputs: map[string]string{"--out": linkToKey}, wantErr: "--out must not name --key"},
		{name: "output hard links to the key", outputs: map[string]string{"--out": hardLinkToKey}, wantErr: "--out must not name --key"},
		{name: "relative path names the key", outputs: map[string]string{"--out": filepath.Join(dir, "..", filepath.Base(dir), "signing.key")}, wantErr: "--out must not name --key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RefuseOutputAliases(protected, tc.outputs)
			if err == nil {
				t.Fatal("RefuseOutputAliases accepted an output path naming a protected input")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}

	t.Run("distinct paths are allowed", func(t *testing.T) {
		if err := RefuseOutputAliases(protected, map[string]string{
			"--out":    filepath.Join(dir, "roster.json"),
			"--ledger": filepath.Join(dir, "licenses.jsonl"),
		}); err != nil {
			t.Fatalf("RefuseOutputAliases rejected distinct output paths: %v", err)
		}
	})

	t.Run("empty paths are ignored", func(t *testing.T) {
		if err := RefuseOutputAliases(protected, map[string]string{"--out": "", "--ledger": ""}); err != nil {
			t.Fatalf("RefuseOutputAliases rejected empty output paths: %v", err)
		}
		if err := RefuseOutputAliases(map[string]string{"--key": ""}, map[string]string{"--out": keyPath}); err != nil {
			t.Fatalf("RefuseOutputAliases rejected an empty protected path: %v", err)
		}
	})

	t.Run("every protected input is checked", func(t *testing.T) {
		rootPath := filepath.Join(dir, "root.json")
		if err := os.WriteFile(rootPath, []byte("root-material"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := RefuseOutputAliases(map[string]string{"--key": keyPath, "the roster root key": rootPath},
			map[string]string{"--out": rootPath})
		if err == nil || !strings.Contains(err.Error(), "the roster root key") {
			t.Fatalf("error = %v, want the second protected input to be reported", err)
		}
	})
}

// TestRefuseOutputAliases_ResolutionEdges covers the comparison branches a normal
// command reaches: a protected file that does not exist yet, an output whose
// parent directory is absent, and a path that cannot be traversed.
func TestRefuseOutputAliases_ResolutionEdges(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing protected file is not an alias", func(t *testing.T) {
		if err := RefuseOutputAliases(map[string]string{"--key": filepath.Join(dir, "absent.key")},
			map[string]string{"--out": filepath.Join(dir, "out.json")}); err != nil {
			t.Fatalf("RefuseOutputAliases errored on a missing protected file: %v", err)
		}
	})

	t.Run("output parent does not exist", func(t *testing.T) {
		keyPath := filepath.Join(dir, "present.key")
		if err := os.WriteFile(keyPath, []byte("key-material"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RefuseOutputAliases(map[string]string{"--key": keyPath},
			map[string]string{"--out": filepath.Join(dir, "no-such-dir", "out.json")}); err != nil {
			t.Fatalf("RefuseOutputAliases errored on an absent output parent: %v", err)
		}
	})

	t.Run("untraversable parent is reported", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory mode does not control traversal on Windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("root traverses unreadable directories")
		}
		blocked := filepath.Join(dir, "blocked")
		if err := os.Mkdir(blocked, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) }) // #nosec G302 -- restores the fixture so TempDir cleanup can remove it.
		err := RefuseOutputAliases(map[string]string{"--key": filepath.Join(blocked, "sub", "signing.key")},
			map[string]string{"--out": filepath.Join(dir, "out.json")})
		if err == nil || !strings.Contains(err.Error(), "resolve --out against --key") {
			t.Fatalf("error = %v, want a resolution failure", err)
		}
	})
}

// TestRefuseOutputAliases_SymlinkThenDotDot pins the spelling that lexical
// normalization gets wrong. filepath.Clean collapses ".." before any symlink is
// resolved; the filesystem does not. With an intermediate symlink followed by
// "..", a cleaned string names a different file than the kernel opens, so
// deciding identity lexically would let an alias through.
func TestRefuseOutputAliases_SymlinkThenDotDot(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	subDir := filepath.Join(realDir, "sub")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatal(err)
	}
	viaDir := filepath.Join(dir, "via")
	if err := os.Mkdir(viaDir, 0o750); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(realDir, "signing.key")
	if err := os.WriteFile(keyPath, []byte("key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(viaDir, "link")
	if err := os.Symlink(subDir, link); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}

	// Build the spelling by hand: filepath.Join cleans its result, which would
	// collapse the ".." here and destroy the very case under test. The kernel
	// resolves this to realDir/signing.key, while a cleaned string names
	// viaDir/signing.key, which does not exist.
	aliased := link + string(filepath.Separator) + ".." + string(filepath.Separator) + "signing.key"
	if _, err := os.Stat(aliased); err != nil {
		t.Fatalf("fixture is wrong, the aliased spelling should reach the key: %v", err)
	}

	err := RefuseOutputAliases(map[string]string{"the signing key": keyPath}, map[string]string{"--out": aliased})
	if err == nil {
		t.Fatal("RefuseOutputAliases accepted a symlink-then-dotdot alias of the protected file")
	}
	if !strings.Contains(err.Error(), "must not name the signing key") {
		t.Fatalf("error = %v, want the protected input named", err)
	}
}
