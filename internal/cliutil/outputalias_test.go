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
	protected := map[string]string{"--key": keyPath}

	// Link fixtures are built inside the subtests that need them. Building them
	// here would skip the whole function on a host without link support, taking
	// the platform-neutral cases down with it.
	linkFixture := func(t *testing.T, name string, create func(string) error) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := create(path); err != nil {
			t.Skipf("%s unsupported here: %v", name, err)
		}
		return path
	}

	for _, tc := range []struct {
		name    string
		outputs map[string]string
		wantErr string
	}{
		{name: "output names the key", outputs: map[string]string{"--out": keyPath}, wantErr: "--out must not name --key"},
		{name: "second output names the key", outputs: map[string]string{"--ledger": keyPath}, wantErr: "--ledger must not name --key"},
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

	t.Run("output symlinks to the key", func(t *testing.T) {
		link := linkFixture(t, "link-to-key", func(p string) error { return os.Symlink(keyPath, p) })
		if err := RefuseOutputAliases(protected, map[string]string{"--out": link}); err == nil ||
			!strings.Contains(err.Error(), "--out must not name --key") {
			t.Fatalf("error = %v, want a refusal", err)
		}
	})

	t.Run("output hard links to the key", func(t *testing.T) {
		link := linkFixture(t, "hardlink-to-key", func(p string) error { return os.Link(keyPath, p) })
		if err := RefuseOutputAliases(protected, map[string]string{"--out": link}); err == nil ||
			!strings.Contains(err.Error(), "--out must not name --key") {
			t.Fatalf("error = %v, want a refusal", err)
		}
	})

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

	t.Run("untraversable output parent is reported", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory mode does not control traversal on Windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("root traverses unreadable directories")
		}
		keyPath := filepath.Join(dir, "present.key")
		if err := os.WriteFile(keyPath, []byte("key-material"), 0o600); err != nil {
			t.Fatal(err)
		}
		blocked := filepath.Join(dir, "blocked-output")
		if err := os.Mkdir(blocked, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) }) // #nosec G302 -- restores the fixture so TempDir cleanup can remove it.
		err := RefuseOutputAliases(map[string]string{"--key": keyPath},
			map[string]string{"--out": filepath.Join(blocked, "sub", "out.json")})
		if err == nil || !strings.Contains(err.Error(), "resolve --out against --key") {
			t.Fatalf("error = %v, want a resolution failure", err)
		}
	})

	t.Run("unresolvable current directory is reported", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows does not permit removing the current directory")
		}
		originalWD, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		vanishedWD := t.TempDir()
		if err := os.Chdir(vanishedWD); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if restoreErr := os.Chdir(originalWD); restoreErr != nil {
				t.Errorf("restore working directory: %v", restoreErr)
			}
		})
		if err := os.Remove(vanishedWD); err != nil {
			t.Skipf("cannot remove current directory on this platform: %v", err)
		}
		if _, err := SamePathIdentity("missing-left", "missing-right"); err == nil {
			t.Fatal("SamePathIdentity accepted paths when the working directory cannot be resolved")
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

// TestRefuseOpenedFileAliases covers the descriptor check that closes the window
// between validating a pathname and opening it.
func TestRefuseOpenedFileAliases(t *testing.T) {
	dir := t.TempDir()
	protectedPath := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(protectedPath, []byte("key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	newOutput := func(t *testing.T, path string) *os.File {
		t.Helper()
		f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}

	t.Run("opened file that is the protected file is refused", func(t *testing.T) {
		// A hard link is the swap that defeats a pre-open symlink check: the
		// pathname is not a symlink, yet the open reaches the protected file.
		aliased := filepath.Join(dir, "ledger-alias.jsonl")
		if err := os.Link(protectedPath, aliased); err != nil {
			t.Skipf("hard links unsupported here: %v", err)
		}
		err := RefuseOpenedFileAliases(newOutput(t, aliased), map[string]string{"the signing key": protectedPath})
		if err == nil || !strings.Contains(err.Error(), "the signing key") {
			t.Fatalf("error = %v, want a refusal naming the protected input", err)
		}
	})

	t.Run("distinct opened file is allowed", func(t *testing.T) {
		if err := RefuseOpenedFileAliases(newOutput(t, filepath.Join(dir, "ledger.jsonl")),
			map[string]string{"the signing key": protectedPath}); err != nil {
			t.Fatalf("RefuseOpenedFileAliases rejected a distinct output: %v", err)
		}
	})

	t.Run("no protected inputs is allowed", func(t *testing.T) {
		if err := RefuseOpenedFileAliases(newOutput(t, filepath.Join(dir, "none.jsonl")), nil); err != nil {
			t.Fatalf("RefuseOpenedFileAliases errored with no protected inputs: %v", err)
		}
		if err := RefuseOpenedFileAliases(newOutput(t, filepath.Join(dir, "empty.jsonl")),
			map[string]string{"the signing key": ""}); err != nil {
			t.Fatalf("RefuseOpenedFileAliases errored on an empty protected path: %v", err)
		}
	})

	t.Run("unstattable protected input fails closed", func(t *testing.T) {
		// The caller has already read this file to sign with it, so a stat
		// failure means the filesystem changed underneath the command. That is
		// exactly when writing is unsafe, so it must refuse rather than proceed.
		err := RefuseOpenedFileAliases(newOutput(t, filepath.Join(dir, "closed.jsonl")),
			map[string]string{"the signing key": filepath.Join(dir, "vanished.key")})
		if err == nil {
			t.Fatal("RefuseOpenedFileAliases proceeded despite an unverifiable protected input")
		}
		if !strings.Contains(err.Error(), "verify the opened output file is not the signing key") {
			t.Fatalf("error = %v, want a fail-closed verification error", err)
		}
	})

	t.Run("uninspectable opened file is refused", func(t *testing.T) {
		// Identity is unknowable when the output itself cannot be inspected, so
		// the write must not proceed. Closing the descriptor first is the
		// deterministic stand-in for a file that cannot be stat'd.
		f := newOutput(t, filepath.Join(dir, "uninspectable.jsonl"))
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		err := RefuseOpenedFileAliases(f, map[string]string{"the signing key": protectedPath})
		if err == nil {
			t.Fatal("RefuseOpenedFileAliases proceeded despite an uninspectable output file")
		}
		if !strings.Contains(err.Error(), "stat opened output file") {
			t.Fatalf("error = %v, want the stat failure reported", err)
		}
	})
}

func TestExistingFileLabelsIgnoresHexAndMissingPaths(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "trusted.key")
	if err := os.WriteFile(keyPath, []byte("key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ExistingFileLabels("--key", []string{
		"4655a7e605c12ebb00a46037881c33c5bca5eb74b45a02e8e7261a7ff5a21678",
		keyPath,
		filepath.Join(dir, "missing.key"),
	})
	if len(got) != 1 || got["--key[1]"] != keyPath {
		t.Fatalf("ExistingFileLabels = %#v, want --key[1] = %q", got, keyPath)
	}
}

func TestRefuseOutputCollisions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "same.json")
	if err := RefuseOutputCollisions(map[string]string{
		"--out":       path,
		"--local-log": path,
	}); err == nil || !strings.Contains(err.Error(), "must not name") {
		t.Fatalf("RefuseOutputCollisions error = %v, want output collision", err)
	}
	if err := RefuseOutputCollisions(map[string]string{
		"--out":       filepath.Join(dir, "bundle.json"),
		"--local-log": filepath.Join(dir, "anchor.jsonl"),
	}); err != nil {
		t.Fatalf("RefuseOutputCollisions rejected distinct outputs: %v", err)
	}
	if err := RefuseOutputCollisions(map[string]string{"--out": path, "--local-log": ""}); err != nil {
		t.Fatalf("RefuseOutputCollisions rejected an empty output: %v", err)
	}
}

func TestExistingRegularFilesLabelsOnlyRegularFiles(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "evidence.jsonl")
	if err := os.WriteFile(filePath, []byte("receipt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o750); err != nil {
		t.Fatal(err)
	}
	got := ExistingRegularFiles("receipt input", dir)
	if len(got) != 1 || got["receipt input"] != filePath {
		t.Fatalf("ExistingRegularFiles = %#v, want receipt input = %q", got, filePath)
	}
	if got := ExistingRegularFiles("receipt input", filepath.Join(dir, "missing")); len(got) != 0 {
		t.Fatalf("ExistingRegularFiles missing dir = %#v, want empty", got)
	}
}
