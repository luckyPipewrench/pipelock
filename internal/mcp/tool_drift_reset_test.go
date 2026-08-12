// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The tool-drift reset file re-baselines the listener's shared upstream tool
// inventory, so it is a security-relevant operator action and carries the same
// owner-only, one-shot contract as the adaptive reset. These pin that contract
// on the drift path specifically: a file the wrapped agent could plant must
// never clear the baseline that agent's own upstream is being measured against.
func TestConsumeToolDriftResetFile_HonorsOwnerOnlyFileOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "drift-reset")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var logW bytes.Buffer

	if !consumeToolDriftResetFile(path, &logW) {
		t.Fatalf("owner-only drift reset was not honored, log=%q", logW.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("drift reset file must be removed after honoring (err=%v)", err)
	}
	if consumeToolDriftResetFile(path, &logW) {
		t.Fatal("drift reset must be one-shot")
	}
}

func TestConsumeToolDriftResetFile_RejectsPlantedFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits and symlink semantics are not the access control on Windows")
	}

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "drift-reset")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		var logW bytes.Buffer

		if consumeToolDriftResetFile(link, &logW) {
			t.Fatal("a symlinked drift reset file must not re-baseline the listener")
		}
		if !strings.Contains(logW.String(), "tool drift") || !strings.Contains(logW.String(), "symlink") {
			t.Errorf("rejection must say what was refused and why; log=%q", logW.String())
		}
		// Removed, so a planted path is not re-checked and re-warned forever.
		if _, err := os.Lstat(link); !os.IsNotExist(err) {
			t.Errorf("rejected symlink was not cleaned up (err=%v)", err)
		}
	})

	t.Run("group or world accessible", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o660, 0o666, 0o604, 0o640} {
			t.Run(mode.String(), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "drift-reset")
				if err := os.WriteFile(path, nil, mode); err != nil {
					t.Fatal(err)
				}
				// WriteFile honors umask, which can quietly turn this into an
				// owner-only file and make the whole case vacuous. Force it.
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				var logW bytes.Buffer

				if consumeToolDriftResetFile(path, &logW) {
					t.Fatalf("mode %o must not re-baseline the listener (agent-writable bypass)", mode)
				}
				if !strings.Contains(logW.String(), "unsafe mode") {
					t.Errorf("rejection must name the mode problem; log=%q", logW.String())
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Error("an unsafe reset file must be removed, not left to persist")
				}
			})
		}
	})

	t.Run("not a regular file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "drift-reset")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		var logW bytes.Buffer

		if consumeToolDriftResetFile(path, &logW) {
			t.Fatal("a directory must not be honored as a drift reset file")
		}
		if !strings.Contains(logW.String(), "not a regular file") {
			t.Errorf("rejection must name the file-type problem; log=%q", logW.String())
		}
		// A directory is never removed, or a mistyped config path could delete
		// a tree on every request.
		if _, err := os.Stat(path); err != nil {
			t.Errorf("a directory must be left in place, got err=%v", err)
		}
	})

	t.Run("empty and missing are silent no-ops", func(t *testing.T) {
		var logW bytes.Buffer
		if consumeToolDriftResetFile("", &logW) {
			t.Error("empty path must be a no-op")
		}
		if consumeToolDriftResetFile(filepath.Join(t.TempDir(), "absent"), &logW) {
			t.Error("missing file must be a no-op")
		}
		if logW.String() != "" {
			t.Errorf("an absent reset file must not warn; log=%q", logW.String())
		}
	})
}
