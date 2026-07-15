//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSecureTokenFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("0600", func(t *testing.T) {
		path := write("owner.token", " owner-only \n", 0o600)
		got, err := readSecureTokenFile("--token-file", path)
		if err != nil || got != "owner-only" {
			t.Fatalf("token/error = %q/%v", got, err)
		}
	})
	t.Run("0640", func(t *testing.T) {
		path := write("group.token", "group-readable", 0o640)
		if _, err := readSecureTokenFile("--token-file", path); err != nil {
			t.Fatalf("0640 token rejected: %v", err)
		}
	})
	t.Run("0440 secret volume", func(t *testing.T) {
		path := write("volume.token", "group-readable", 0o440)
		if _, err := readSecureTokenFile("--token-file", path); err != nil {
			t.Fatalf("0440 token rejected: %v", err)
		}
	})
	t.Run("world readable", func(t *testing.T) {
		path := write("world.token", "exposed", 0o644)
		if _, err := readSecureTokenFile("--token-file", path); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("error = %v, want permissions rejection", err)
		}
	})
	t.Run("in-directory secret volume symlink", func(t *testing.T) {
		versionDir := filepath.Join(dir, "..2026_07_14")
		if err := os.Mkdir(versionDir, 0o750); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(versionDir, "token")
		secretVolumeMode := os.FileMode(0o400 | 0o040)
		if err := os.WriteFile(target, []byte("rotated-secret"), secretVolumeMode); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.token")
		if err := os.Symlink(filepath.Join(filepath.Base(versionDir), "token"), link); err != nil {
			t.Fatal(err)
		}
		if got, err := readSecureTokenFile("--token-file", link); err != nil || got != "rotated-secret" {
			t.Fatalf("token/error = %q/%v, want managed symlink accepted", got, err)
		}
	})
	t.Run("escaping symlink", func(t *testing.T) {
		outside := t.TempDir()
		target := filepath.Join(outside, "target.token")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "escape.token")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readSecureTokenFile("--token-file", link); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("error = %v, want escaping symlink rejection", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := readSecureTokenFile("--token-file", dir); err == nil || !strings.Contains(err.Error(), "regular") {
			t.Fatalf("error = %v, want regular-file rejection", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		path := write("large.token", strings.Repeat("x", conductorTokenFileMaxBytes+1), 0o600)
		if _, err := readSecureTokenFile("--token-file", path); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("error = %v, want size rejection", err)
		}
	})
}
