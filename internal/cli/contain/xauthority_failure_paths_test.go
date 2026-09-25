// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisplayAuthorityOversizeRegenerates(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	env.readFileBounded = readContainFileBounded
	if err := os.WriteFile(env.displayAuthorityPath, bytes.Repeat([]byte{'x'}, maxDisplayAuthorityBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, exists, err := readDisplayAuthority(env); err != nil || exists || data != nil {
		t.Fatalf("oversize authority = %d bytes, exists=%t, err=%v; want regeneration", len(data), exists, err)
	}
	if err := os.WriteFile(env.displayAuthorityPath, []byte("valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, exists, err := readDisplayAuthority(env); err != nil || !exists || string(data) != "valid" {
		t.Fatalf("valid authority = %q, exists=%t, err=%v", data, exists, err)
	}
}

func TestDisplayAuthorityReadRemoveRestoreFailures(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	path := env.displayAuthorityPath
	if data, exists, err := readDisplayAuthority(env); err != nil || exists || data != nil {
		t.Fatalf("absent read = %q, %v, %v", data, exists, err)
	}
	if err := removeDisplayAuthority(env); err != nil {
		t.Fatalf("remove absent: %v", err)
	}
	env.readFileBounded = func(string, int64) ([]byte, error) { return nil, os.ErrPermission }
	if _, exists, err := readDisplayAuthority(env); exists || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("read denied = %v, %v", exists, err)
	}
	env.removeFile = func(string) error { return os.ErrPermission }
	if err := removeDisplayAuthority(env); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("remove denied: %v", err)
	}
	env.removeFile = os.Remove
	env.readFileBounded = readContainFileBounded
	if err := restoreDisplayAuthority(env, []byte("previous"), true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, err := os.ReadFile(filepath.Clean(path)); err != nil || string(got) != "previous" {
		t.Fatalf("restored content = %q, %v", got, err)
	}
	if err := restoreDisplayAuthority(env, nil, false); err != nil {
		t.Fatalf("remove by restore: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("authority remains: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*installEnv)
		want   string
	}{
		{"write", func(e *installEnv) { e.writeFile = func(string, []byte, os.FileMode) error { return os.ErrPermission } }, "restore Xauthority file"},
		{"chown", func(e *installEnv) { e.chown = func(string, int, int) error { return os.ErrPermission } }, "restore Xauthority ownership"},
		{"lookup", func(e *installEnv) { e.agentUserName = "absent-agent" }, "absent-agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := covDispPrepareDisplayEnv(t)
			tc.change(e)
			if err := restoreDisplayAuthority(e, []byte("prior"), true); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("restore error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestWriteDisplayAuthorityFaults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*installEnv)
		random []byte
		want   string
	}{
		{"nil random", nil, nil, "random source is nil"},
		{"short random", nil, []byte{1}, "generate Xauthority cookie"},
		{"write denied", func(e *installEnv) { e.writeFile = func(string, []byte, os.FileMode) error { return os.ErrPermission } }, bytes.Repeat([]byte{1}, displayAuthorityCookieSize), "write Xauthority file"},
		{"lookup denied", func(e *installEnv) { e.agentUserName = "absent-agent" }, bytes.Repeat([]byte{1}, displayAuthorityCookieSize), "absent-agent"},
		{"chown denied", func(e *installEnv) { e.chown = func(string, int, int) error { return os.ErrPermission } }, bytes.Repeat([]byte{1}, displayAuthorityCookieSize), "chown Xauthority file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := covDispPrepareDisplayEnv(t)
			if tc.change != nil {
				tc.change(env)
			}
			var source *bytes.Reader
			if tc.random != nil {
				source = bytes.NewReader(tc.random)
			}
			var err error
			if source == nil {
				err = writeDisplayAuthority(env, nil)
			} else {
				err = writeDisplayAuthority(env, source)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("write error = %v, want %q", err, tc.want)
			}
			if tc.name == "lookup denied" || tc.name == "chown denied" {
				if _, statErr := os.Lstat(env.displayAuthorityPath); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("failed write left cookie: %v", statErr)
				}
			}
		})
	}
}

func TestEnsureDisplayAuthorityDirFailures(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		if err := ensureDisplayAuthorityDir(env, "relative"); err == nil || !strings.Contains(err.Error(), "not absolute") {
			t.Fatalf("relative path: %v", err)
		}
	})
	for _, tc := range []struct {
		name string
		info os.FileInfo
		want string
	}{
		{"non-directory", fakeFileInfo{mode: 0o600, sys: fakeFileSysWithUID(0)}, "not a real directory"},
		{"wrong owner", fakeFileInfo{mode: os.ModeDir | 0o711, sys: fakeFileSysWithUID(1234)}, "not root-owned"},
		{"writable", fakeFileInfo{mode: os.ModeDir | 0o733, sys: fakeFileSysWithUID(0)}, "writable by non-root users"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := covDispPrepareDisplayEnv(t)
			dir := filepath.Dir(env.displayAuthorityPath)
			priorLstat := env.lstat
			env.lstat = func(path string) (os.FileInfo, error) {
				if filepath.Clean(path) == dir {
					return tc.info, nil
				}
				return priorLstat(path)
			}
			if err := ensureDisplayAuthorityDir(env, dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("directory error = %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("chmod denied", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
		if err := ensureDisplayAuthorityDir(env, filepath.Dir(env.displayAuthorityPath)); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("chmod error: %v", err)
		}
	})
	for _, tc := range []struct {
		name, want string
		change     func(*installEnv, string)
	}{
		{"parent stat denied", "stat parent", func(e *installEnv, dir string) {
			parent := filepath.Dir(dir)
			priorLstat := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == parent {
					return nil, os.ErrPermission
				}
				return priorLstat(p)
			}
		}},
		{"state stat denied", "stat Xauthority directory", func(e *installEnv, dir string) {
			priorLstat := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == dir {
					return nil, os.ErrPermission
				}
				return priorLstat(p)
			}
		}},
		{"state creation denied", "create Xauthority state directory", func(e *installEnv, dir string) {
			_ = os.Remove(dir)
			e.mkdirAll = func(string, os.FileMode) error { return os.ErrPermission }
		}},
		{"state missing after creation", "stat Xauthority state directory", func(e *installEnv, dir string) {
			_ = os.Remove(dir)
			e.mkdirAll = func(string, os.FileMode) error { return nil }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := covDispPrepareDisplayEnv(t)
			dir := filepath.Dir(env.displayAuthorityPath)
			tc.change(env, dir)
			if err := ensureDisplayAuthorityDir(env, dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("directory error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDisplayAuthorityFieldAndLateDirectoryChecks(t *testing.T) {
	if _, err := encodeDisplayAuthority(strings.Repeat("h", 65536), "7", bytes.Repeat([]byte{1}, displayAuthorityCookieSize)); err == nil || !strings.Contains(err.Error(), "field is too long") {
		t.Fatalf("large host field: %v", err)
	}
	for _, tc := range []struct {
		name string
		info os.FileInfo
		want string
	}{
		{"path becomes file", fakeFileInfo{mode: 0o600, sys: fakeFileSysWithUID(0)}, "not a real directory"},
		{"path changes owner", fakeFileInfo{mode: os.ModeDir | 0o711, sys: fakeFileSysWithUID(1234)}, "not root-owned"},
		{"path becomes writable", fakeFileInfo{mode: os.ModeDir | 0o733, sys: fakeFileSysWithUID(0)}, "writable by non-root users"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := covDispPrepareDisplayEnv(t)
			dir := filepath.Dir(env.displayAuthorityPath)
			priorLstat := env.lstat
			seen := 0
			env.lstat = func(path string) (os.FileInfo, error) {
				if path == dir {
					seen++
					if seen == 2 {
						return tc.info, nil
					}
				}
				return priorLstat(path)
			}
			if err := ensureDisplayAuthorityDir(env, dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("late check error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDisplayAuthorityRejectsUnsafeWriteTargets(t *testing.T) {
	t.Run("write target symlink", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		target := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, env.displayAuthorityPath); err != nil {
			t.Fatal(err)
		}
		if err := writeDisplayAuthority(env, bytes.NewReader(bytes.Repeat([]byte{1}, displayAuthorityCookieSize))); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("write target: %v", err)
		}
		if got, _ := os.ReadFile(filepath.Clean(target)); string(got) != "untouched" {
			t.Fatalf("target changed: %s", got)
		}
		if err := restoreDisplayAuthority(env, []byte("prior"), true); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("restore target: %v", err)
		}
	})
	t.Run("restore directory fails", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		env.displayAuthorityPath = filepath.Join("relative", "Xauthority")
		if err := restoreDisplayAuthority(env, []byte("prior"), true); err == nil || !strings.Contains(err.Error(), "not absolute") {
			t.Fatalf("restore directory: %v", err)
		}
	})
}
