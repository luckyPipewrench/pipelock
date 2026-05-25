// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSidecarOpConstructorsAndAccessors(t *testing.T) {
	t.Parallel()

	w := SidecarWrite("/p/x.headers", []byte("X: 1\n"))
	if !w.IsWrite() || w.IsDelete() || w.Path() != "/p/x.headers" || string(w.Body()) != "X: 1\n" {
		t.Errorf("write op accessors wrong: %+v", w)
	}
	d := SidecarDelete("/p/x.headers")
	if !d.IsDelete() || d.IsWrite() || d.Path() != "/p/x.headers" || d.Body() != nil {
		t.Errorf("delete op accessors wrong: %+v", d)
	}
}

func TestApplySidecarOps_WriteThenDelete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path, err := headerSidecarPath("/cfg/config.yaml", "remote")
	if err != nil {
		t.Fatalf("headerSidecarPath: %v", err)
	}
	if err := ApplySidecarOps([]SidecarOp{SidecarWrite(path, []byte("Authorization: Bearer x\n"))}); err != nil {
		t.Fatalf("apply write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("sidecar perms = %o, want 600", info.Mode().Perm())
	}
	// Parent dir must be 0700.
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("sidecar dir perms = %o, want 700", dirInfo.Mode().Perm())
	}

	if err := ApplySidecarOps([]SidecarOp{SidecarDelete(path)}); err != nil {
		t.Fatalf("apply delete: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("sidecar still present after delete: %v", err)
	}
	// Deleting an already-absent sidecar is a no-op, not an error.
	if err := ApplySidecarOps([]SidecarOp{SidecarDelete(path)}); err != nil {
		t.Errorf("delete of missing sidecar errored: %v", err)
	}
}

func TestApplySidecarOps_RollsBackOnWriteFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	good, err := headerSidecarPath("/cfg/config.yaml", "good")
	if err != nil {
		t.Fatalf("headerSidecarPath: %v", err)
	}
	// A path whose parent cannot be created (a file occupies a parent segment).
	blocker := filepath.Join(home, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	bad := filepath.Join(blocker, "nested", "x.headers")

	err = ApplySidecarOps([]SidecarOp{
		SidecarWrite(good, []byte("X: 1\n")),
		SidecarWrite(bad, []byte("Y: 2\n")),
	})
	if err == nil {
		t.Fatal("expected the second (impossible) write to fail")
	}
	// The first write must have been rolled back.
	if _, statErr := os.Stat(good); !os.IsNotExist(statErr) {
		t.Errorf("first sidecar not rolled back after failure: %v", statErr)
	}
}

func TestRollbackSidecarWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	one, _ := headerSidecarPath("/cfg.yaml", "one")
	two, _ := headerSidecarPath("/cfg.yaml", "two")
	ops := []SidecarOp{SidecarWrite(one, []byte("A: 1\n")), SidecarWrite(two, []byte("B: 2\n"))}
	if err := ApplySidecarOps(ops); err != nil {
		t.Fatalf("apply: %v", err)
	}
	RollbackSidecarWrites(ops)
	for _, p := range []string{one, two} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s not removed by rollback", p)
		}
	}
}

func TestHeaderSidecarPath_CollisionSafe(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Same server name, different config paths -> different sidecars.
	a, _ := headerSidecarPath("/home/a/mcp.json", "remote")
	b, _ := headerSidecarPath("/home/b/mcp.json", "remote")
	if a == b {
		t.Error("different config paths collided on one sidecar")
	}
	// Names that sanitize to the same component -> different sidecars (hashed).
	slashed, _ := headerSidecarPath("/cfg.yaml", "prod/api")
	under, _ := headerSidecarPath("/cfg.yaml", "prod_api")
	if slashed == under {
		t.Error("prod/api and prod_api collided despite sanitization")
	}
	// The sidecar lives under the shared operator-private dir.
	wantDir := filepath.Join(home, ".config", "pipelock", "wrap-headers")
	if filepath.Dir(a) != wantDir {
		t.Errorf("sidecar dir = %q, want %q", filepath.Dir(a), wantDir)
	}
	if !strings.HasSuffix(a, ".headers") {
		t.Errorf("sidecar path %q must end in .headers", a)
	}
}

func TestSanitizeSidecarComponent(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"plain":      "plain",
		"a.b-c_d":    "a.b-c_d",
		"prod/api":   "prod_api",
		"weird name": "weird_name",
		"":           "_",
		"../escape":  ".._escape",
	}
	for in, want := range cases {
		if got := sanitizeSidecarComponent(in); got != want {
			t.Errorf("sanitizeSidecarComponent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidatedHeaderSidecarDeletePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got, err := validatedHeaderSidecarDeletePath(""); err != nil || got != "" {
		t.Errorf("empty path: got %q err %v", got, err)
	}
	inside, _ := headerSidecarPath("/cfg.yaml", "ok")
	if got, err := validatedHeaderSidecarDeletePath(inside); err != nil || got != inside {
		t.Errorf("valid inside path rejected: got %q err %v", got, err)
	}

	dir := filepath.Join(home, ".config", "pipelock", "wrap-headers")
	bad := []struct {
		name, path, want string
	}{
		{"relative", "rel/x.headers", "must be absolute"},
		{"wrong suffix", filepath.Join(dir, "x.txt"), "must end in .headers"},
		{"escapes dir", filepath.Join(home, "elsewhere.headers"), "escapes"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validatedHeaderSidecarDeletePath(tc.path); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("path %q err = %v, want containing %q", tc.path, err, tc.want)
			}
		})
	}
}

func TestExtractHeaderLines(t *testing.T) {
	t.Parallel()

	// No headers -> nil.
	if lines, err := extractHeaderLines(map[string]interface{}{}); err != nil || lines != nil {
		t.Errorf("no headers: lines=%v err=%v", lines, err)
	}
	// Sorted, "Key: Value" form, whitespace trimmed.
	lines, err := extractHeaderLines(map[string]interface{}{
		FieldHeaders: map[string]interface{}{"X-B": " 2 ", "X-A": "1"},
	})
	if err != nil {
		t.Fatalf("extractHeaderLines: %v", err)
	}
	want := []string{"X-A: 1", "X-B: 2"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Errorf("lines = %v, want %v", lines, want)
	}
}

func TestValidateHeader(t *testing.T) {
	t.Parallel()

	bad := []struct{ key, val, want string }{
		{"", "v", "empty"},
		{"Bad Key", "v", "invalid characters"},
		{"Content-Type", "v", "managed by the MCP HTTP transport"},
		{"Mcp-Session-Id", "v", "managed by the MCP HTTP transport"},
		{"X-Ok", "bad\nvalue", "invalid value"},
	}
	for _, tc := range bad {
		if err := validateHeader(tc.key, tc.val); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("validateHeader(%q,%q) = %v, want containing %q", tc.key, tc.val, err, tc.want)
		}
	}
	if err := validateHeader("Authorization", "Bearer abc"); err != nil {
		t.Errorf("valid header rejected: %v", err)
	}
}

func TestAtomicWriteFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "out.json")
	if err := AtomicWriteFile(target, []byte("{}"), dir); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms = %o, want 600", info.Mode().Perm())
	}
	// Overwrite works.
	if err := AtomicWriteFile(target, []byte("{\"v\":1}"), dir); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	data, _ := os.ReadFile(filepath.Clean(target))
	if string(data) != "{\"v\":1}" {
		t.Errorf("content = %q", data)
	}
	// Missing tmpDir -> error.
	if err := AtomicWriteFile(filepath.Join(dir, "x"), []byte("y"), filepath.Join(dir, "nope")); err == nil {
		t.Error("expected error for missing tmpDir")
	}
}

func TestFullRoundTrip_WrapApplyUnwrapDelete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	server := map[string]interface{}{
		FieldURL:     "https://up/mcp",
		FieldHeaders: map[string]interface{}{"Authorization": "Bearer secret"},
	}
	wrapped, meta, writeOp, err := WrapServer(server, fakeExe, "", "/cfg.yaml", "remote")
	if err != nil {
		t.Fatalf("WrapServer: %v", err)
	}
	if writeOp == nil {
		t.Fatal("expected sidecar write op")
	}
	if err := ApplySidecarOps([]SidecarOp{*writeOp}); err != nil {
		t.Fatalf("apply write: %v", err)
	}
	if _, statErr := os.Stat(meta.HeaderSidecarPath); statErr != nil {
		t.Fatalf("sidecar not on disk: %v", statErr)
	}

	wrapped[FieldPipelock] = roundTripMeta(t, meta)
	_, deleteOp, err := UnwrapServer(wrapped)
	if err != nil {
		t.Fatalf("UnwrapServer: %v", err)
	}
	if deleteOp == nil || !deleteOp.IsDelete() {
		t.Fatal("expected sidecar delete op from unwrap")
	}
	if err := ApplySidecarOps([]SidecarOp{*deleteOp}); err != nil {
		t.Fatalf("apply delete: %v", err)
	}
	if _, statErr := os.Stat(meta.HeaderSidecarPath); !os.IsNotExist(statErr) {
		t.Errorf("sidecar not cleaned up: %v", statErr)
	}
}
