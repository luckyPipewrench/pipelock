// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHeaderSidecarPath_NoHome exercises the os.UserHomeDir error branch that
// propagates through headerSidecarDir into the path helpers.
func TestHeaderSidecarPath_NoHome(t *testing.T) {
	t.Setenv("HOME", "")

	if _, err := headerSidecarPath("/c.yaml", "s"); err == nil {
		t.Fatal("headerSidecarPath: expected error when HOME is unset")
	}
	if _, err := validatedHeaderSidecarDeletePath("/abs/x.headers"); err == nil {
		t.Fatal("validatedHeaderSidecarDeletePath: expected error when HOME is unset")
	}
}

func TestPathWithinDir(t *testing.T) {
	t.Parallel()

	dir := filepath.FromSlash("/a/b")
	cases := []struct {
		path string
		want bool
	}{
		{dir, false}, // the directory itself
		{filepath.FromSlash("/a/b/c.headers"), true},
		{filepath.FromSlash("/a/x"), false},      // sibling
		{filepath.FromSlash("/a/b/../x"), false}, // escapes via ..
	}
	for _, tc := range cases {
		if got := pathWithinDir(dir, tc.path); got != tc.want {
			t.Errorf("pathWithinDir(%q,%q) = %v, want %v", dir, tc.path, got, tc.want)
		}
	}
}

// TestValidatedHeaderSidecarDeletePath_SymlinkEscape covers the EvalSymlinks
// containment check: a sidecar-looking symlink inside the dir that resolves to
// a file outside it must be rejected (defends remove against tampered metadata
// turning into an arbitrary-file delete via a symlink).
func TestValidatedHeaderSidecarDeletePath_SymlinkEscape(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".config", "pipelock", "wrap-headers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outside := filepath.Join(home, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	target := filepath.Join(outside, "evil.headers")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(dir, "evil.headers")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := validatedHeaderSidecarDeletePath(link); err == nil || !strings.Contains(err.Error(), "resolves outside") {
		t.Fatalf("symlink escape not rejected: %v", err)
	}
}

func TestParseMeta_NonObject(t *testing.T) {
	t.Parallel()

	// A _pipelock value that is not an object fails the JSON unmarshal into Meta.
	if _, _, err := ParseMeta(map[string]interface{}{FieldPipelock: "not-an-object"}); err == nil {
		t.Fatal("expected error parsing non-object _pipelock metadata")
	}
}

func TestUnwrapServer_MetaParseError(t *testing.T) {
	t.Parallel()

	// Non-object metadata propagates the ParseMeta error out of UnwrapServer.
	if _, _, err := UnwrapServer(map[string]interface{}{FieldPipelock: "garbage"}); err == nil {
		t.Fatal("expected UnwrapServer to surface a metadata parse error")
	}
}

func TestUnwrapServer_BadSidecarPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// A relative sidecar path in metadata must be rejected (not turned into a
	// delete op against an arbitrary relative file).
	_, _, err := UnwrapServer(map[string]interface{}{
		FieldPipelock: map[string]interface{}{
			"original_type":       "http",
			"original_url":        "https://u/mcp",
			"header_sidecar_path": "relative/x.headers",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("err = %v, want containing 'must be absolute'", err)
	}
}

func TestApplySidecarOps_EmptyDeletePath(t *testing.T) {
	t.Parallel()

	// A delete op with an empty path is a silent no-op.
	if err := ApplySidecarOps([]SidecarOp{SidecarDelete("")}); err != nil {
		t.Fatalf("empty delete path errored: %v", err)
	}
}

func TestValidHeaderValue_NonASCII(t *testing.T) {
	t.Parallel()

	// A non-ASCII, non-space value is allowed (e.g. accented text).
	if err := validateHeader("X-Note", "héllo"); err != nil {
		t.Errorf("non-ASCII non-space value rejected: %v", err)
	}
	// A non-ASCII whitespace rune (U+00A0 no-break space) is rejected.
	if err := validateHeader("X-Note", "a b"); err == nil || !strings.Contains(err.Error(), "invalid value") {
		t.Errorf("non-ASCII whitespace value should be rejected, got %v", err)
	}
}

// TestCommitHeaderSidecar_RejectsLooseDir verifies that writing a credential
// sidecar into a pre-existing group/other-accessible directory is refused
// rather than silently widening exposure.
func TestCommitHeaderSidecar_RejectsLooseDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".config", "pipelock", "wrap-headers")
	// 0o750 grants group access; 0o750 is within G301's allowed range, so no
	// lint suppression is needed to create it for the test.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir loose: %v", err)
	}
	path := filepath.Join(dir, "x.headers")
	err := commitHeaderSidecar(path, []byte("X: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "too permissive") {
		t.Fatalf("commitHeaderSidecar err = %v, want a 'too permissive' rejection", err)
	}
}
