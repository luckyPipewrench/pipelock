// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTrustedRootRelativePathBoundary(t *testing.T) {
	root := t.TempDir()
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	missingRoot := filepath.Join(root, "absent")
	tests := []struct {
		name    string
		root    string
		path    string
		wantRel string
		want    string // empty means success expected
		is      error
		exact   string // full error text for rows whose error wraps no cause
	}{
		{name: "child path accepted", root: root, path: filepath.Join(root, "profiles", "agent.json"), wantRel: filepath.Join("profiles", "agent.json")},
		{name: "dot-dot named child accepted", root: root, path: filepath.Join(root, "..hidden"), wantRel: "..hidden"},
		{name: "empty trusted root", root: "", path: filepath.Join(root, "x"), want: "trusted root is empty", exact: "profile trusted root is empty"},
		{
			name: "root itself is not a file path", root: root, path: root, want: "escapes trusted root",
			exact: fmt.Sprintf("profile path %q escapes trusted root %q", root, root),
		},
		{
			name: "parent escape", root: root, path: filepath.Dir(root), want: "escapes trusted root",
			exact: fmt.Sprintf("profile path %q escapes trusted root %q", filepath.Dir(root), root),
		},
		{name: "sibling escape", root: root, path: filepath.Join(filepath.Dir(root), "other", "x"), want: "escapes trusted root"},
		{name: "missing root cannot be canonicalized", root: missingRoot, path: filepath.Join(missingRoot, "x"), want: "canonicalize trusted root", is: fs.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRoot, gotRel, err := trustedRootRelativePath(tt.root, filepath.Clean(tt.path), "profile")
			if tt.want == "" {
				if err != nil {
					t.Fatalf("trustedRootRelativePath: %v", err)
				}
				if gotRoot != canonical || gotRel != tt.wantRel {
					t.Fatalf("got (%q, %q), want (%q, %q)", gotRoot, gotRel, canonical, tt.wantRel)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if tt.exact != "" && err.Error() != tt.exact {
				t.Fatalf("error = %q, want exactly %q", err.Error(), tt.exact)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Fatalf("error %v does not wrap %v", err, tt.is)
			}
			if gotRoot != "" || gotRel != "" {
				t.Fatalf("got (%q, %q) alongside error, want empty", gotRoot, gotRel)
			}
		})
	}
}

func TestPathWithinBoundary(t *testing.T) {
	// pathWithin is purely lexical (Abs/Rel, no filesystem lookups), but
	// filepath.Rel compares path elements with the platform's sameWord:
	// strings.EqualFold on Windows, byte equality elsewhere (including macOS,
	// whose filesystem is case-insensitive but whose Rel is not). So a
	// case-only sibling is inside only on Windows.
	dir := filepath.Join(t.TempDir(), "profiles")
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "dir itself", path: dir, want: true},
		{name: "nested child", path: filepath.Join(dir, "a", "b"), want: true},
		{name: "dot-dot named child", path: filepath.Join(dir, "..hidden"), want: true},
		{name: "parent", path: filepath.Dir(dir), want: false},
		{name: "shared-prefix sibling", path: dir + "-other", want: false},
		{name: "case-only sibling", path: filepath.Join(filepath.Dir(dir), "Profiles", "x"), want: runtime.GOOS == "windows"},
		{name: "traversal out", path: dir + string(os.PathSeparator) + filepath.Join("..", "..", "etc"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pathWithin(tt.path, dir)
			if err != nil {
				t.Fatalf("pathWithin: %v", err)
			}
			if got != tt.want {
				t.Fatalf("pathWithin(%q, %q) = %t, want %t", tt.path, dir, got, tt.want)
			}
		})
	}
}

// Relative inputs are resolved against the working directory, the way a
// relative integrity key path from config is. Not parallel: it changes cwd.
func TestPathWithinRelativeInputs(t *testing.T) {
	t.Chdir(t.TempDir())
	tests := []struct {
		name string
		path string
		dir  string
		want bool
	}{
		{name: "relative child inside", path: filepath.Join("profiles", "keys", "k"), dir: "profiles", want: true},
		{name: "relative dir itself", path: "profiles", dir: "profiles", want: true},
		{name: "relative path outside", path: filepath.Join("keys", "k"), dir: "profiles", want: false},
		{name: "relative path against absolute dir", path: filepath.Join("profiles", "k"), dir: filepath.Join(mustGetwd(t), "profiles"), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pathWithin(tt.path, tt.dir)
			if err != nil {
				t.Fatalf("pathWithin(%q, %q) error: %v", tt.path, tt.dir, err)
			}
			if got != tt.want {
				t.Fatalf("pathWithin(%q, %q) = %t, want %t", tt.path, tt.dir, got, tt.want)
			}
		})
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func TestSanitizeLogAttrValueKinds(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want any
	}{
		{name: "plain value untouched", in: 42, want: 42},
		{name: "string newline flattened", in: "a\nforged", want: "a forged"},
		{name: "error text flattened", in: errors.New("a\rforged"), want: "a forged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeLogAttrValue(tt.in); got != tt.want {
				t.Fatalf("sanitizeLogAttrValue(%#v) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
	got, ok := sanitizeLogAttrValue(slog.String("k", "a\nforged")).(slog.Attr)
	if !ok || got.Value.String() != "a forged" {
		t.Fatalf("nested attr sanitized to %#v, want value %q", got, "a forged")
	}
}
