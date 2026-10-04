// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package display

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDisplayDoesNotFeedVerificationPaths(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	allowed := []string{
		filepath.Join("internal", "evidence", "display"),
		filepath.Join("internal", "report", "render.go"),
		filepath.Join("internal", "report", "render_test.go"),
		filepath.Join("internal", "cli", "explain.go"),
		filepath.Join("internal", "cli", "explain_test.go"),
		filepath.Join("internal", "cli", "signing", "receipt.go"),
		filepath.Join("internal", "cli", "signing", "receipt_test.go"),
	}
	paths, err := displaySourcePaths(root)
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !containsDisplaySymbol(data) {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatalf("rel %s: %v", path, err)
		}
		rel = filepath.Clean(rel)
		allowedPath := false
		for _, prefix := range allowed {
			if rel == prefix || strings.HasPrefix(rel, prefix+string(filepath.Separator)) {
				allowedPath = true
				break
			}
		}
		if allowedPath {
			continue
		}
		t.Errorf("display symbol in non-render path: %s", rel)
	}
}

func displaySourcePaths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Go package discovery ignores dot- and underscore-prefixed
			// directories. Runtime tests create and remove scratch trees here.
			if path != root && (strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_") || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		paths = append(paths, filepath.Clean(path))
		return nil
	})
	return paths, err
}

func TestDisplaySourcePathsExcludesScratchDirectories(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"internal/verify", ".runtime-conductor-apply-123/audit-queue", "_scratch", "vendor/example"} {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "source.go"), []byte("package verify\nimport _ \""+displayImportPath+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := displaySourcePaths(root)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "internal", "verify", "source.go")
	if len(paths) != 1 || paths[0] != want {
		t.Fatalf("source paths = %v, want only %s", paths, want)
	}
	data, err := os.ReadFile(filepath.Clean(want))
	if err != nil {
		t.Fatal(err)
	}
	if !containsDisplaySymbol(data) {
		t.Fatal("ordinary source directory must still expose forbidden display imports")
	}
}

// displayImportPath is how a file reaches this package's symbols. The guard
// reads the file's parsed import list, so an aliased or dot import is caught
// and the path appearing in a comment or string literal is not.
const displayImportPath = "github.com/luckyPipewrench/pipelock/internal/evidence/display"

func containsDisplaySymbol(data []byte) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "", data, parser.ImportsOnly)
	if err != nil {
		// A file the parser cannot read is reported rather than skipped.
		return true
	}
	for _, spec := range file.Imports {
		if path, err := strconv.Unquote(spec.Path.Value); err == nil && path == displayImportPath {
			return true
		}
	}
	return false
}
