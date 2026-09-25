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
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor":
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
