// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package display

import (
	"os"
	"path/filepath"
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

func containsDisplaySymbol(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.Contains(trimmed, "display.") {
			return true
		}
	}
	return false
}
