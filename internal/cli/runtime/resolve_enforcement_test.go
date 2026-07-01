// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
)

func TestProductionCallersUseResolveAndReportConfig(t *testing.T) {
	_, thisFile, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../../.."))
	checkedDirs := []string{
		filepath.Join(repoRoot, "internal", "cli", "runtime"),
		filepath.Join(repoRoot, "internal", "cli", "hermes"),
	}

	for _, dir := range checkedDirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "ResolveRuntime" {
					return true
				}
				pos := fset.Position(sel.Sel.Pos())
				t.Errorf("%s calls ResolveRuntime directly; use runtimeconfig.ResolveAndReportConfig", pos)
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}
