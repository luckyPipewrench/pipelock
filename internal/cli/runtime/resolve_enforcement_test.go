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
		filepath.Join(repoRoot, "internal", "cli"),
	}

	for _, dir := range checkedDirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			if strings.HasPrefix(rel, filepath.Join("internal", "cli", "runtimeconfig")+string(filepath.Separator)) {
				return nil
			}

			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			for _, pos := range resolveRuntimeSelectorPositions(fset, file) {
				t.Errorf("%s calls ResolveRuntime directly; use runtimeconfig.ResolveAndReportConfig", pos)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}

func TestResolveRuntimeSelectorDetectorCatchesMethodValueBypass(t *testing.T) {
	src := `package runtime

func direct(cfg interface{ ResolveRuntime(any) (any, any) }, opts any) {
	_, _ = cfg.ResolveRuntime(opts)
}

func methodValue(cfg interface{ ResolveRuntime(any) (any, any) }, opts any) {
	resolve := cfg.ResolveRuntime
	_, _ = resolve(opts)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "bypass.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	positions := resolveRuntimeSelectorPositions(fset, file)
	if len(positions) != 2 {
		t.Fatalf("selector detector found %d ResolveRuntime selectors, want 2", len(positions))
	}
}

func resolveRuntimeSelectorPositions(fset *token.FileSet, file *ast.File) []token.Position {
	var positions []token.Position
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ResolveRuntime" {
			return true
		}
		positions = append(positions, fset.Position(sel.Sel.Pos()))
		return true
	})
	return positions
}
