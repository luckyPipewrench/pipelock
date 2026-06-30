// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMCPReceiptCallsitesStayV2Paired guards the maintenance invariant behind
// MCP receipt parity: production call sites that emit an authoritative v1 MCP
// receipt must also pass the v2 proxy_decision emitter into the same emission
// helper. Runtime tests cover representative stdio, HTTP listener, and A2A
// paths; this catches future v1-only receipt emit sites before they ship.
func TestMCPReceiptCallsitesStayV2Paired(t *testing.T) {
	t.Parallel()

	dir := mcpPackageDir(t)
	fset, files := parseMCPProductionFiles(t, dir)
	for _, file := range files {
		ast.Inspect(file.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if callName(node.Fun) == "EmitMCPDecision" {
					assertEmitMCPDecisionV2Paired(t, fset, node)
				}
			case *ast.CompositeLit:
				if typeName(node.Type) == "mcpToolReceiptOpts" {
					assertToolReceiptOptsV2Paired(t, fset, node)
				}
			}
			return true
		})
	}
}

func TestMCPV1ReceiptEmissionStaysFunnelled(t *testing.T) {
	t.Parallel()

	dir := mcpPackageDir(t)
	fset, files := parseMCPProductionFiles(t, dir)
	for _, file := range files {
		ast.Inspect(file.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Emit" {
				return true
			}
			if file.name != "pipeline_decision.go" {
				t.Fatalf("%s: MCP emitter calls must stay funnelled through EmitMCPDecision", fset.Position(call.Pos()))
			}
			return true
		})
	}
}

type mcpProductionFile struct {
	name string
	file *ast.File
}

func parseMCPProductionFiles(t *testing.T, dir string) (*token.FileSet, []mcpProductionFile) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []mcpProductionFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		files = append(files, mcpProductionFile{
			name: entry.Name(),
			file: file,
		})
	}
	return fset, files
}

func assertEmitMCPDecisionV2Paired(t *testing.T, fset *token.FileSet, call *ast.CallExpr) {
	t.Helper()
	if len(call.Args) < 2 {
		t.Fatalf("%s: EmitMCPDecision call has %d args, want at least 2", fset.Position(call.Pos()), len(call.Args))
	}
	if exprIsNil(call.Args[0]) {
		return
	}
	if exprIsNil(call.Args[1]) {
		t.Fatalf("%s: EmitMCPDecision emits v1 receipt without paired v2 emitter", fset.Position(call.Pos()))
	}
}

func assertToolReceiptOptsV2Paired(t *testing.T, fset *token.FileSet, lit *ast.CompositeLit) {
	t.Helper()

	hasV1Emitter := false
	hasV2Emitter := false
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Emitter":
			hasV1Emitter = !exprIsNil(kv.Value)
		case "V2Emitter":
			hasV2Emitter = !exprIsNil(kv.Value)
		}
	}
	if hasV1Emitter && !hasV2Emitter {
		t.Fatalf("%s: mcpToolReceiptOpts sets Emitter without paired V2Emitter", fset.Position(lit.Pos()))
	}
}

func mcpPackageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

func callName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	default:
		return ""
	}
}

func typeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.StarExpr:
		return typeName(e.X)
	default:
		return ""
	}
}

func exprIsNil(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}
