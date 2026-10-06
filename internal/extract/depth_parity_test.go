// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestJSONNestingBoundParity fails if an extractor declares its own JSON
// nesting bound instead of deriving it from MaxExtractDepth. Extractors that
// walk the same input must agree on depth: a subtree one admits and another
// refuses is either scanned by only some layers or rejected inconsistently.
func TestJSONNestingBoundParity(t *testing.T) {
	declarations := []struct {
		file, name string
	}{
		{"internal/extract/json.go", "maxExtractDepth"},
		{"internal/mcp/jsonrpc/jsonrpc.go", "maxExtractDepth"},
		{"internal/decide/extract.go", "maxExtractDepth"},
		{"internal/proxy/bodyscan.go", "extractJSONMaxDepth"},
		{"internal/mcp/policy/policy.go", "structuralMaxArgDepth"},
	}
	for _, decl := range declarations {
		t.Run(decl.file+"/"+decl.name, func(t *testing.T) {
			path := filepath.Join("..", "..", filepath.FromSlash(decl.file))
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", decl.file, err)
			}
			value := constValue(file, decl.name)
			if value == nil {
				t.Fatalf("%s no longer declares const %s; update this parity list", decl.file, decl.name)
			}
			if !refersToMaxExtractDepth(value) {
				t.Fatalf("%s: const %s must be MaxExtractDepth, not its own value", decl.file, decl.name)
			}
		})
	}
}

func constValue(file *ast.File, name string) ast.Expr {
	for _, d := range file.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name == name && i < len(vs.Values) {
					return vs.Values[i]
				}
			}
		}
	}
	return nil
}

func refersToMaxExtractDepth(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "MaxExtractDepth"
	case *ast.SelectorExpr:
		pkg, ok := e.X.(*ast.Ident)
		return ok && pkg.Name == "extract" && e.Sel.Name == "MaxExtractDepth"
	}
	return false
}
