// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestReachability_IgnoresUncalledClosures guards the closure hole: a reference
// to a payload constant inside a function literal that is never invoked is not
// a production path, and must not satisfy the live-producer check.
//
// Without the *ast.FuncLit skip in reachesPayloadKind, a producer could be
// declared live on the strength of dead code such as
// `var _ = func() { _ = PayloadKeyRotation }`.
//
// Non-vacuity: delete the `if _, ok := node.(*ast.FuncLit); ok { return false }`
// guard in reachesPayloadKind. This test must then FAIL.
func TestReachability_IgnoresUncalledClosures(t *testing.T) {
	t.Parallel()
	const src = `package sample

import contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"

func Producer() {
	_ = func() { _ = contractreceipt.PayloadKeyRotation }
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	var decl *ast.FuncDecl
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "Producer" {
			decl = fn
		}
	}
	if decl == nil {
		t.Fatal("Producer not found in fixture")
	}
	fn := &productionFunction{
		packagePath: receiptMaturityModulePath + "/sample",
		name:        "Producer",
		decl:        decl,
		imports:     importPaths(file),
	}
	functions := map[string]*productionFunction{functionKey(fn.packagePath, fn.name): fn}
	if reachesPayloadKind(fn, PayloadKeyRotation, functions, map[string]bool{}) {
		t.Fatal("a reference inside an uncalled closure was treated as a production path")
	}
}
