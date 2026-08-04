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
	cases := []struct {
		name string
		src  string
	}{
		{
			// Exercises the FuncLit skip in reachesPayloadKind: the constant is
			// referenced DIRECTLY inside an uncalled closure.
			name: "direct reference inside closure",
			src: `package sample

import contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"

func Producer() {
	_ = func() { _ = contractreceipt.PayloadKeyRotation }
}
`,
		},
		{
			// Exercises the FuncLit skip in calledProductionFunctions: the
			// closure does not name the constant at all, it CALLS a helper that
			// does. Without that second guard the helper is collected as a
			// called function and the delegated reference counts.
			name: "delegated call inside closure",
			src: `package sample

import contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"

func helper() { _ = contractreceipt.PayloadKeyRotation }

func Producer() {
	_ = func() { helper() }
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "sample.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			pkg := receiptMaturityModulePath + "/sample"
			imports := importPaths(file)
			functions := make(map[string]*productionFunction)
			for _, d := range file.Decls {
				decl, ok := d.(*ast.FuncDecl)
				if !ok || decl.Body == nil {
					continue
				}
				name := productionFunctionName(decl)
				functions[functionKey(pkg, name)] = &productionFunction{
					packagePath: pkg, name: name, decl: decl, imports: imports,
				}
			}
			producer := functions[functionKey(pkg, "Producer")]
			if producer == nil {
				t.Fatal("Producer not found in fixture")
			}
			if reachesPayloadKind(producer, PayloadKeyRotation, functions, map[string]bool{}) {
				t.Fatal("a reference reached only through an uncalled closure was treated as a production path")
			}
		})
	}
}
