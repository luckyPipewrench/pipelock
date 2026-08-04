// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestReachability_ClosureHandling pins how the producer-reachability walk
// treats function literals, in BOTH directions.
//
// An UNCALLED closure is not a production path. Without the function-literal
// guards, a producer could be declared live on the strength of dead code such
// as `var _ = func() { _ = PayloadKeyRotation }`, which is the false-positive
// this whole check exists to prevent.
//
// An IMMEDIATELY INVOKED closure (`func(){ ... }()`) IS a real static call.
// Pruning it would make a genuinely live producer read as dark, which is the
// same defect in the opposite direction and would be worse: it turns the check
// into a source of false alarms that operators learn to ignore.
//
// Non-vacuity, per case:
//   - uncalled cases: delete the corresponding `invoked[lit]` guard (in
//     reachesPayloadKind for the direct case, in calledProductionFunctions for
//     the delegated case) so the walk descends unconditionally.
//   - invoked cases: make either guard `return false` unconditionally.
//
// Each neutralization must fail its own cases and only its own.
func TestReachability_ClosureHandling(t *testing.T) {
	t.Parallel()
	receiptPkg := receiptMaturityModulePath + "/internal/contract/receipt"
	cases := []struct {
		name          string
		body          string
		extraDecls    string
		wantReachable bool
	}{
		{
			// reachesPayloadKind: constant referenced DIRECTLY inside an
			// uncalled closure.
			name:          "uncalled closure, direct reference",
			body:          "\t_ = func() { _ = contractreceipt.PayloadKeyRotation }\n",
			wantReachable: false,
		},
		{
			// calledProductionFunctions: the closure never names the constant,
			// it CALLS a helper that does.
			name:          "uncalled closure, delegated call",
			extraDecls:    "func helper() { _ = contractreceipt.PayloadKeyRotation }\n",
			body:          "\t_ = func() { helper() }\n",
			wantReachable: false,
		},
		{
			// An IIFE is a real static call, so the direct reference inside it
			// must be found.
			name:          "invoked closure, direct reference",
			body:          "\tfunc() { _ = contractreceipt.PayloadKeyRotation }()\n",
			wantReachable: true,
		},
		{
			// Same, one level of delegation deeper.
			name:          "invoked closure, delegated call",
			extraDecls:    "func helper() { _ = contractreceipt.PayloadKeyRotation }\n",
			body:          "\tfunc() { helper() }()\n",
			wantReachable: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := fmt.Sprintf("package sample\n\nimport contractreceipt %q\n\n%sfunc Producer() {\n%s}\n",
				receiptPkg, tc.extraDecls, tc.body)
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "sample.go", src, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v\n%s", err, src)
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
			got := reachesPayloadKind(producer, PayloadKeyRotation, functions, map[string]bool{})
			if got != tc.wantReachable {
				t.Fatalf("reachesPayloadKind = %v, want %v\nfixture:\n%s", got, tc.wantReachable, src)
			}
		})
	}
}
