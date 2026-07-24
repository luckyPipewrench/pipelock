// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestBundleErrorConstructorsSetClass is a construction-time lint: every
// BundleError composite literal in loader.go must set the Class field
// explicitly. ClassOrDefault fails CLOSED (integrity) for an unclassified
// error, but that default is only a fail-safe backstop — a real loader path
// must always classify its failure so an availability-only condition (a missing
// optional store, a permission blip) is not misreported as an integrity failure
// that refuses strict startup. This test catches a future constructor that
// forgets Class before it ships a fail-open (or over-strict) regression.
func TestBundleErrorConstructorsSetClass(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "loader.go", nil, 0)
	if err != nil {
		t.Fatalf("parse loader.go: %v", err)
	}

	var found int
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		ident, ok := lit.Type.(*ast.Ident)
		if !ok || ident.Name != "BundleError" {
			return true
		}
		found++
		hasClass := false
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				// A positional literal would set every field including Class;
				// treat it as satisfying the invariant but flag it, since keyed
				// literals are the project convention.
				t.Errorf("BundleError literal at %s is positional; use a keyed literal with an explicit Class", fset.Position(lit.Pos()))
				hasClass = true
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Class" {
				hasClass = true
			}
		}
		if !hasClass {
			t.Errorf("BundleError literal at %s does not set Class explicitly; every loader failure must classify itself (availability vs integrity)", fset.Position(lit.Pos()))
		}
		return true
	})

	if found == 0 {
		t.Fatal("found no BundleError composite literals in loader.go; did the file move or change form?")
	}
}
