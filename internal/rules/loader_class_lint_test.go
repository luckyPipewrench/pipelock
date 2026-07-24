// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bundleErrorClassViolations returns one message per BundleError composite
// literal in src that does not explicitly set a non-empty Class. It is the core
// of the construction-time lint below, factored out so the lint itself can be
// tested against synthetic sources.
//
// A literal violates the invariant when it is positional (no keyed Class) or
// when it sets Class to an explicit empty string literal (""). A Class set via
// a constant, variable, or classifier call is accepted — only a statically
// empty class is rejected, since ClassOrDefault fails closed on anything else.
func bundleErrorClassViolations(t *testing.T, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}

	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		ident, ok := lit.Type.(*ast.Ident)
		if !ok || ident.Name != "BundleError" {
			return true
		}
		hasClass := false
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				violations = append(violations, "positional BundleError literal (use a keyed literal with an explicit Class)")
				hasClass = true
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Class" {
				hasClass = true
				if v, ok := kv.Value.(*ast.BasicLit); ok && v.Kind == token.STRING && v.Value == `""` {
					violations = append(violations, "BundleError sets an empty Class")
				}
			}
		}
		if !hasClass {
			violations = append(violations, "BundleError does not set Class explicitly")
		}
		return true
	})
	return violations
}

// TestBundleErrorConstructorsSetClass is a construction-time lint: every
// BundleError composite literal in loader.go must set Class to a non-empty
// value. ClassOrDefault fails CLOSED (integrity) for an unclassified or
// unrecognized error, but that default is a fail-safe backstop — a real loader
// path must always classify its failure so an availability-only condition (a
// missing optional store, a permission blip) is not misreported as an integrity
// failure that refuses strict startup. This catches a future constructor that
// forgets Class, or sets it empty, before it ships a regression.
func TestBundleErrorConstructorsSetClass(t *testing.T) {
	data, err := os.ReadFile("loader.go")
	if err != nil {
		t.Fatalf("read loader.go: %v", err)
	}
	src := string(data)
	if v := bundleErrorClassViolations(t, src); len(v) > 0 {
		t.Errorf("loader.go has unclassified BundleError literals: %s", strings.Join(v, "; "))
	}
	// Guard against the file moving or changing form to a shape the lint no
	// longer recognizes.
	if !strings.Contains(src, "BundleError{") {
		t.Fatal("found no BundleError composite literals in loader.go; did the file move or change form?")
	}
}

// TestBundleErrorClassLintDetectsViolations proves the lint is non-vacuous: it
// flags positional literals and explicit empty classes, and accepts a keyed
// non-empty class (constant or classifier call).
func TestBundleErrorClassLintDetectsViolations(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantNum int
	}{
		{
			name:    "explicit empty class",
			src:     "package p\nvar _ = BundleError{Name: \"x\", Class: \"\"}\n",
			wantNum: 1,
		},
		{
			name:    "missing class key",
			src:     "package p\nvar _ = BundleError{Name: \"x\", Reason: \"y\"}\n",
			wantNum: 1,
		},
		{
			name:    "positional literal",
			src:     "package p\nvar _ = BundleError{\"x\"}\n",
			wantNum: 1,
		},
		{
			name:    "keyed constant class is accepted",
			src:     "package p\nvar _ = BundleError{Name: \"x\", Class: BundleErrorClassIntegrity}\n",
			wantNum: 0,
		},
		{
			name:    "classifier call is accepted",
			src:     "package p\nvar _ = BundleError{Name: \"x\", Class: classifyBundleFileReadError(err)}\n",
			wantNum: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bundleErrorClassViolations(t, tc.src); len(got) != tc.wantNum {
				t.Fatalf("violations = %v (%d), want %d", got, len(got), tc.wantNum)
			}
		})
	}
}
