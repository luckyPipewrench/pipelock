// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package eventcatalog

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestEveryDeclaredEventHasDescriptor(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "catalog.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	descriptors := make(map[string]Descriptor)
	for _, d := range Builtins() {
		if _, exists := descriptors[d.Name]; exists {
			t.Fatalf("duplicate descriptor %q", d.Name)
		}
		descriptors[d.Name] = d
	}
	declarations := 0
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || !strings.HasPrefix(spec.Names[0].Name, "Event") {
			return true
		}
		declarations++
		if len(spec.Values) != 1 {
			t.Fatalf("%s must declare exactly one literal name", spec.Names[0].Name)
		}
		literal, ok := spec.Values[0].(*ast.BasicLit)
		if !ok {
			t.Fatalf("%s must declare a literal name", spec.Names[0].Name)
		}
		name, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := descriptors[name]; !ok {
			t.Errorf("missing descriptor for %s (%q)", spec.Names[0].Name, name)
		}
		return true
	})
	if declarations == 0 || declarations != len(descriptors) {
		t.Fatalf("declarations=%d descriptors=%d", declarations, len(descriptors))
	}
}

func TestBuiltinsReturnsIndependentCopy(t *testing.T) {
	first := Builtins()
	original := first[0]
	first[0].Name = "mutated"
	if got := Builtins()[0]; got != original {
		t.Fatalf("shared mutable descriptor: %+v", got)
	}
}
