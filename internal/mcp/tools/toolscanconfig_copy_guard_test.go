// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestToolScanConfigLiteralsCarryAcknowledgments fails when production code
// builds a ToolScanConfig without passing CredentialAcks through. Several
// transports rebuild the configuration field by field; each new copy that
// forgot the acknowledgments made them silently never apply on that
// transport. A literal that deliberately has none must say why on the line
// above with an "ack-exempt:" comment.
func TestToolScanConfigLiteralsCarryAcknowledgments(t *testing.T) {
	dirs := []string{"..", "../../cli/runtime"}
	// Lets the guard be pointed at another checkout to prove it fires.
	if override := os.Getenv("PIPELOCK_TOOLSCANCONFIG_GUARD_DIRS"); override != "" {
		dirs = strings.Split(override, string(os.PathListSeparator))
	}
	checked := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			src, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(src), "\n")
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "ToolScanConfig" {
					return true
				}
				checked++
				for _, elt := range lit.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "CredentialAcks" {
							return true
						}
					}
				}
				line := fset.Position(lit.Pos()).Line
				for i := line - 2; i >= 0 && i >= line-4; i-- {
					if strings.Contains(lines[i], "ack-exempt:") {
						return true
					}
				}
				t.Errorf("%s:%d builds a ToolScanConfig without CredentialAcks; pass them through or mark it ack-exempt with a reason", path, line)
				return true
			})
		}
	}
	if checked < 7 {
		t.Fatalf("checked only %d ToolScanConfig literals; the guard no longer sees the transport copies", checked)
	}
}
