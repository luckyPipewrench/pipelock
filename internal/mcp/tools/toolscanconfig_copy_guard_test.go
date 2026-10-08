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
	// Every production package under internal/ is walked, nested ones
	// included, so a new transport copy anywhere is caught.
	dirs := []string{"../.."}
	// Lets the guard be pointed at another checkout to prove it fires.
	if override := os.Getenv("PIPELOCK_TOOLSCANCONFIG_GUARD_DIRS"); override != "" {
		dirs = strings.Split(override, string(os.PathListSeparator))
	}
	checked := 0
	var files []string
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range files {
		{
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
				typeName := ""
				switch typ := lit.Type.(type) {
				case *ast.SelectorExpr:
					typeName = typ.Sel.Name
				case *ast.Ident:
					typeName = typ.Name
				}
				keys := map[string]bool{}
				for _, elt := range lit.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok {
							keys[id.Name] = true
						}
					}
				}
				exempt := func() bool {
					line := fset.Position(lit.Pos()).Line
					for i := line - 2; i >= 0 && i >= line-4; i-- {
						if strings.Contains(lines[i], "ack-exempt:") {
							return true
						}
					}
					return false
				}
				// Proxy options that name a server must carry its transport
				// binding too, or every acknowledgment for that server
				// silently fails as a binding mismatch.
				if typeName == "MCPProxyOpts" && keys["ServerName"] && !keys["ServerBinding"] && !exempt() {
					t.Errorf("%s:%d sets MCPProxyOpts.ServerName without ServerBinding", path, fset.Position(lit.Pos()).Line)
				}
				if typeName != "ToolScanConfig" {
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
