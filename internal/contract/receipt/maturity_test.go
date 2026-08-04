// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const receiptMaturityModulePath = "github.com/luckyPipewrench/pipelock"

type productionFunction struct {
	packagePath string
	name        string
	decl        *ast.FuncDecl
	imports     map[string]string
}

// TestPayloadMaturityDeclarationIsExhaustive makes registry changes and
// capability declarations move together. A registered kind without exactly
// one maturity state fails this test.
func TestPayloadMaturityDeclarationIsExhaustive(t *testing.T) {
	if len(payloadMaturity) != len(payloadValidators) {
		t.Fatalf("payload maturity declarations = %d, registered payload kinds = %d", len(payloadMaturity), len(payloadValidators))
	}
	for kind := range payloadValidators {
		entry, ok := payloadMaturity[kind]
		if !ok {
			t.Fatalf("registered payload kind %q has no maturity declaration", kind)
		}
		switch entry.maturity {
		case PayloadMaturityLive:
			if entry.producer == nil {
				t.Fatalf("live payload kind %q has no production producer reference", kind)
			}
		case PayloadMaturityFixtureOnly:
			if entry.producer != nil {
				t.Fatalf("non-live payload kind %q unexpectedly names producer %s.%s", kind, entry.producer.packagePath, entry.producer.function)
			}
			if err := payloadValidators[kind](json.RawMessage(`{}`)); errors.Is(err, ErrPayloadKindNotImplemented) {
				t.Fatalf("fixture-only payload kind %q routes to ErrPayloadKindNotImplemented", kind)
			}
		case PayloadMaturityReserved:
			if entry.producer != nil {
				t.Fatalf("non-live payload kind %q unexpectedly names producer %s.%s", kind, entry.producer.packagePath, entry.producer.function)
			}
			if err := payloadValidators[kind](json.RawMessage(`{}`)); !errors.Is(err, ErrPayloadKindNotImplemented) {
				t.Fatalf("reserved payload kind %q error = %v, want ErrPayloadKindNotImplemented", kind, err)
			}
		default:
			t.Fatalf("payload kind %q has unknown maturity %q", kind, entry.maturity)
		}
	}
	for kind := range payloadMaturity {
		if _, ok := payloadValidators[kind]; !ok {
			t.Fatalf("maturity declaration exists for unregistered payload kind %q", kind)
		}
	}
}

// TestLivePayloadKindsHaveProductionProducers parses every non-test Go file,
// resolves each declared live producer, and follows direct static calls until
// it reaches that kind's PayloadKind constant. It catches a false live claim
// without a declared non-test producer path; schemas, validators, and test
// fixtures alone cannot satisfy it.
//
// This source-level check cannot prove a runtime configuration enables a
// producer or see reflection and function-value calls; those are integration
// test concerns.
func TestLivePayloadKindsHaveProductionProducers(t *testing.T) {
	functions := loadProductionFunctions(t)
	for kind, entry := range payloadMaturity {
		if entry.maturity != PayloadMaturityLive {
			continue
		}
		if entry.producer == nil {
			t.Fatalf("live payload kind %q has no production producer reference", kind)
		}
		root := functions[functionKey(entry.producer.packagePath, entry.producer.function)]
		if root == nil {
			t.Fatalf("live payload kind %q producer %s.%s does not exist in non-test source", kind, entry.producer.packagePath, entry.producer.function)
		}
		if !reachesPayloadKind(root, kind, functions, map[string]bool{}) {
			t.Fatalf("live payload kind %q producer %s.%s does not reach contractreceipt.%s", kind, entry.producer.packagePath, entry.producer.function, payloadKindConstantName(kind))
		}
	}
}

func loadProductionFunctions(t *testing.T) map[string]*productionFunction {
	t.Helper()
	root := receiptMaturityRepositoryRoot(t)
	functions := make(map[string]*productionFunction)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		packagePath := receiptMaturityModulePath
		if rel != "." {
			packagePath += "/" + filepath.ToSlash(rel)
		}
		imports := importPaths(file)
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := productionFunctionName(fn)
			functions[functionKey(packagePath, name)] = &productionFunction{packagePath: packagePath, name: name, decl: fn, imports: imports}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("load non-test production functions: %v", err)
	}
	return functions
}

func receiptMaturityRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate maturity test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func importPaths(file *ast.File) map[string]string {
	imports := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, "\"")
		name := filepath.Base(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[name] = path
	}
	return imports
}

func productionFunctionName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return receiverName(fn.Recv.List[0].Type) + "." + fn.Name.Name
}

func receiverName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.StarExpr:
		return "(*" + receiverName(typed.X) + ")"
	case *ast.Ident:
		return typed.Name
	default:
		return "?"
	}
}

func functionKey(packagePath, name string) string {
	return packagePath + ":" + name
}

func reachesPayloadKind(fn *productionFunction, kind PayloadKind, functions map[string]*productionFunction, visited map[string]bool) bool {
	key := functionKey(fn.packagePath, fn.name)
	if visited[key] {
		return false
	}
	visited[key] = true
	want := payloadKindConstantName(kind)
	found := false
	ast.Inspect(fn.decl.Body, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != want {
			return true
		}
		ident, ok := selector.X.(*ast.Ident)
		if ok && fn.imports[ident.Name] == receiptMaturityModulePath+"/internal/contract/receipt" {
			found = true
			return false
		}
		return true
	})
	if found {
		return true
	}
	for _, called := range calledProductionFunctions(fn, functions) {
		if reachesPayloadKind(called, kind, functions, visited) {
			return true
		}
	}
	return false
}

func calledProductionFunctions(fn *productionFunction, functions map[string]*productionFunction) []*productionFunction {
	var called []*productionFunction
	ast.Inspect(fn.decl.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		key := ""
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			key = functionKey(fn.packagePath, callee.Name)
		case *ast.SelectorExpr:
			ident, ok := callee.X.(*ast.Ident)
			if ok && fn.imports[ident.Name] != "" {
				key = functionKey(fn.imports[ident.Name], callee.Sel.Name)
			}
		}
		if candidate := functions[key]; candidate != nil {
			called = append(called, candidate)
		}
		return true
	})
	return called
}

func payloadKindConstantName(kind PayloadKind) string {
	for name, candidate := range map[string]PayloadKind{
		"PayloadProxyDecision": PayloadProxyDecision, "PayloadProxyDecisionWithSpans": PayloadProxyDecisionWithSpans,
		"PayloadContractRatified": PayloadContractRatified, "PayloadContractPromoteIntent": PayloadContractPromoteIntent,
		"PayloadContractPromoteCommitted": PayloadContractPromoteCommitted, "PayloadContractRollbackAuthorized": PayloadContractRollbackAuthorized,
		"PayloadContractRollbackCommitted": PayloadContractRollbackCommitted, "PayloadContractDemoted": PayloadContractDemoted,
		"PayloadContractExpired": PayloadContractExpired, "PayloadContractDrift": PayloadContractDrift,
		"PayloadShadowDelta": PayloadShadowDelta, "PayloadOpportunityMissing": PayloadOpportunityMissing,
		"PayloadKeyRotation": PayloadKeyRotation, "PayloadContractRedactionRequest": PayloadContractRedactionRequest,
		"PayloadDeferOpened": PayloadDeferOpened, "PayloadDeferResolved": PayloadDeferResolved,
	} {
		if candidate == kind {
			return name
		}
	}
	return ""
}
