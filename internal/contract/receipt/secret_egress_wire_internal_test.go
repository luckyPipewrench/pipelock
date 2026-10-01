// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

func TestSecretEgressWireSelectorDetection(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		raw  string
		want bool
	}{
		{`{"payload_kind":"secret_egress_decision_v1"}`, true},
		{`{"PAYLOAD_KIND":"secret_egress_decision_v1"}`, true},
		{`{"payload_Kind":"secret_egress_decision_v1"}`, true},
		{`{"crit":["secret_egress_decision_v1"]}`, true},
		{`{"CRIT":["canonicalization","secret_egress_decision_v1"]}`, true},
		{`{"payload_kind":"secret_egress_decision_v1","payload_kind":"proxy_decision"}`, true},
		{`{"payload_kind":"proxy_decision"}`, false},
		{`{"payload_kind":null}`, false},
		{`{"payload_kind":1}`, false},
		{`{"payload_kind":`, false},
		{`{null:1}`, false},
		{`null`, false},
		{`[]`, false},
		{``, false},
	} {
		t.Run(c.raw, func(t *testing.T) {
			if got := isSecretEgressWire([]byte(c.raw)); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

// This explicit ingress inventory complements the behavioral reader tests.
// Each authoritative byte-to-EvidenceReceipt entry point must call the shared
// receipt parser, which runs the raw new-kind profile before typed binding.
// Higher-level CLI chain/audit-packet/session helpers delegate to these roots.
func TestEvidenceReceiptSupportedIngressUsesWireParser(t *testing.T) {
	t.Parallel()
	root := receiptMaturityRepositoryRoot(t)
	for _, c := range []struct{ file, function string }{
		{"internal/contract/receipt/bytes_verify.go", "VerifyV2BytesWithKey"},
		{"internal/contract/receipt/chain.go", "AddRaw"},
		{"internal/contract/receipt/chain.go", "decodeEvidenceReceiptDetail"},
		{"cmd/pipelock-verifier/evidence.go", "decodeEvidenceReceipt"},
	} {
		t.Run(c.function, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, c.file), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != c.function {
					continue
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "ParseEvidenceReceipt" {
						found = true
					}
					if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "ParseEvidenceReceipt" {
						if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "contractreceipt" {
							found = true
						}
					}
					return true
				})
			}
			if !found {
				t.Fatal("supported receipt ingress no longer invokes ParseEvidenceReceipt")
			}
		})
	}
}
