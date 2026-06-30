// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDocsDeclareSVIDVerifierOnlyScope(t *testing.T) {
	cases := []struct {
		path  string
		terms []string
	}{
		{
			path: "README.md",
			terms: []string{
				"AARP/SVID",
				"verifier-side",
				"do not consume SVID evidence in live allow/deny decisions",
			},
		},
		{
			path: "docs/guides/mediation-envelope.md",
			terms: []string{
				"not X.509-SVID proof-of-possession",
				"offline in the verifier",
				"do not consume an SVID certificate",
			},
		},
		{
			path: "docs/specs/aarp-v0.1-envelope.md",
			terms: []string{
				"Runtime scope",
				"verifier-side appraisal",
				"allow/deny decisions",
				"identity enforcement",
			},
		},
		{
			path: "docs/specs/receipt-prior-art-mapping.md",
			terms: []string{
				"after the fact",
				"the live proxy and MCP decision paths do not currently consume that SVID result",
				"set receipt identity",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			text := readScopeDoc(t, tc.path)
			for _, term := range tc.terms {
				if !strings.Contains(text, term) {
					t.Fatalf("missing scope term %q", term)
				}
			}
		})
	}
}

// TestSVIDStaysOutOfLiveDecisionPath is the load-bearing guardrail behind the
// "verifier-side only" scope statements asserted above. The prose check can
// only catch deletion of the disclaimer text; it cannot catch the dangerous
// drift where someone wires AARP/SVID into a live decision or receipt-actor
// path while leaving the docs untouched (which would silently make the docs
// false). This test fails on exactly that: any non-test file in a live
// proxy/MCP/receipt/scanner/mediation package importing the AARP or SVID
// packages. If that wiring is ever intentional, this test and the scope docs
// must change together.
func TestSVIDStaysOutOfLiveDecisionPath(t *testing.T) {
	// Relative to this package directory (internal/aarp). These are the live
	// allow/deny decision surfaces and the receipt-actor / mediation-envelope
	// packages - the exact paths the scope docs say do not consume SVID.
	liveDirs := []string{"../proxy", "../mcp", "../receipt", "../scanner", "../envelope"}
	forbidden := []string{
		"github.com/luckyPipewrench/pipelock/internal/svid",
		"github.com/luckyPipewrench/pipelock/internal/svidsidecar",
		"github.com/luckyPipewrench/pipelock/internal/aarp",
	}
	fset := token.NewFileSet()
	for _, dir := range liveDirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				switch d.Name() {
				case "testdata", "vendor":
					return fs.SkipDir
				default:
					return nil
				}
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}
			for _, imp := range f.Imports {
				imported := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range forbidden {
					if imported == bad || strings.HasPrefix(imported, bad+"/") {
						t.Errorf("%s imports %s: AARP/SVID must stay verifier-side. "+
							"Wiring it into a live decision/receipt path makes the documented "+
							"\"verifier-side only\" scope false - update the scope docs in the same change.",
							path, imported)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}

func readScopeDoc(t *testing.T, path string) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))

	var (
		body []byte
		err  error
	)
	switch path {
	case "README.md":
		body, err = os.ReadFile(filepath.Join(repoRoot, "README.md"))
	case "docs/guides/mediation-envelope.md":
		body, err = os.ReadFile(filepath.Join(repoRoot, "docs/guides/mediation-envelope.md"))
	case "docs/specs/aarp-v0.1-envelope.md":
		body, err = os.ReadFile(filepath.Join(repoRoot, "docs/specs/aarp-v0.1-envelope.md"))
	case "docs/specs/receipt-prior-art-mapping.md":
		body, err = os.ReadFile(filepath.Join(repoRoot, "docs/specs/receipt-prior-art-mapping.md"))
	default:
		t.Fatalf("unhandled scope doc %q", path)
	}
	if err != nil {
		t.Fatalf("read doc: %v", err)
	}
	return string(body)
}
