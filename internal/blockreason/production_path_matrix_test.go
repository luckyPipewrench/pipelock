// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package blockreason_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
)

// blockreasonImportPath is the canonical import path the matrix anchors on.
// Matching by import path (not by selector identifier name) means the gate
// stays correct under aliased imports and ignores unrelated locals named
// `blockreason`.
const blockreasonImportPath = "github.com/luckyPipewrench/pipelock/internal/blockreason"

// TestProductionPathMatrix walks the in-tree Go source for every canonical
// blockreason.Reason and asserts each one is referenced from at least one
// production .go file outside the blockreason package itself. This is a
// static-analysis gate against two regression classes:
//
//  1. A new Reason constant lands but no production block path emits it
//     (block_reason_header.md spec drift versus shipped behavior).
//  2. A production emitter is removed but the constant lives on, leaving
//     dead vocabulary in the public header schema.
//
// The matrix is intentionally static - exercising every block path through
// runtime traffic would require a transport-by-transport black-box rig that
// belongs in the pen-test layer, not the unit suite. This test catches the
// "constant exists but no live caller" class cheaply on every commit.
//
// Exemptions live in nonProductionEmitReasons below; each one carries a
// comment explaining why the lack of a production caller is intentional.
func TestProductionPathMatrix(t *testing.T) {
	t.Parallel()

	repoRoot, err := repoRootFromHere()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	references, err := collectBlockReasonReferences(repoRoot)
	if err != nil {
		t.Fatalf("walk source tree: %v", err)
	}

	for _, reason := range blockreason.AllReasons() {
		if _, exempt := nonProductionEmitReasons[reason]; exempt {
			continue
		}
		emitters, ok := references[constNameForReason(reason)]
		if !ok || len(emitters) == 0 {
			t.Errorf("Reason %q (%s) has no production emit site — either wire a caller or document an exemption in nonProductionEmitReasons",
				constNameForReason(reason), string(reason))
			continue
		}
		t.Logf("Reason %q referenced by: %s", string(reason), strings.Join(emitters, ", "))
	}
}

// nonProductionEmitReasons documents Reasons that intentionally have no
// runtime production emitter today. Each exemption MUST carry a justification
// comment so a future reader knows whether the gap is by design or stale.
var nonProductionEmitReasons = map[blockreason.Reason]string{
	// BlockReasonOverflow is the dedicated sentinel CloseFramePayload uses
	// when an Info has accumulated a Reason value too long to fit RFC 6455's
	// 123-byte close-frame payload limit. It is never EMITTED by a block
	// path; it is RESOLVED to inside CloseFramePayload as a fallback. No
	// production caller is expected.
	blockreason.BlockReasonOverflow: "sentinel resolved inside CloseFramePayload, not emitted by a block path",

	// ToolPoisoning fires from internal/mcp/proxy.go via blockResponseReason
	// on tools/list responses where a poisoned tool description was
	// detected. The block surfaces as a JSON-RPC error in the MCP response
	// stream, not as an HTTP response - there is no HTTP header surface to
	// carry X-Pipelock-Block-Reason on the MCP transport. The vocabulary
	// stays in the canonical allowlist for cross-system labeling
	// (audit logs, receipts, dashboards) even though the HTTP header path
	// does not apply.
	blockreason.ToolPoisoning: "fires at JSON-RPC layer in MCP response stream; no HTTP header surface",

	// ToolChainBlocked fires from internal/mcp/proxy_http.go and
	// internal/mcp/input.go when a chain matcher rejects a tools/call
	// sequence. Same shape as ToolPoisoning: the block becomes a JSON-RPC
	// error in the MCP response stream, with no HTTP response to attach a
	// header to. Reason vocabulary kept for receipt + audit consistency.
	blockreason.ToolChainBlocked: "fires at JSON-RPC layer in MCP response stream; no HTTP header surface",

	// ContractObservedOnly is an info-tier annotation that the runtime
	// evaluator surfaces in shadow / capture modes when the contract path
	// would have produced a non-allow live verdict but the configured mode
	// did not enforce. The annotation is for audit and drift telemetry
	// (Decision.Reason + receipt.live_verdict); it never appears on a 4xx
	// HTTP response surface. Reason vocabulary stays in the canonical
	// allowlist so receipts and dashboards can label observation events
	// alongside real blocks without forking into observed-vs-blocking.
	blockreason.ContractObservedOnly: "shadow/capture mode annotation; never emitted on a block path",

	// SSRFDNSRebind is part of the SSRF reason set on the wire, but the
	// scanner pipeline currently emits SSRFPrivateIP / SSRFMetadata from
	// the DNS rebinding TOCTOU path because the rebind detection lives
	// upstream of the blockheaders helper that maps to the typed Reason.
	// Vocabulary stays in the canonical allowlist so receipts and the
	// public spec doc can name DNS rebinding distinctly from generic
	// private-IP SSRF; the wire emit site lands when the SSRF block path
	// is refactored to surface the more specific reason.
	blockreason.SSRFDNSRebind: "vocabulary placeholder; SSRF block path collapses TOCTOU rebinds onto SSRFPrivateIP today",

	// Timeout is reserved for fail-closed timeouts on scanner / HITL
	// surfaces. Today the timeout paths return ParseError or do not
	// surface a header at all (HITL has no HTTP response surface). The
	// reason stays in the canonical allowlist so the spec doc can
	// describe it once a transport wires the dedicated emit site.
	blockreason.Timeout: "vocabulary placeholder; timeout block paths today return ParseError or have no HTTP surface",

	// ToolPolicyDeny and SessionBinding are MCP-layer reasons. The MCP
	// proxy emits its block as a JSON-RPC error in the response stream,
	// not as an HTTP response - same shape as ToolPoisoning and
	// ToolChainBlocked. Reason vocabulary kept for receipt + audit
	// consistency once the MCP receipt stream wires these specific
	// labels.
	blockreason.ToolPolicyDeny: "fires at JSON-RPC layer in MCP response stream; no HTTP header surface",
	blockreason.SessionBinding: "fires at JSON-RPC layer in MCP response stream; no HTTP header surface",
}

// constNameForReason maps a Reason value to the exported constant name in the
// blockreason package, since references in production code use the constant
// (e.g. blockreason.DLPMatch) not the underlying string ("dlp_match").
func constNameForReason(r blockreason.Reason) string {
	switch r {
	case blockreason.SchemeBlocked:
		return "SchemeBlocked"
	case blockreason.DomainBlocklist:
		return "DomainBlocklist"
	case blockreason.SSRFPrivateIP:
		return "SSRFPrivateIP"
	case blockreason.SSRFMetadata:
		return "SSRFMetadata"
	case blockreason.SSRFDNSRebind:
		return "SSRFDNSRebind"
	case blockreason.PathEntropy:
		return "PathEntropy"
	case blockreason.SubdomainEntropy:
		return "SubdomainEntropy"
	case blockreason.URLLength:
		return "URLLength"
	case blockreason.RateLimit:
		return "RateLimit"
	case blockreason.DataBudget:
		return "DataBudget"
	case blockreason.ResponseSize:
		return "ResponseSize"
	case blockreason.DLPMatch:
		return "DLPMatch"
	case blockreason.PromptInjection:
		return "PromptInjection"
	case blockreason.RedactionFailure:
		return "RedactionFailure"
	case blockreason.MediaPolicy:
		return "MediaPolicy"
	case blockreason.ToolPolicyDeny:
		return "ToolPolicyDeny"
	case blockreason.ToolChainBlocked:
		return "ToolChainBlocked"
	case blockreason.ToolPoisoning:
		return "ToolPoisoning"
	case blockreason.SessionBinding:
		return "SessionBinding"
	case blockreason.AirlockActive:
		return "AirlockActive"
	case blockreason.KillSwitchActive:
		return "KillSwitchActive"
	case blockreason.EnvelopeVerifyFailed:
		return "EnvelopeVerifyFailed"
	case blockreason.OutboundEnvelopeFailed:
		return "OutboundEnvelopeFailed"
	case blockreason.RedirectScanDenied:
		return "RedirectScanDenied"
	case blockreason.AuthorityMismatch:
		return "AuthorityMismatch"
	case blockreason.EscalationLevel:
		return "EscalationLevel"
	case blockreason.SessionAnomaly:
		return "SessionAnomaly"
	case blockreason.CrossRequestDeny:
		return "CrossRequestDeny"
	case blockreason.CompressedResponse:
		return "CompressedResponse"
	case blockreason.BrowserShieldOversize:
		return "BrowserShieldOversize"
	case blockreason.ParseError:
		return "ParseError"
	case blockreason.Timeout:
		return "Timeout"
	case blockreason.PatternUnavailable:
		return "PatternUnavailable"
	case blockreason.NotEnabled:
		return "NotEnabled"
	case blockreason.BadRequest:
		return "BadRequest"
	case blockreason.BlockReasonOverflow:
		return "BlockReasonOverflow"
	case blockreason.ContractDefaultDeny:
		return "ContractDefaultDeny"
	case blockreason.ContractEnforceDefault:
		return "ContractEnforceDefault"
	case blockreason.ContractNonDefaultPort:
		return "ContractNonDefaultPort"
	case blockreason.ContractInvalidPath:
		return "ContractInvalidPath"
	case blockreason.ContractObservedOnly:
		return "ContractObservedOnly"
	case blockreason.RequestPolicyDeny:
		return "RequestPolicyDeny"
	}
	return ""
}

// collectBlockReasonReferences walks the source tree under root and returns a
// map of `<ConstantName> -> [files where blockreason.<ConstantName> appears]`,
// considering only production .go files (skips _test.go, the blockreason
// package itself, and vendor/build artifacts). AST-based so a `// blockreason.X`
// comment does not count as a reference.
func collectBlockReasonReferences(root string) (map[string][]string, error) {
	hits := make(map[string][]string)
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Skip the blockreason package itself; the constants are defined
		// there and self-reference would mask missing production callers.
		if strings.Contains(filepath.ToSlash(path), "/internal/blockreason/") {
			return nil
		}

		f, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			// Tolerate parse errors (e.g. test fixtures that include
			// intentionally invalid Go) so the matrix never bricks the
			// suite on unrelated breakage. The fmt-imported file would
			// just be skipped.
			return nil
		}
		// Build the per-file alias set keyed on the import PATH, not the
		// identifier name. This is the bug class CodeRabbit flagged: a
		// looser `pkg.Name == "blockreason"` selector match would (a)
		// count unrelated selectors on a local identifier shadowing the
		// package name, and (b) miss valid references when the import is
		// aliased. Dot/blank imports do not carry a usable selector
		// identifier, so they are excluded from the alias set.
		aliases := map[string]struct{}{}
		for _, imp := range f.Imports {
			p, unquoteErr := strconv.Unquote(imp.Path.Value)
			if unquoteErr != nil || p != blockreasonImportPath {
				continue
			}
			alias := "blockreason"
			if imp.Name != nil {
				if imp.Name.Name == "." || imp.Name.Name == "_" {
					continue
				}
				alias = imp.Name.Name
			}
			aliases[alias] = struct{}{}
		}
		if len(aliases) == 0 {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, ok := aliases[pkg.Name]; !ok {
				return true
			}
			rel, _ := filepath.Rel(root, path)
			hits[sel.Sel.Name] = append(hits[sel.Sel.Name], rel)
			return true
		})
		return nil
	})
	return hits, err
}

// repoRootFromHere walks up from the test file's directory until it finds a
// go.mod, returning the repository root. Lets the matrix run from any package
// without hard-coding the repo path.
func repoRootFromHere() (string, error) {
	cwd, err := filepath.Abs(".")
	if err != nil {
		return "", err
	}
	for dir := cwd; ; {
		if _, statErr := filepath.Glob(filepath.Join(dir, "go.mod")); statErr == nil {
			matches, _ := filepath.Glob(filepath.Join(dir, "go.mod"))
			if len(matches) > 0 {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fs.ErrNotExist
		}
		dir = parent
	}
}
