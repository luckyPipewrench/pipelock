// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const provenanceTransformDirective = "pipelock:provenance-transform "

type transformSymbol struct {
	packagePath string
	name        string
	receiver    string
}

// TestScannerTransformProfileCompleteness derives the required operation set
// from directives attached to production transform declarations. A directive
// names both the live function and the recipe operation that replays it; the
// gate rejects stale declarations, unused declarations, and operations absent
// from the typed vocabulary.
func TestScannerTransformProfileCompleteness(t *testing.T) {
	t.Parallel()
	directives, references := productionTransformDirectives(t)
	supported := make(map[string]bool)
	for _, kind := range normalize.SupportedOperationKinds() {
		supported[string(kind)] = true
	}
	claimed := make(map[string]bool)
	for function, operations := range directives {
		if references[function] == 0 {
			t.Errorf("production transform %s.%s is declared but has no scanner call site", function.packagePath, function.name)
		}
		for _, operation := range operations {
			claimed[operation] = true
			if !supported[operation] {
				t.Errorf("production transform %s.%s requires missing typed operation %q", function.packagePath, function.name, operation)
			}
		}
	}

	// The forward check above only proves that whatever a directive CLAIMS is a
	// real operation. On its own it is satisfied by deleting the directive, so
	// a production transform could quietly lose its typed operation and the
	// gate would stay green while the profile silently stopped describing the
	// scanner. That is the exact recurrence this gate exists to prevent, so the
	// reverse direction has to be asserted too: every scanner-backed operation
	// must be claimed by some live transform declaration.
	//
	// Vocabulary-only operations are excluded deliberately. They are building
	// blocks the profile offers rather than transforms the scanner performs, so
	// requiring a production claim for them would force a fake directive.
	vocabularyOnly := map[string]bool{
		"identity":       true,
		"url_component":  true,
		"percent_decode": true,
		"hex_decode":     true,
		"base32_decode":  true,
		"base64_decode":  true,
		"lowercase":      true,
	}
	for _, kind := range normalize.SupportedOperationKinds() {
		operation := string(kind)
		if vocabularyOnly[operation] || claimed[operation] {
			continue
		}
		t.Errorf("typed operation %q is not claimed by any production transform directive; either a directive was deleted or the operation describes nothing the scanner does", operation)
	}
}

func productionTransformDirectives(t *testing.T) (map[transformSymbol][]string, map[transformSymbol]int) {
	t.Helper()
	directories := []struct {
		path        string
		packagePath string
	}{
		{".", "github.com/luckyPipewrench/pipelock/internal/scanner"},
		{"../normalize", "github.com/luckyPipewrench/pipelock/internal/normalize"},
	}
	directives := make(map[transformSymbol][]string)
	references := make(map[transformSymbol]int)
	for _, directory := range directories {
		files := []string{}
		entries, err := os.ReadDir(directory.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			files = append(files, filepath.Join(directory.path, entry.Name()))
		}
		slices.Sort(files)
		set := token.NewFileSet()
		parsedFiles := make([]*ast.File, 0, len(files))
		for _, path := range files {
			parsed, err := parser.ParseFile(set, path, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			parsedFiles = append(parsedFiles, parsed)
		}
		info := &types.Info{
			Defs: make(map[*ast.Ident]types.Object),
			Uses: make(map[*ast.Ident]types.Object),
		}
		config := types.Config{Importer: importer.ForCompiler(set, "source", nil)}
		if _, err := config.Check(directory.packagePath, set, parsedFiles, info); err != nil {
			t.Fatalf("type-check %s: %v", directory.packagePath, err)
		}
		for _, parsed := range parsedFiles {
			countResolvedTransformReferences(parsed, info, references)
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Doc == nil {
					continue
				}
				object, ok := info.Defs[function.Name].(*types.Func)
				if !ok || object.Pkg() == nil {
					t.Fatalf("resolve declaration %s", function.Name.Name)
				}
				symbol := resolvedTransformSymbol(object)
				for _, comment := range function.Doc.List {
					text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
					if !strings.HasPrefix(text, provenanceTransformDirective) {
						continue
					}
					operation := strings.TrimSpace(strings.TrimPrefix(text, provenanceTransformDirective))
					if operation == "" || strings.ContainsAny(operation, " \t") {
						t.Fatalf("%s has malformed provenance transform directive %q", function.Name.Name, comment.Text)
					}
					directives[symbol] = append(directives[symbol], operation)
				}
			}
		}
	}
	if len(directives) == 0 {
		t.Fatal("no production provenance transform directives found")
	}
	return directives, references
}

func countResolvedTransformReferences(file *ast.File, info *types.Info, references map[transformSymbol]int) {
	ast.Inspect(file, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		function, ok := info.Uses[identifier].(*types.Func)
		if !ok || function.Pkg() == nil {
			return true
		}
		references[resolvedTransformSymbol(function)]++
		return true
	})
}

func resolvedTransformSymbol(function *types.Func) transformSymbol {
	receiver := ""
	if signature, ok := function.Type().(*types.Signature); ok && signature.Recv() != nil {
		receiver = types.TypeString(signature.Recv().Type(), func(pkg *types.Package) string { return pkg.Path() })
	}
	return transformSymbol{packagePath: function.Pkg().Path(), name: function.Name(), receiver: receiver}
}

func encodedRunAt(runs []string, index int) (string, bool) {
	if index >= len(runs) {
		return "", false
	}
	return runs[index], true
}

func TestEncodedRunAtRejectsMissingOccurrence(t *testing.T) {
	if _, ok := encodedRunAt([]string{"only"}, 1); ok {
		t.Fatal("missing encoded run occurrence unexpectedly succeeded")
	}
}

func TestResolvedTransformReferencesUseSymbols(t *testing.T) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "fixture.go", `package fixture
func transform() {}
type record struct { transform int }
type worker struct{}
func (worker) transform() {}
func use(value record, work worker) { _ = value.transform; work.transform(); transform() }
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Uses: make(map[*ast.Ident]types.Object)}
	if _, err := (&types.Config{}).Check("fixture", set, []*ast.File{file}, info); err != nil {
		t.Fatal(err)
	}
	references := make(map[transformSymbol]int)
	countResolvedTransformReferences(file, info, references)
	if got := references[transformSymbol{packagePath: "fixture", name: "transform"}]; got != 1 {
		t.Fatalf("resolved transform references = %d, want 1 real call and no same-named field", got)
	}
}

func TestTransformProfileReplaysProductionScannerTransforms(t *testing.T) {
	t.Parallel()
	findDecoded := func(t *testing.T, input, encoding, want string) string {
		t.Helper()
		for _, result := range decodeEncodings(input) {
			if result.encoding == encoding && result.text == want {
				return result.text
			}
		}
		t.Fatalf("production decoder did not produce %q from %q as %s", want, input, encoding)
		return ""
	}
	productionSegment := func(t *testing.T, input string, occurrence int) string {
		t.Helper()
		segments := strings.FieldsFunc(input, isTextDLPEncodingDelimiter)
		if occurrence >= len(segments) {
			t.Fatalf("production segment %d unavailable in %q", occurrence, input)
		}
		return segments[occurrence]
	}
	productionSubsequence := func(t *testing.T, rawQuery string, indices []uint8) string {
		t.Helper()
		values := querySubsequenceValues(rawQuery)
		var result strings.Builder
		for _, index := range indices {
			if int(index) >= len(values) {
				t.Fatalf("production query value %d unavailable", index)
			}
			result.WriteString(values[index])
		}
		return result.String()
	}

	for _, test := range []struct {
		name       string
		input      string
		operation  normalize.Operation
		production func(*testing.T) string
	}{
		{"query unescape plus and depth", "a+b%2525252521", normalize.Operation{Kind: normalize.OperationQueryUnescape}, func(*testing.T) string { return IterativeDecode("a+b%2525252521") }},
		{"invisible to space", "alpha\u200bbeta", normalize.Operation{Kind: normalize.OperationInvisibleSpace}, func(*testing.T) string { return normalize.ReplaceInvisibleWithSpace("alpha\u200bbeta") }},
		{"matching normalize", "Ａ\u200bB\u00a0C", normalize.Operation{Kind: normalize.OperationMatchingNormalize, Profile: "pipelock-matching-v1"}, func(*testing.T) string { return normalize.ForMatching("Ａ\u200bB\u00a0C") }},
		{"liberal uppercase hex", "4A", normalize.Operation{Kind: normalize.OperationHexDecodeLiberal}, func(t *testing.T) string { return findDecoded(t, "4A", encodingHex, "J") }},
		{"liberal noncanonical base32", "MZ======", normalize.Operation{Kind: normalize.OperationBase32DecodeLiberal, DecodePadding: true}, func(t *testing.T) string { return findDecoded(t, "MZ======", encodingBase32, "f") }},
		{"liberal URL base64", "4KC-", normalize.Operation{Kind: normalize.OperationBase64DecodeLiberal, Alphabet: "url", DecodePadding: false}, func(t *testing.T) string {
			return findDecoded(t, "4KC-", encodingBase64, "࠾")
		}},
		{"hex token normalization", `\x48 \x69`, normalize.Operation{Kind: normalize.OperationEncodedTokenNormalize, Alphabet: "hex"}, func(*testing.T) string { return normalizeHex(`\x48 \x69`) }},
		{"base64 token normalization", "S G.k=", normalize.Operation{Kind: normalize.OperationEncodedTokenNormalize, Alphabet: "base64_standard"}, func(*testing.T) string { return normalizeEncodedToken("S G.k=", encodedTokenBase64Std) }},
		{"base32 token normalization", "J B/UQ====", normalize.Operation{Kind: normalize.OperationEncodedTokenNormalize, Alphabet: "base32"}, func(*testing.T) string { return normalizeEncodedToken("J B/UQ====", encodedTokenBase32) }},
		{"text segment", "pre https://host/path,tail", normalize.Operation{Kind: normalize.OperationTextSegment, Occurrence: 3}, func(t *testing.T) string { return productionSegment(t, "pre https://host/path,tail", 3) }},
		{"HTML entities", "&amp;amp;", normalize.Operation{Kind: normalize.OperationHTMLEntityDecode}, func(*testing.T) string { return decodeHTMLEntities("&amp;amp;") }},
		{"Unicode whitespace", "a\u2003 b\n", normalize.Operation{Kind: normalize.OperationWhitespaceCompact}, func(*testing.T) string { return compactTextDLPWhitespace("a\u2003 b\n") }},
		{"URL noise", "a./ +,;|\tb", normalize.Operation{Kind: normalize.OperationURLNoiseStrip}, func(*testing.T) string { return stripURLNoise("a./ +,;|\tb") }},
		{"ordered query", "a=x%2521&empty=&b=y+z", normalize.Operation{Kind: normalize.OperationOrderedQueryConcat}, func(*testing.T) string { return orderedQueryConcat("a=x%2521&empty=&b=y+z") }},
		{"query subsequence", "a=one&b=junk&c=two&d=three", normalize.Operation{Kind: normalize.OperationQuerySubsequence, Indices: []uint8{0, 2, 3}}, func(t *testing.T) string {
			return productionSubsequence(t, "a=one&b=junk&c=two&d=three", []uint8{0, 2, 3})
		}},
		{"dot removal", "api.vendor.example", normalize.Operation{Kind: normalize.OperationHostnameDotRemove}, func(*testing.T) string { return removeHostnameDots("api.vendor.example") }},
		{"encoded run", "prefix:QUJDRA== suffix", normalize.Operation{Kind: normalize.OperationEncodedRun, Occurrence: 1, MinimumLength: 6}, func(t *testing.T) string {
			runs := extractEncodedRuns("prefix:QUJDRA== suffix", 6)
			run, ok := encodedRunAt(runs, 1)
			if !ok {
				t.Fatalf("production extracted %d encoded runs, want at least 2", len(runs))
			}
			return run
		}},
		{"canary canonicalization", "Ab-c_d/e?f", normalize.Operation{Kind: normalize.OperationCanaryCanonicalize}, func(*testing.T) string { return canonicalizeCanaryText("Ab-c_d/e?f") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{test.operation}}
			got, err := recipe.Apply(test.input)
			if err != nil {
				t.Fatal(err)
			}
			want := test.production(t)
			if got != want {
				t.Fatalf("typed replay bytes = %x, production scanner bytes = %x", []byte(got), []byte(want))
			}
		})
	}
}
