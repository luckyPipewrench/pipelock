// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const provenanceTransformDirective = "pipelock:provenance-transform "

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
	for function, operations := range directives {
		if references[function] < 2 {
			t.Errorf("production transform %s is declared but has no scanner call site", function)
		}
		for _, operation := range operations {
			if !supported[operation] {
				t.Errorf("production transform %s requires missing typed operation %q", function, operation)
			}
		}
	}
}

func productionTransformDirectives(t *testing.T) (map[string][]string, map[string]int) {
	t.Helper()
	files := []string{}
	for _, directory := range []string{".", "../normalize"} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			files = append(files, filepath.Join(directory, entry.Name()))
		}
	}
	slices.Sort(files)
	set := token.NewFileSet()
	directives := make(map[string][]string)
	references := make(map[string]int)
	for _, path := range files {
		parsed, err := parser.ParseFile(set, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok {
				references[identifier.Name]++
			}
			return true
		})
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Doc == nil {
				continue
			}
			for _, comment := range function.Doc.List {
				text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
				if !strings.HasPrefix(text, provenanceTransformDirective) {
					continue
				}
				operation := strings.TrimSpace(strings.TrimPrefix(text, provenanceTransformDirective))
				if operation == "" || strings.ContainsAny(operation, " \t") {
					t.Fatalf("%s has malformed provenance transform directive %q", function.Name.Name, comment.Text)
				}
				directives[function.Name.Name] = append(directives[function.Name.Name], operation)
			}
		}
	}
	if len(directives) == 0 {
		t.Fatal("no production provenance transform directives found")
	}
	return directives, references
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
		var values []string
		for _, pair := range strings.Split(rawQuery, "&") {
			_, value, _ := strings.Cut(pair, "=")
			if value != "" {
				values = append(values, IterativeDecode(value))
			}
		}
		if len(values) > 20 {
			values = values[:20]
		}
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
		{"encoded run", "prefix:QUJDRA== suffix", normalize.Operation{Kind: normalize.OperationEncodedRun, Occurrence: 1, MinimumLength: 6}, func(*testing.T) string { return extractEncodedRuns("prefix:QUJDRA== suffix", 6)[1] }},
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
