// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	goyamlast "github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

func TestParseYAMLStrict_Rejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		fixture string
		wantErr error
	}{
		{"duplicate key", "duplicate_key.yaml", ErrYAMLDuplicateKey},
		{"anchor", "yaml_anchor.yaml", ErrYAMLAliasOrAnchor},
		{"alias", "yaml_alias.yaml", ErrYAMLAliasOrAnchor},
		{"merge key", "yaml_merge_key.yaml", ErrYAMLMergeKey},
		{"custom tag", "yaml_custom_tag.yaml", ErrYAMLCustomTag},
		{"long-form tag", "yaml_longform_tag.yaml", ErrYAMLCustomTag},
		{"multi-doc", "yaml_multi_doc.yaml", ErrYAMLMultiDoc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join("testdata", "invalid", tc.fixture)
			b, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			_, err = ParseYAMLStrict(b)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got err=%v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseYAMLStrict_AcceptsCleanYAML(t *testing.T) {
	t.Parallel()
	in := []byte("schema_version: 1\ncontract_kind: behavioral_contract\n")
	got, err := ParseYAMLStrict(in)
	if err != nil {
		t.Fatalf("ParseYAMLStrict: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", got)
	}
	if m["schema_version"] == nil {
		t.Error("missing schema_version")
	}
}

func TestParseYAMLStrict_RejectsAliasInSequence(t *testing.T) {
	t.Parallel()
	// An alias appearing as a sequence item exercises the SequenceNode →
	// walkRejectBannedNodes → AliasNode branch.
	in := []byte("items:\n  - &anchor_val foo\n  - *anchor_val\n")
	_, err := ParseYAMLStrict(in)
	if !errors.Is(err, ErrYAMLAliasOrAnchor) {
		t.Errorf("got %v, want ErrYAMLAliasOrAnchor", err)
	}
}

func TestParseYAMLStrict_RejectsAliasBeforeAnchor(t *testing.T) {
	t.Parallel()
	// Alias appears as the first mapping value, before any anchor is defined.
	// The walker hits the AliasNode case directly before reaching any AnchorNode.
	in := []byte("copy: *d\ndefaults: &d value\n")
	_, err := ParseYAMLStrict(in)
	if !errors.Is(err, ErrYAMLAliasOrAnchor) {
		t.Errorf("got %v, want ErrYAMLAliasOrAnchor", err)
	}
}

func TestParseYAMLStrict_EmptyDocument(t *testing.T) {
	t.Parallel()
	// An empty byte slice produces a single document with a nil body.
	// walkRejectBannedNodes(nil) returns nil, so ParseYAMLStrict succeeds
	// and returns nil (the empty YAML null value). Verify it doesn't panic.
	got, err := ParseYAMLStrict([]byte(""))
	if err != nil {
		t.Fatalf("expected success for empty document, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for empty YAML, got %v (%T)", got, got)
	}
}

func TestParseYAMLStrict_BadSyntax(t *testing.T) {
	t.Parallel()
	// A structurally invalid YAML document should trigger the parse-error path.
	_, err := ParseYAMLStrict([]byte("key: [unclosed"))
	if err == nil {
		t.Error("expected error for bad YAML syntax, got nil")
	}
}

func TestParseYAMLStrict_NestedMapWithAlias(t *testing.T) {
	t.Parallel()
	// Alias nested inside a mapping value, exercising MappingValueNode recursion.
	in := []byte("outer:\n  base: &base_anchor value\n  copy: *base_anchor\n")
	_, err := ParseYAMLStrict(in)
	if !errors.Is(err, ErrYAMLAliasOrAnchor) {
		t.Errorf("got %v, want ErrYAMLAliasOrAnchor", err)
	}
}

func TestParseYAMLStrict_RejectsAnchorAsMapKey(t *testing.T) {
	t.Parallel()
	// An anchor used as a mapping key exercises the walkRejectBannedNodes call on
	// mv.Key inside the MappingNode case, returning ErrYAMLAliasOrAnchor from
	// that branch rather than from the top-level AnchorNode case in a value position.
	in := []byte("&myanchor keyname: value\n")
	_, err := ParseYAMLStrict(in)
	if !errors.Is(err, ErrYAMLAliasOrAnchor) {
		t.Errorf("got %v, want ErrYAMLAliasOrAnchor", err)
	}
}

func TestParseYAMLStrict_AcceptsAllowedTag(t *testing.T) {
	t.Parallel()
	// A !!str tag is in allowedTags; the walker continues into its value
	// without error. This exercises the TagNode allowed-tag → walkRejectBannedNodes(n.Value) path.
	in := []byte("name: !!str hello\n")
	_, err := ParseYAMLStrict(in)
	if err != nil {
		t.Errorf("expected nil for allowed !!str tag, got %v", err)
	}
}

func TestWalkRejectBannedNodes_DocumentNode(t *testing.T) {
	t.Parallel()
	// Parse a clean document and extract the DocumentNode to exercise the
	// DocumentNode branch of walkRejectBannedNodes directly.
	file, err := parser.ParseBytes(
		[]byte("key: value\n"),
		parser.ParseComments, parser.AllowDuplicateMapKey(),
	)
	if err != nil {
		t.Fatalf("parser.ParseBytes: %v", err)
	}
	if len(file.Docs) == 0 {
		t.Fatal("no documents parsed")
	}
	// file.Docs[0] is a *ast.DocumentNode.
	if walkErr := walkRejectBannedNodes(file.Docs[0]); walkErr != nil {
		t.Errorf("expected nil for clean DocumentNode, got %v", walkErr)
	}
}

func TestWalkRejectBannedNodes_MappingValueNodeDirect(t *testing.T) {
	t.Parallel()
	// The MappingValueNode case in walkRejectBannedNodes is reached when the function
	// is called directly with a *ast.MappingValueNode. Extract one from a parsed AST
	// and call walkRejectBannedNodes on it directly.
	file, err := parser.ParseBytes(
		[]byte("alpha: clean_value\n"),
		parser.ParseComments, parser.AllowDuplicateMapKey(),
	)
	if err != nil {
		t.Fatalf("parser.ParseBytes: %v", err)
	}
	if len(file.Docs) == 0 {
		t.Fatal("no docs parsed")
	}

	// Reach into the MappingNode to extract a MappingValueNode.
	mn, ok := file.Docs[0].Body.(*goyamlast.MappingNode)
	if !ok {
		t.Fatalf("expected *ast.MappingNode body, got %T", file.Docs[0].Body)
	}
	if len(mn.Values) == 0 {
		t.Fatal("mapping has no values")
	}
	// Call walkRejectBannedNodes directly with a *ast.MappingValueNode.
	// A clean MappingValueNode with a non-merge key should return nil.
	if walkErr := walkRejectBannedNodes(mn.Values[0]); walkErr != nil {
		t.Errorf("expected nil for clean MappingValueNode, got %v", walkErr)
	}
}

func TestWalkRejectBannedNodes_MappingValueNodeWithBannedKey(t *testing.T) {
	t.Parallel()
	// Exercise the walkRejectBannedNodes(n.Key) error branch inside the
	// MappingValueNode case. We need a MappingValueNode whose key is a banned node
	// (AnchorNode). Extract it from the parsed AST and call the walker directly.
	file, err := parser.ParseBytes(
		[]byte("&anchorkey keyname: value\n"),
		parser.ParseComments, parser.AllowDuplicateMapKey(),
	)
	if err != nil {
		t.Fatalf("parser.ParseBytes: %v", err)
	}
	if len(file.Docs) == 0 {
		t.Fatal("no docs")
	}
	mn, ok := file.Docs[0].Body.(*goyamlast.MappingNode)
	if !ok {
		t.Fatalf("expected *ast.MappingNode, got %T", file.Docs[0].Body)
	}
	if len(mn.Values) == 0 {
		t.Fatal("no values")
	}
	// mn.Values[0] is a *ast.MappingValueNode with Key=*ast.AnchorNode.
	// Calling walkRejectBannedNodes on this MappingValueNode exercises the
	// n.Key.IsMergeKey() (false) path, then walkRejectBannedNodes(n.Key) which
	// returns ErrYAMLAliasOrAnchor, hitting the "return err" branch.
	walkErr := walkRejectBannedNodes(mn.Values[0])
	if !errors.Is(walkErr, ErrYAMLAliasOrAnchor) {
		t.Errorf("expected ErrYAMLAliasOrAnchor from MappingValueNode with AnchorNode key, got %v", walkErr)
	}
}

func TestWalkRejectBannedNodes_MappingNodeWithMergeKeyValue(t *testing.T) {
	t.Parallel()
	// Exercise the mv.Key.IsMergeKey() → ErrYAMLMergeKey branch inside the
	// MappingNode case. Parse a merge-key YAML bypassing the preflight byte scan,
	// then call walkRejectBannedNodes directly on the MappingNode body.
	file, err := parser.ParseBytes(
		[]byte("<<:\n  a: 1\n"),
		parser.ParseComments, parser.AllowDuplicateMapKey(),
	)
	if err != nil {
		t.Fatalf("parser.ParseBytes: %v", err)
	}
	if len(file.Docs) == 0 {
		t.Fatal("no docs")
	}
	// The body is a *ast.MappingNode containing a MappingValueNode with a MergeKeyNode key.
	// Calling walkRejectBannedNodes directly on the MappingNode exercises line 124.
	walkErr := walkRejectBannedNodes(file.Docs[0].Body)
	if !errors.Is(walkErr, ErrYAMLMergeKey) {
		t.Errorf("expected ErrYAMLMergeKey from MappingNode with merge key, got %v", walkErr)
	}
}

func TestWalkRejectBannedNodes_MergeKeyNodeDirect(t *testing.T) {
	t.Parallel()
	// The case *ast.MergeKeyNode branch is reachable when walkRejectBannedNodes is
	// called directly with a *ast.MergeKeyNode (e.g., from within the MappingNode loop
	// at walkRejectBannedNodes(mv.Key) after the IsMergeKey check path isn't taken).
	// Parse a merge-key YAML bypassing the preflight byte scan, extract the MergeKeyNode,
	// and pass it directly to walkRejectBannedNodes to exercise that case.
	file, err := parser.ParseBytes(
		[]byte("<<:\n  a: 1\n"),
		parser.ParseComments, parser.AllowDuplicateMapKey(),
	)
	if err != nil {
		t.Fatalf("parser.ParseBytes: %v", err)
	}
	if len(file.Docs) == 0 {
		t.Fatal("no docs parsed")
	}

	// Extract the MergeKeyNode from the mapping.
	mn, ok := file.Docs[0].Body.(*goyamlast.MappingNode)
	if !ok {
		t.Fatalf("expected *ast.MappingNode, got %T", file.Docs[0].Body)
	}
	if len(mn.Values) == 0 {
		t.Fatal("no values in mapping")
	}
	mergeKey, ok := mn.Values[0].Key.(*goyamlast.MergeKeyNode)
	if !ok {
		t.Fatalf("expected *ast.MergeKeyNode key, got %T", mn.Values[0].Key)
	}

	// Call walkRejectBannedNodes directly with the MergeKeyNode.
	walkErr := walkRejectBannedNodes(mergeKey)
	if !errors.Is(walkErr, ErrYAMLMergeKey) {
		t.Errorf("expected ErrYAMLMergeKey, got %v", walkErr)
	}
}

func TestWalkRejectBannedNodes_MappingValueNodeMergeKeyDirect(t *testing.T) {
	t.Parallel()
	// Exercise the case *ast.MappingValueNode branch when the key IsMergeKey().
	// We need a MappingValueNode whose Key is a MergeKeyNode.
	file, err := parser.ParseBytes(
		[]byte("<<:\n  a: 1\n"),
		parser.ParseComments, parser.AllowDuplicateMapKey(),
	)
	if err != nil {
		t.Fatalf("parser.ParseBytes: %v", err)
	}
	if len(file.Docs) == 0 {
		t.Fatal("no docs")
	}
	mn, ok := file.Docs[0].Body.(*goyamlast.MappingNode)
	if !ok {
		t.Fatalf("expected *ast.MappingNode, got %T", file.Docs[0].Body)
	}
	if len(mn.Values) == 0 {
		t.Fatal("no values")
	}
	// mn.Values[0] is a *ast.MappingValueNode with Key=*ast.MergeKeyNode.
	// Call walkRejectBannedNodes directly with the MappingValueNode to exercise
	// the n.Key.IsMergeKey() → ErrYAMLMergeKey path inside the MappingValueNode case.
	walkErr := walkRejectBannedNodes(mn.Values[0])
	if !errors.Is(walkErr, ErrYAMLMergeKey) {
		t.Errorf("expected ErrYAMLMergeKey, got %v", walkErr)
	}
}
