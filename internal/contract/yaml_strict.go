// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"errors"
	"fmt"

	goyaml "github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

var (
	// ErrYAMLDuplicateKey is returned when a YAML mapping contains duplicate keys.
	ErrYAMLDuplicateKey = errors.New("yaml: duplicate key")
	// ErrYAMLAliasOrAnchor is returned when a YAML document uses anchors or aliases.
	// Signed artifacts must be fully self-contained; anchors/aliases introduce
	// indirection that can alter semantics after signature verification.
	ErrYAMLAliasOrAnchor = errors.New("yaml: anchors and aliases forbidden in signed artifacts")
	// ErrYAMLMergeKey is returned when a YAML document uses merge keys (<<:).
	// Merge keys expand at parse time and can replace keys silently.
	ErrYAMLMergeKey = errors.New("yaml: merge keys forbidden in signed artifacts")
	// ErrYAMLCustomTag is returned when a YAML document uses custom type tags.
	// Custom tags alter type coercion and can bypass schema validation.
	ErrYAMLCustomTag = errors.New("yaml: custom tags forbidden in signed artifacts")
	// ErrYAMLMultiDoc is returned when the input contains more than one YAML document.
	// Signed artifacts must be a single document to have a single canonical form.
	ErrYAMLMultiDoc = errors.New("yaml: multi-document streams forbidden in signed artifacts")
)

// allowedTags are the implicit YAML core schema tags that carry no type
// coercion risk. Every other tag (e.g. !!int, !!float, !!binary) is rejected.
var allowedTags = map[string]bool{
	"!!str": true,
	"!!seq": true,
	"!!map": true,
}

// ParseYAMLStrict parses a YAML document with the strictness required for
// signed artifacts: rejects duplicate keys, anchors, aliases, merge keys,
// custom tags, and multi-document streams.
//
// Returns a map[string]any / []any tree compatible with Canonicalize.
func ParseYAMLStrict(data []byte) (any, error) {
	// Pre-flight: byte-level scan for merge keys. This runs before the AST walk
	// so that a document with both an anchor definition and a merge key reports
	// ErrYAMLMergeKey rather than ErrYAMLAliasOrAnchor (deterministic priority).
	if bytes.Contains(data, []byte("<<:")) {
		return nil, ErrYAMLMergeKey
	}

	// ParseBytes with ParseComments so we get the full AST including anchors
	// and aliases. AllowDuplicateMapKey lets the parser build the full AST even
	// when duplicate keys are present; we detect them ourselves in the AST walk
	// so we can return our own sentinel error via errors.Is.
	file, err := parser.ParseBytes(data, parser.ParseComments, parser.AllowDuplicateMapKey())
	if err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}

	if len(file.Docs) == 0 {
		return nil, fmt.Errorf("yaml: empty document")
	}
	if len(file.Docs) > 1 {
		return nil, ErrYAMLMultiDoc
	}

	if err := walkRejectBannedNodes(file.Docs[0].Body); err != nil {
		return nil, err
	}

	// Unmarshal into any using goccy. This resolves the parsed AST into a
	// map[string]any / []any tree. We rely on AST-level detection above for
	// all forbidden constructs; Unmarshal here is purely for value extraction.
	var v any
	if err := goyaml.UnmarshalWithOptions(data, &v); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	return v, nil
}

// walkRejectBannedNodes walks the AST and returns the first sentinel error for
// any forbidden construct: anchors, aliases, merge keys, custom tags, or
// duplicate mapping keys.
func walkRejectBannedNodes(node ast.Node) error {
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *ast.AnchorNode:
		return ErrYAMLAliasOrAnchor

	case *ast.AliasNode:
		return ErrYAMLAliasOrAnchor

	case *ast.MergeKeyNode:
		return ErrYAMLMergeKey

	case *ast.TagNode:
		tag := n.Start.Value
		if !allowedTags[tag] {
			return ErrYAMLCustomTag
		}
		// Tag value wraps the actual node; keep walking into it.
		return walkRejectBannedNodes(n.Value)

	case *ast.MappingValueNode:
		// Check the key first — merge keys surface here.
		if n.Key != nil && n.Key.IsMergeKey() {
			return ErrYAMLMergeKey
		}
		if err := walkRejectBannedNodes(n.Key); err != nil {
			return err
		}
		return walkRejectBannedNodes(n.Value)

	case *ast.MappingNode:
		seen := make(map[string]bool, len(n.Values))
		for _, mv := range n.Values {
			if mv.Key != nil && mv.Key.IsMergeKey() {
				return ErrYAMLMergeKey
			}
			if mv.Key != nil {
				keyStr := mv.Key.GetToken().Value
				if seen[keyStr] {
					return ErrYAMLDuplicateKey
				}
				seen[keyStr] = true
			}
			if err := walkRejectBannedNodes(mv.Key); err != nil {
				return err
			}
			if err := walkRejectBannedNodes(mv.Value); err != nil {
				return err
			}
		}

	case *ast.SequenceNode:
		for _, item := range n.Values {
			if err := walkRejectBannedNodes(item); err != nil {
				return err
			}
		}

	case *ast.DocumentNode:
		return walkRejectBannedNodes(n.Body)
	}

	return nil
}
