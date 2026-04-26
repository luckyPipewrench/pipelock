// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
