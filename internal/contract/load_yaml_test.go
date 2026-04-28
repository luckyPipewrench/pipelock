// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeStrictYAML_HappyPath(t *testing.T) {
	t.Parallel()
	raw := []byte("schema_version: 1\nroster_signed_by: root-key\nkeys: []\ndata_class_root: internal\n")
	var r KeyRoster
	if err := DecodeStrictYAML(raw, &r); err != nil {
		t.Fatalf("DecodeStrictYAML: %v", err)
	}
	if r.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", r.SchemaVersion)
	}
	if r.RosterSignedBy != "root-key" {
		t.Errorf("RosterSignedBy = %q, want %q", r.RosterSignedBy, "root-key")
	}
}

func TestDecodeStrictYAML_RejectsNilAndEmpty(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var r KeyRoster
			if err := DecodeStrictYAML(tc.raw, &r); !errors.Is(err, ErrEmptyPayload) {
				t.Errorf("got %v, want ErrEmptyPayload", err)
			}
		})
	}
}

func TestDecodeStrictYAML_RejectsNullTree(t *testing.T) {
	t.Parallel()
	// ParseYAMLStrict returns nil for empty YAML documents (just whitespace/comments).
	// DecodeStrictYAML treats a nil tree as ErrEmptyPayload.
	raw := []byte("# just a comment\n")
	var r KeyRoster
	if err := DecodeStrictYAML(raw, &r); !errors.Is(err, ErrEmptyPayload) {
		t.Errorf("got %v, want ErrEmptyPayload", err)
	}
}

func TestDecodeStrictYAML_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte("schema_version: 1\nroster_signed_by: root-key\nkeys: []\ndata_class_root: internal\nextra_field: sneaky\n")
	var r KeyRoster
	if err := DecodeStrictYAML(raw, &r); !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField", err)
	}
}

func TestDecodeStrictYAML_RejectsYAMLLayerViolations(t *testing.T) {
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
			var r KeyRoster
			if err := DecodeStrictYAML(b, &r); !errors.Is(err, tc.wantErr) {
				t.Errorf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadContractYAML_HappyPath(t *testing.T) {
	t.Parallel()
	raw := []byte(`schema_version: 1
contract_kind: behavioral_contract
contract_hash: ""
signer_key_id: ""
key_purpose: ""
data_class_root: internal
field_data_classes: {}
selector:
  selector_id: ""
observation_window:
  start: "0001-01-01T00:00:00Z"
  end: "0001-01-01T00:00:00Z"
  event_count: 0
  session_count: 0
  observation_window_root: ""
compile:
  pipelock_version: ""
  pipelock_build_sha: ""
  go_version: ""
  module_digest_root: ""
  compile_config_hash: ""
  inference_algorithm: ""
  normalization_algorithm: ""
defaults:
  fidelity: ""
  confidence: null
  privacy:
    default_data_class: ""
    salt_epoch: 0
    forbid_classes: null
rules: null
`)
	c, err := LoadContractYAML(raw)
	if err != nil {
		t.Fatalf("LoadContractYAML: %v", err)
	}
	if c.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", c.SchemaVersion)
	}
	if c.ContractKind != "behavioral_contract" {
		t.Errorf("ContractKind = %q, want %q", c.ContractKind, "behavioral_contract")
	}
}

func TestLoadContractYAML_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte("schema_version: 1\ncontract_kind: behavioral_contract\nfuture_field: sneaky\n")
	_, err := LoadContractYAML(raw)
	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}

func TestLoadKeyRosterYAML_HappyPath(t *testing.T) {
	t.Parallel()
	raw := []byte(`schema_version: 1
roster_signed_by: root-key
keys:
  - key_id: root-key
    key_purpose: roster-signing
    public_key_hex: deadbeef
    valid_from: "2026-01-01T00:00:00Z"
    status: root
data_class_root: internal
`)
	r, err := LoadKeyRosterYAML(raw)
	if err != nil {
		t.Fatalf("LoadKeyRosterYAML: %v", err)
	}
	if r.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", r.SchemaVersion)
	}
	if r.RosterSignedBy != "root-key" {
		t.Errorf("RosterSignedBy = %q, want %q", r.RosterSignedBy, "root-key")
	}
	if len(r.Keys) != 1 {
		t.Errorf("len(Keys) = %d, want 1", len(r.Keys))
	}
}

func TestLoadKeyRosterYAML_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte("schema_version: 1\nroster_signed_by: root-key\nkeys: []\ndata_class_root: internal\nextra: x\n")
	_, err := LoadKeyRosterYAML(raw)
	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}

func TestLoadTombstoneYAML_HappyPath(t *testing.T) {
	t.Parallel()
	raw := []byte(`schema_version: 1
tombstone: true
prior_contract_hash: abc123
redacted_at: "2026-04-26T00:00:00Z"
redaction_authorization_id: auth-1
signer_key_id: key-1
key_purpose: contract-activation-signing
data_class_root: internal
`)
	ts, err := LoadTombstoneYAML(raw)
	if err != nil {
		t.Fatalf("LoadTombstoneYAML: %v", err)
	}
	if ts.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", ts.SchemaVersion)
	}
	if !ts.Tombstone {
		t.Error("Tombstone = false, want true")
	}
	if ts.PriorContractHash != "abc123" {
		t.Errorf("PriorContractHash = %q, want %q", ts.PriorContractHash, "abc123")
	}
}

func TestLoadTombstoneYAML_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := []byte("schema_version: 1\ntombstone: true\nsurplus: yes\n")
	_, err := LoadTombstoneYAML(raw)
	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("got %v, want ErrUnknownField wrapped", err)
	}
}
