// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import "testing"

func TestKeyAliasesContract(t *testing.T) {
	for _, raw := range []string{`{"schema_version":2,"SCHEMA_VERSION":1}`, `{"SCHEMA_VERSION":1}`, `{"selector":{"selector_id":"one","SELECTOR_ID":"two"}}`} {
		if _, err := LoadContract([]byte(raw)); err == nil {
			t.Errorf("accepted alias: %s", raw)
		}
	}
	if _, err := LoadContract([]byte(`{"schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
}

func TestKeyAliasesArtifactLoads(t *testing.T) {
	for name, load := range map[string]func([]byte) error{
		"contract":              func(raw []byte) error { _, err := LoadContract(raw); return err },
		"active_manifest":       func(raw []byte) error { _, err := LoadActiveManifest(raw); return err },
		"compile_manifest":      func(raw []byte) error { _, err := LoadCompileManifest(raw); return err },
		"tombstone":             func(raw []byte) error { _, err := LoadTombstone(raw); return err },
		"key_roster":            func(raw []byte) error { _, err := LoadKeyRoster(raw); return err },
		"verification_metadata": func(raw []byte) error { _, err := LoadVerificationMetadata(raw); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := load([]byte(`{"schema_version":1}`)); err != nil {
				t.Fatalf("canonical control: %v", err)
			}
			for _, raw := range []string{`{"SCHEMA_VERSION":1}`, `{"schema_version":1,"Schema_Version":1}`} {
				if err := load([]byte(raw)); err == nil {
					t.Fatalf("accepted %s", raw)
				}
			}
		})
	}
}
