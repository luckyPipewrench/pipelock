// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEvidenceProvenanceCommitmentKeyringPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte("mode: balanced\nevidence_provenance:\n  commitment_keyring_path: state/commitment-keyring.json\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := filepath.Join(dir, "state", "commitment-keyring.json")
	if cfg.EvidenceProvenance.CommitmentKeyringPath != want {
		t.Fatalf("CommitmentKeyringPath = %q, want %q", cfg.EvidenceProvenance.CommitmentKeyringPath, want)
	}
	if cfg.FlightRecorder.SigningKeyPath != "" {
		t.Fatalf("commitment path polluted receipt signing config: %q", cfg.FlightRecorder.SigningKeyPath)
	}
}

func TestEvidenceProvenancePathExcludedFromCanonicalPolicyHash(t *testing.T) {
	a := Defaults()
	b := Defaults()
	a.EvidenceProvenance.CommitmentKeyringPath = "/var/lib/pipelock/a.json"
	b.EvidenceProvenance.CommitmentKeyringPath = "/var/lib/pipelock/b.json"
	if a.CanonicalPolicyHash() != b.CanonicalPolicyHash() {
		t.Fatal("operator keyring path changed scanner policy hash")
	}
}

func TestEvidenceProvenanceConfiguredPathWarnsThatCapabilityIsInert(t *testing.T) {
	cfg := Defaults()
	cfg.EvidenceProvenance.CommitmentKeyringPath = "/var/lib/pipelock/evidence/commitment-keyring.json"
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	for _, warning := range warnings {
		if warning.Field == "evidence_provenance.commitment_keyring_path" && strings.Contains(warning.Message, "nothing is currently being committed") {
			return
		}
	}
	t.Fatalf("warnings = %+v, want inert-capability warning", warnings)
}
