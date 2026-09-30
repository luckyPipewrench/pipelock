// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretEgressCLIWireProfile(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../sdk/conformance/testdata/secret-egress-v1/valid-intent-block.json")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := decodeEvidenceReceipt(raw)
	if err != nil {
		t.Fatalf("baseline receipt: %v", err)
	}
	if err := baseline.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, old, replacement string }{
		{"missing_sequence", `"chain_seq":0,`, ``},
		{"null_sequence", `"chain_seq":0`, `"chain_seq":null`},
		{"decimal_sequence", `"chain_seq":0`, `"chain_seq":0.0`},
		{"aliased_sequence", `"chain_seq":`, `"CHAIN_SEQ":`},
		{"aliased_kind", `"payload_kind":`, `"PAYLOAD_KIND":`},
		{"optional_null", `"payload_kind":`, `"contract_generation":null,"payload_kind":`},
		{"optional_boolean", `"payload_kind":`, `"delegation_chain":false,"payload_kind":`},
		{"offset_timestamp", `T12:00:00Z`, `T12:00:00+00:00`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !bytes.Contains(raw, []byte(c.old)) {
				t.Fatalf("missing fixture marker %q", c.old)
			}
			invalid := bytes.Replace(raw, []byte(c.old), []byte(c.replacement), 1)
			if _, err := decodeEvidenceReceipt(invalid); err == nil {
				t.Fatal("CLI decoder accepted non-profile wire JSON")
			}
			path := filepath.Join(t.TempDir(), "receipt.json")
			if err := os.WriteFile(path, invalid, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if err := runReceipt(&stdout, &stderr, path, receiptOptions{signerKey: baseline.Signature.SignerKeyID, jsonOutput: true}); err == nil {
				t.Fatal("receipt CLI accepted non-profile JSON")
			}
			var report receiptReport
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Valid {
				t.Fatal("CLI reported invalid profile valid")
			}
		})
	}
}
