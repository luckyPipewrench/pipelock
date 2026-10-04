// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

func addSecretEgressDestinationCases(t *testing.T, base receipt.EvidenceReceipt, priv ed25519.PrivateKey, add func(string, []byte, bool, string)) {
	t.Helper()
	directory := "../../internal/egressevidence/testdata/decision-v1"
	rawManifest, err := os.ReadFile(filepath.Clean(filepath.Join(directory, "manifest.json")))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Fixtures []struct {
			ID    string `json:"id"`
			File  string `json:"file"`
			Valid bool   `json:"valid"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range manifest.Fixtures {
		if fixture.Valid || !strings.HasPrefix(fixture.ID, "invalid-destination-") {
			continue
		}
		decision, err := os.ReadFile(filepath.Clean(filepath.Join(directory, fixture.File)))
		if err != nil {
			t.Fatal(err)
		}
		// Duplicate members have no unambiguous signing preimage. Keep the
		// known-good proof while requiring the raw parser to reject them.
		if strings.Contains(fixture.ID, "duplicate") {
			raw, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(base.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			raw = replaceSecretEgress(t, raw, string(payload["decision"]), string(decision))
			add(fixture.ID, raw, false, "Duplicate destination facts must reject before binding")
			continue
		}
		r := base
		payload := map[string]json.RawMessage{"decision": decision}
		payload["registry_hash"], err = json.Marshal(registryHashFromFixture(t, base))
		if err != nil {
			t.Fatal(err)
		}
		r.Payload, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		add(fixture.ID, signSecretEgressFixture(t, &r, priv), false, "Destination reference/redaction sum-type shape must reject")
	}
}
