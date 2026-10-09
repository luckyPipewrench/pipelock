// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"runtime"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/digestorigin"
)

// TestActiveSetHoldsComputedDigestOrigins proves the active set keeps the
// origin of the manifest and contract hashes it stamps for its own lifetime,
// rather than relying on a process-wide record that a long run can outgrow.
// A chosen hash with the same shape gains nothing.
func TestActiveSetHoldsComputedDigestOrigins(t *testing.T) {
	contractHash, err := store.ContractHash(contract.Contract{SchemaVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := store.ActiveManifestHash(contract.ActiveManifest{Generation: 7})
	if err != nil {
		t.Fatal(err)
	}
	state := store.State{
		Envelope: contract.ActiveManifestEnvelope{Body: contract.ActiveManifest{
			Generation: 7,
			Selectors: []contract.ManifestSelector{
				{SelectorID: testExact, Agent: "build-agent", ContractHash: contractHash},
				{SelectorID: testDefault, Default: true, ContractHash: testContractHash},
			},
		}},
		ManifestHash: manifestHash,
		Contracts: map[string]contract.ContractEnvelope{
			testExact:   {Body: contract.Contract{ContractHash: contractHash}},
			testDefault: {Body: contract.Contract{ContractHash: testContractHash}},
		},
	}
	active, err := NewActiveSet(state)
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]bool{}
	for _, d := range active.origins {
		if d.Held() {
			held["sha256:"+d.String()] = true
		}
	}
	if len(held) != 2 || !held[contractHash] || !held[manifestHash] {
		t.Fatalf("active set holds %v, want the computed contract and manifest hashes", held)
	}
	if held[testContractHash] || digestorigin.Computed(testContractHash[len("sha256:"):]) {
		t.Fatal("a chosen contract hash acquired origin")
	}
	runtime.KeepAlive(active)
}
