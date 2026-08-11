// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import "testing"

func TestExecutionProofBindsEffectiveInvocation(t *testing.T) {
	record := EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull}
	proof := NewExecutionProof(record, "config-hash", "worker", "/workspace", "/tmp/private", "/usr/bin/tool", []string{"tool", "arg"})
	if err := proof.Verify("config-hash"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := proof.Verify("other-config"); err == nil {
		t.Fatal("proof with the wrong config binding was accepted")
	}
	failed := NewExecutionProof(record, "config-hash", "worker", "/workspace", "/tmp/private", "/usr/bin/tool", []string{"tool"})
	failed.ExecError = "exec failed"
	if err := failed.Verify("config-hash"); err == nil {
		t.Fatal("proof carrying an exec failure was accepted")
	}
	proof.TempDir = "/tmp/other"
	if err := proof.Verify("config-hash"); err == nil {
		t.Fatal("tampered effective invocation was accepted")
	}
}
