// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import "testing"

func TestExecutionProofBindsEffectiveInvocation(t *testing.T) {
	newValidProof := func() ExecutionProof {
		return NewExecutionProof(
			EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull},
			ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool"},
			[]string{"tool", "arg"},
		)
	}
	t.Run("valid proof", func(t *testing.T) {
		if err := newValidProof().Verify("config-hash"); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
	t.Run("wrong config binding", func(t *testing.T) {
		if err := newValidProof().Verify("other-config"); err == nil {
			t.Fatal("proof with the wrong config binding was accepted")
		}
	})
	t.Run("execution failure", func(t *testing.T) {
		proof := newValidProof()
		proof.ExecError = "exec failed"
		if err := proof.Verify("config-hash"); err == nil {
			t.Fatal("proof carrying an exec failure was accepted")
		}
	})
	t.Run("tampered temporary directory", func(t *testing.T) {
		proof := newValidProof()
		proof.TempDir = "/tmp/other"
		if err := proof.Verify("config-hash"); err == nil {
			t.Fatal("tampered effective invocation was accepted")
		}
	})
	t.Run("tampered command", func(t *testing.T) {
		proof := newValidProof()
		proof.Command = []string{"other"}
		if err := proof.Verify("config-hash"); err == nil {
			t.Fatal("tampered command was accepted")
		}
	})
	t.Run("missing effective hash", func(t *testing.T) {
		proof := newValidProof()
		proof.EffectivePolicyHash = ""
		if err := proof.Verify("config-hash"); err == nil {
			t.Fatal("proof without an effective policy hash was accepted")
		}
	})
}
