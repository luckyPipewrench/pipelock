// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import (
	"slices"
	"testing"
)

func TestExecutionProofBindsEffectiveInvocation(t *testing.T) {
	newValidProof := func() ExecutionProof {
		return NewExecutionProof(
			EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull},
			ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool"},
			[]string{"tool", "arg"},
		)
	}
	t.Run("valid proof", func(t *testing.T) {
		if err := newValidProof().VerifyInvocation(ExecControlOptions{
			Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool",
		}, []string{"tool", "arg"}); err != nil {
			t.Fatalf("VerifyInvocation: %v", err)
		}
	})
	for _, testCase := range []struct {
		name     string
		expected ExecControlOptions
		command  []string
	}{
		{name: "wrong requested profile", expected: ExecControlOptions{Profile: "other", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool"}, command: []string{"tool", "arg"}},
		{name: "wrong requested workspace", expected: ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/other", TempDir: "/tmp/private", Binary: "/usr/bin/tool"}, command: []string{"tool", "arg"}},
		{name: "wrong requested temporary directory", expected: ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/other", Binary: "/usr/bin/tool"}, command: []string{"tool", "arg"}},
		{name: "wrong requested binary", expected: ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/other"}, command: []string{"tool", "arg"}},
		{name: "wrong requested argv", expected: ExecControlOptions{Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool"}, command: []string{"tool", "other"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := newValidProof().VerifyInvocation(testCase.expected, testCase.command); err == nil {
				t.Fatal("proof for a different requested invocation was accepted")
			}
		})
	}
	t.Run("wrong config binding", func(t *testing.T) {
		if err := newValidProof().VerifyInvocation(ExecControlOptions{
			Profile: "worker", PolicyHash: "other-config", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool",
		}, []string{"tool", "arg"}); err == nil {
			t.Fatal("proof with the wrong config binding was accepted")
		}
	})
	t.Run("tampered record through invocation verifier", func(t *testing.T) {
		proof := newValidProof()
		proof.Record.Coverage = CoveragePartial
		if err := proof.VerifyInvocation(ExecControlOptions{
			Profile: "worker", PolicyHash: "config-hash", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/tool",
		}, []string{"tool", "arg"}); err == nil {
			t.Fatal("invocation verifier accepted a tampered enforcement record")
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

	// These are the remaining child-to-parent bindings. Each mutation keeps the
	// original digest, so a mixed or malformed helper record must fail closed
	// instead of being mistaken for proof about another invocation.
	for _, testCase := range []struct {
		name   string
		mutate func(*ExecutionProof)
	}{
		{name: "enforcement record", mutate: func(proof *ExecutionProof) { proof.Record.Coverage = CoveragePartial }},
		{name: "config hash", mutate: func(proof *ExecutionProof) { proof.ConfigPolicyHash = "other-config" }},
		{name: "profile", mutate: func(proof *ExecutionProof) { proof.Profile = "other-profile" }},
		{name: "workspace", mutate: func(proof *ExecutionProof) { proof.Workspace = "/other-workspace" }},
		{name: "binary", mutate: func(proof *ExecutionProof) { proof.Binary = "/usr/bin/other" }},
	} {
		t.Run("tampered "+testCase.name, func(t *testing.T) {
			proof := newValidProof()
			before := slices.Clone(proof.Command)
			testCase.mutate(&proof)
			if err := proof.Verify("config-hash"); err == nil {
				t.Fatalf("proof with tampered %s was accepted", testCase.name)
			}
			if !slices.Equal(proof.Command, before) {
				t.Fatal("proof verification mutated the command binding")
			}
		})
	}
}
