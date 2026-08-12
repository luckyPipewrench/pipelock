// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
)

// ExecutionProof binds the kernel result to the exact invocation whose helper
// entered the enforced domain before attempting exec. The close-on-exec status
// pipe can distinguish a returned exec error, but EOF cannot distinguish a
// successful exec from abrupt helper termination. This proof never asserts
// that the operator command started.
type ExecutionProof struct {
	Record              EnforcementRecord `json:"record"`
	ConfigPolicyHash    string            `json:"config_policy_hash"`
	EffectivePolicyHash string            `json:"effective_policy_hash"`
	Profile             string            `json:"profile,omitempty"`
	Workspace           string            `json:"workspace"`
	TempDir             string            `json:"temp_dir"`
	Binary              string            `json:"binary"`
	Command             []string          `json:"command"`
	ExecError           string            `json:"exec_error,omitempty"`
}

// NewExecutionProof constructs and hashes the effective child-side policy.
func NewExecutionProof(record EnforcementRecord, opts ExecControlOptions, command []string) ExecutionProof {
	proof := ExecutionProof{
		Record: record, ConfigPolicyHash: opts.PolicyHash, Profile: opts.Profile,
		Workspace: opts.Workspace, TempDir: opts.TempDir, Binary: opts.Binary,
		Command: slices.Clone(command),
	}
	proof.EffectivePolicyHash = proof.recomputeHash()
	return proof
}

// Verify checks the child proof against the parent-side configuration binding.
func (p ExecutionProof) Verify(expectedConfigHash string) error {
	if !p.Record.Enforced() || p.ConfigPolicyHash == "" || p.ConfigPolicyHash != expectedConfigHash || p.ExecError != "" {
		return errors.New("guard execution proof does not describe valid pre-exec enforcement")
	}
	want := p.recomputeHash()
	if p.EffectivePolicyHash == "" || p.EffectivePolicyHash != want {
		return errors.New("guard execution proof hash mismatch")
	}
	return nil
}

// VerifyInvocation checks the proof and binds it to the invocation requested
// by the parent. Recomputing a digest over child-supplied fields proves that
// those fields agree with each other; it does not prove they match the
// parent's profile, workspace, temporary directory, executable, and argv unless
// they are compared.
func (p ExecutionProof) VerifyInvocation(expected ExecControlOptions, command []string) error {
	if err := p.Verify(expected.PolicyHash); err != nil {
		return err
	}
	if p.Profile != expected.Profile || p.Workspace != expected.Workspace || p.TempDir != expected.TempDir ||
		p.Binary != expected.Binary || !slices.Equal(p.Command, command) {
		return errors.New("guard execution proof does not match the requested invocation")
	}
	return nil
}

func (p ExecutionProof) recomputeHash() string {
	material := struct {
		Record           EnforcementRecord `json:"record"`
		ConfigPolicyHash string            `json:"config_policy_hash"`
		Profile          string            `json:"profile,omitempty"`
		Workspace        string            `json:"workspace"`
		TempDir          string            `json:"temp_dir"`
		Binary           string            `json:"binary"`
		Command          []string          `json:"command"`
	}{p.Record, p.ConfigPolicyHash, p.Profile, p.Workspace, p.TempDir, p.Binary, p.Command}
	encoded, _ := json.Marshal(material)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
