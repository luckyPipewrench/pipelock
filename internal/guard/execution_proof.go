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

// ExecutionProof binds the kernel result to the exact invocation that entered
// the enforced domain. It is transported over an inherited close-on-exec pipe;
// the parent accepts it only after exec closes that pipe without a later error.
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
func NewExecutionProof(record EnforcementRecord, configHash, profile, workspace, tempDir, binary string, command []string) ExecutionProof {
	proof := ExecutionProof{
		Record: record, ConfigPolicyHash: configHash, Profile: profile,
		Workspace: workspace, TempDir: tempDir, Binary: binary,
		Command: slices.Clone(command),
	}
	proof.EffectivePolicyHash = proof.recomputeHash()
	return proof
}

// Verify checks the child proof against the parent-side configuration binding.
func (p ExecutionProof) Verify(expectedConfigHash string) error {
	if !p.Record.Enforced() || p.ConfigPolicyHash == "" || p.ConfigPolicyHash != expectedConfigHash || p.ExecError != "" {
		return errors.New("guard execution proof does not describe a successful enforced invocation")
	}
	want := p.recomputeHash()
	if p.EffectivePolicyHash == "" || p.EffectivePolicyHash != want {
		return errors.New("guard execution proof hash mismatch")
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
