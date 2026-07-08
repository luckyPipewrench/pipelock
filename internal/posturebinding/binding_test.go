// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posturebinding

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/posture"
)

func TestLoadFileMissingReturnsZeroBinding(t *testing.T) {
	got, err := LoadFile(filepath.Join(t.TempDir(), "missing-proof.json"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got.CapsuleSHA256 != "" || got.SignerKeyID != "" || got.ContainmentNonce != "" || got.ContainedUID != "" {
		t.Fatalf("binding = %+v, want zero", got)
	}
}

func TestLoadFileDerivesContainmentBinding(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	capsule, err := posture.Emit(config.Defaults(), posture.Options{
		SigningKey: priv,
		Containment: &posture.ContainmentEvidence{
			Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
			BoundaryVerified:         true,
			ProbeRefusedDirectEgress: true,
			KernelRuleHash:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			TargetUID:                "966",
		},
	})
	if err != nil {
		t.Fatalf("posture.Emit: %v", err)
	}
	data, err := json.Marshal(capsule)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	sum := sha256.Sum256(data)
	if got.CapsuleSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("CapsuleSHA256 = %q, want hash of proof", got.CapsuleSHA256)
	}
	if got.SignerKeyID != capsule.SignerKeyID || got.ContainmentNonce != capsule.Signature || got.ContainedUID != "966" {
		t.Fatalf("binding = %+v, want signer/signature/uid from capsule", got)
	}
}

func TestLoadFileNoContainmentReturnsZeroBinding(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	capsule, err := posture.Emit(config.Defaults(), posture.Options{
		SigningKey: priv,
	})
	if err != nil {
		t.Fatalf("posture.Emit: %v", err)
	}
	data, err := json.Marshal(capsule)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got.CapsuleSHA256 != "" || got.SignerKeyID != "" || got.ContainmentNonce != "" || got.ContainedUID != "" {
		t.Fatalf("binding = %+v, want zero (no containment evidence)", got)
	}
}

func TestLoadFileMalformedReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("LoadFile error = nil, want parse error")
	}
}
