//go:build !windows

// The permission refusals asserted here depend on POSIX mode bits.
// secperm.TooPermissive and OwnedGroupWritableAllowed are deliberate no-ops on
// Windows, so these assertions cannot hold there.

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posturebinding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// mintContainmentCapsule emits a valid, signed posture capsule carrying
// containment evidence, using posture.Emit so signing is never hand-rolled.
func mintContainmentCapsule(t *testing.T) (*posture.Capsule, []byte) {
	t.Helper()
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
	return capsule, data
}

func requireAvailability(t *testing.T, got Result, want Availability) {
	t.Helper()
	if got.Availability != want {
		t.Fatalf("availability = %q, want %q (result = %+v)", got.Availability, want, got)
	}
}

// writeMutatedCapsule rewrites one or more top-level capsule fields in the
// marshaled JSON while leaving the signature untouched, then writes it to a
// fresh temp file. It preserves the exact field set so the capsule still
// unmarshals under strict decoding.
func writeMutatedCapsule(t *testing.T, data []byte, mutate map[string]string) string {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal capsule fields: %v", err)
	}
	for key, val := range mutate {
		raw, err := json.Marshal(val)
		if err != nil {
			t.Fatalf("marshal mutation %q: %v", key, err)
		}
		fields[key] = raw
	}
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal mutated capsule: %v", err)
	}
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadFileTamperedBodyRejected(t *testing.T) {
	_, data := mintContainmentCapsule(t)
	// Mutate a signed field (config_hash) to a well-formed but different value,
	// keeping the original signature: the load-time self-consistency verify must
	// reject it fail-closed on the signature, not on field shape.
	path := writeMutatedCapsule(t, data, map[string]string{
		"config_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	})
	got, err := LoadFile(path)
	if err == nil {
		t.Fatal("LoadFile error = nil, want signature verification failure on tampered body")
	}
	requireAvailability(t, got, AvailabilityInvalid)
}

func TestLoadFileExpiredCapsuleRejected(t *testing.T) {
	_, data := mintContainmentCapsule(t)
	// Backdate the window so it is well-formed (generated < expires) but expired
	// (expires < now). VerifyAt checks expiry before the signature, so the old
	// signature does not need to cover the mutated times.
	now := time.Now().UTC()
	path := writeMutatedCapsule(t, data, map[string]string{
		"generated_at": now.Add(-48 * time.Hour).Format(time.RFC3339Nano),
		"expires_at":   now.Add(-24 * time.Hour).Format(time.RFC3339Nano),
	})
	got, err := LoadFile(path)
	if err == nil {
		t.Fatal("LoadFile error = nil, want expiry rejection")
	}
	// VerifyAt checks the expiry window BEFORE the signature, so this must fail
	// specifically on expiry rather than passing on the (now-stale) signature -
	// otherwise the test would prove signature rejection, not expiry rejection.
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("LoadFile error = %v, want an expiry rejection", err)
	}
	requireAvailability(t, got, AvailabilityInvalid)
}

func TestLoadFileNonHexSignerKeyRejected(t *testing.T) {
	_, data := mintContainmentCapsule(t)
	// A signer_key_id that is not valid hex must fail closed at the key-decode
	// step, before any signature verification.
	path := writeMutatedCapsule(t, data, map[string]string{"signer_key_id": "not-hex-zz"})
	got, err := LoadFile(path)
	if err == nil {
		t.Fatal("LoadFile error = nil, want signer-key decode rejection")
	}
	requireAvailability(t, got, AvailabilityInvalid)
}

func TestLoadFileValidContainmentCapsuleStillBinds(t *testing.T) {
	capsule, data := mintContainmentCapsule(t)
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	requireAvailability(t, result, AvailabilityAttested)
	got := result.Binding
	sum := sha256.Sum256(data)
	if got.CapsuleSHA256 != hex.EncodeToString(sum[:]) ||
		got.SignerKeyID != capsule.SignerKeyID ||
		got.ContainmentNonce != capsule.Signature ||
		got.ContainedUID != "966" {
		t.Fatalf("binding = %+v, want fields from valid capsule", got)
	}
}

func TestLoadFileRejectsGroupWritableProof(t *testing.T) {
	_, data := mintContainmentCapsule(t)
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write proof: %v", err)
	}
	groupWritableMode := os.FileMode(0o660)
	if err := os.Chmod(path, groupWritableMode); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	got, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("LoadFile(group-writable proof) error = %v, want permission rejection", err)
	}
	requireAvailability(t, got, AvailabilityInvalid)
}

func TestLoadRuntimeRelativeOverrideRejected(t *testing.T) {
	t.Setenv(RuntimeProofEnv, "relative/proof.json")
	if _, err := LoadRuntime(); err == nil {
		t.Fatal("LoadRuntime error = nil, want absolute-path rejection")
	}
}

func TestLoadRuntimeAbsoluteOverrideWorks(t *testing.T) {
	capsule, data := mintContainmentCapsule(t)
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(RuntimeProofEnv, path)
	result, err := LoadRuntime()
	if err != nil {
		t.Fatalf("LoadRuntime: %v", err)
	}
	requireAvailability(t, result, AvailabilityAttested)
	got := result.Binding
	if got.SignerKeyID != capsule.SignerKeyID || got.ContainedUID != "966" {
		t.Fatalf("binding = %+v, want fields from capsule at absolute override", got)
	}
}

func TestLoadRuntimeAbsentOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-proof.json")
	t.Setenv(RuntimeProofEnv, path)
	got, err := LoadRuntime()
	if err != nil {
		t.Fatalf("LoadRuntime: %v", err)
	}
	requireAvailability(t, got, AvailabilityAbsent)
	if got.Binding.CapsuleSHA256 != "" || got.Binding.SignerKeyID != "" || got.Binding.ContainmentNonce != "" || got.Binding.ContainedUID != "" {
		t.Fatalf("binding = %+v, want zero from missing proof", got.Binding)
	}
}

func TestLoadFileMissingReturnsZeroBinding(t *testing.T) {
	got, err := LoadFile(filepath.Join(t.TempDir(), "missing-proof.json"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	requireAvailability(t, got, AvailabilityAbsent)
	if got.Binding.CapsuleSHA256 != "" || got.Binding.SignerKeyID != "" || got.Binding.ContainmentNonce != "" || got.Binding.ContainedUID != "" {
		t.Fatalf("binding = %+v, want zero", got)
	}
}

func TestLoadRuntimeForReceiptsAbsentPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-proof.json")
	t.Setenv(RuntimeProofEnv, path)

	binding, err := LoadRuntimeForReceipts(RuntimeReceiptOptions{ReceiptSigningEnabled: true})
	if err != nil {
		t.Fatalf("ordinary receipt policy: %v", err)
	}
	if binding != (receipt.PostureBinding{}) {
		t.Fatalf("absent proof binding = %+v, want zero", binding)
	}
}

func TestLoadRuntimeForReceiptsSkipsProofWithoutSigning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-proof.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(RuntimeProofEnv, path)

	binding, err := LoadRuntimeForReceipts(RuntimeReceiptOptions{})
	if err != nil {
		t.Fatalf("recorder-only runtime loaded posture proof: %v", err)
	}
	if binding != (receipt.PostureBinding{}) {
		t.Fatalf("recorder-only posture binding = %+v, want zero", binding)
	}
}

func TestLoadRuntimeForReceiptsBindsAttestedContainment(t *testing.T) {
	_, data := mintContainmentCapsule(t)
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(RuntimeProofEnv, path)
	binding, err := LoadRuntimeForReceipts(RuntimeReceiptOptions{ReceiptSigningEnabled: true})
	if err != nil {
		t.Fatalf("ordinary receipt policy: %v", err)
	}
	if binding.CapsuleSHA256 == "" || binding.ContainmentNonce == "" {
		t.Fatalf("attested binding = %+v, want containment fields", binding)
	}
}

func TestLoadRuntimeForReceiptsBindsNothingWithoutContainment(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	capsule, err := posture.Emit(config.Defaults(), posture.Options{SigningKey: priv})
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
	t.Setenv(RuntimeProofEnv, path)
	binding, err := LoadRuntimeForReceipts(RuntimeReceiptOptions{ReceiptSigningEnabled: true})
	if err != nil {
		t.Fatalf("proof without containment: %v", err)
	}
	if binding != (receipt.PostureBinding{}) {
		t.Fatalf("binding without containment evidence = %+v, want zero", binding)
	}
}

func TestLoadFileDerivesContainmentBinding(t *testing.T) {
	capsule, data := mintContainmentCapsule(t)
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	requireAvailability(t, result, AvailabilityAttested)
	got := result.Binding
	canonicalSum := sha256.Sum256(data)
	if got.CapsuleSHA256 != hex.EncodeToString(canonicalSum[:]) {
		t.Fatalf("CapsuleSHA256 = %q, want canonical capsule hash", got.CapsuleSHA256)
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	rawSum := sha256.Sum256(raw)
	if got.CapsuleSHA256 == hex.EncodeToString(rawSum[:]) {
		t.Fatal("CapsuleSHA256 unexpectedly matched raw proof file hash; want canonical capsule hash")
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
	requireAvailability(t, got, AvailabilityAttested)
	if got.Binding.CapsuleSHA256 != "" || got.Binding.SignerKeyID != "" || got.Binding.ContainmentNonce != "" || got.Binding.ContainedUID != "" {
		t.Fatalf("binding = %+v, want zero (no containment evidence)", got)
	}
}

func TestLoadFileUnsignedNoContainmentIsInvalid(t *testing.T) {
	// A readable capsule that carries no containment evidence AND cannot be
	// verified must be invalid, not attested. Before the fix, this exact file
	// produced posture_availability "attested" in a signed session_open.
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := LoadFile(path)
	if err == nil {
		t.Fatalf("LoadFile: want error for unverifiable capsule, got nil (availability=%q)", got.Availability)
	}
	requireAvailability(t, got, AvailabilityInvalid)
}

func TestLoadFileMalformedReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := LoadFile(path)
	if err == nil {
		t.Fatal("LoadFile error = nil, want parse error")
	}
	requireAvailability(t, got, AvailabilityInvalid)
}

func TestLoadFileRejectsOversizedAndEscapingSymlink(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "proof.json")
		if err := os.WriteFile(path, make([]byte, maxRuntimeProofBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path); err == nil {
			t.Fatal("LoadFile accepted oversized posture proof")
		}
	})
	t.Run("escaping symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(t.TempDir(), "proof.json")
		if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "proof.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(link); err == nil {
			t.Fatal("LoadFile accepted symlink escaping the proof directory")
		}
	})
}

func TestLoadFileEmptyPathIsAbsent(t *testing.T) {
	got, err := LoadFile("   ")
	if err != nil {
		t.Fatalf("LoadFile with a blank path: %v", err)
	}
	requireAvailability(t, got, AvailabilityAbsent)
	if got.Binding != (receipt.PostureBinding{}) {
		t.Fatalf("blank-path binding = %+v, want zero", got.Binding)
	}
}

func TestLoadRuntimeForReceiptsPropagatesInvalidProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(RuntimeProofEnv, path)

	var warning bytes.Buffer
	binding, err := LoadRuntimeForReceipts(RuntimeReceiptOptions{ReceiptSigningEnabled: true, Stderr: &warning})
	if err == nil || !strings.Contains(err.Error(), "parse posture proof") {
		t.Fatalf("malformed proof error = %v, want a parse failure", err)
	}
	if binding != (receipt.PostureBinding{}) {
		t.Fatalf("malformed proof binding = %+v, want zero", binding)
	}
	if warning.Len() != 0 {
		t.Fatalf("malformed proof wrote an unreadable warning: %q", warning.String())
	}
}
