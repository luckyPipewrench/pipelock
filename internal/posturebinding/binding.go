// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package posturebinding derives receipt session_open binding fields from a
// signed posture proof artifact.
package posturebinding

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const (
	// RuntimeProofEnv overrides the posture proof path used for receipt
	// session_open binding.
	RuntimeProofEnv = "PIPELOCK_POSTURE_PROOF"
	// DefaultContainRunProofPath is where `pipelock contain run` writes the
	// signed runtime posture capsule by default.
	DefaultContainRunProofPath = "/var/lib/pipelock/contain/posture/proof.json"
	maxRuntimeProofBytes       = 4 << 20
)

// LoadRuntime returns the posture binding for the configured runtime proof
// path. Missing proof files mean no attested containment is available and return
// the zero binding; malformed present proof files return an error so callers do
// not sign a misleading empty binding by accident.
//
// A non-empty PIPELOCK_POSTURE_PROOF override must be an ABSOLUTE path. A
// relative value would resolve against the runtime process cwd and could
// silently read the wrong file, so it is rejected outright rather than
// filepath.Abs-resolved (resolving would hide the operator's mistake against an
// ambiguous cwd). The default DefaultContainRunProofPath is already absolute.
func LoadRuntime() (receipt.PostureBinding, error) {
	path := strings.TrimSpace(os.Getenv(RuntimeProofEnv))
	switch {
	case path == "":
		path = DefaultContainRunProofPath
	case !filepath.IsAbs(path):
		return receipt.PostureBinding{}, fmt.Errorf("%s must be an absolute path, got %q", RuntimeProofEnv, path)
	}
	return LoadFile(path)
}

// LoadFile derives a receipt posture binding from a signed posture proof file.
//
// A present capsule with containment evidence is signature-verified before its
// fields are bound. This is a defense-in-depth SELF-CONSISTENCY check: it
// confirms the capsule was signed by the key it names (SignerKeyID) and is
// unexpired and well-formed. It is NOT trust-anchoring — an attacker who
// regenerates a whole capsule together with a fresh key still passes it, because
// the check trusts the key embedded in the capsule. The authoritative trust
// anchor remains the operator-provided key at verify-receipt time
// (verify-receipt --posture-key <hex>). This only prevents binding a corrupted
// or tampered capsule body at emit time, rejecting it fail-closed instead of
// recording misleading fields.
//
// A missing proof file still returns the zero binding (no attested containment).
// A present-but-invalid capsule now returns an error where it previously bound
// silently; callers already fail emitter setup on that error.
func LoadFile(path string) (receipt.PostureBinding, error) {
	if strings.TrimSpace(path) == "" {
		return receipt.PostureBinding{}, nil
	}
	data, err := securefile.Read(path, securefile.Options{MaxBytes: maxRuntimeProofBytes, DisallowedPerms: 0o022})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return receipt.PostureBinding{}, nil
		}
		return receipt.PostureBinding{}, fmt.Errorf("read posture proof: %w", err)
	}
	var capsule posture.Capsule
	if err := json.Unmarshal(data, &capsule); err != nil {
		return receipt.PostureBinding{}, fmt.Errorf("parse posture proof: %w", err)
	}
	if capsule.Evidence.Containment == nil {
		return receipt.PostureBinding{}, nil
	}
	pub, err := hex.DecodeString(capsule.SignerKeyID)
	if err != nil {
		return receipt.PostureBinding{}, fmt.Errorf("decode posture proof signer key: %w", err)
	}
	if err := posture.VerifyAt(&capsule, ed25519.PublicKey(pub), time.Now().UTC()); err != nil {
		return receipt.PostureBinding{}, fmt.Errorf("verify posture proof: %w", err)
	}
	// CapsuleSHA256 binds the canonical posture capsule, not the raw proof.json
	// bytes. That matches contain-run proofs and verifier-side canonical capsule
	// hashing: insignificant JSON whitespace/key-order differences in a
	// hand-written proof file do not change the signed receipt binding. Operators
	// comparing the receipt field directly to sha256sum(proof.json) must
	// canonicalize the file first.
	canonical, err := json.Marshal(&capsule)
	if err != nil {
		return receipt.PostureBinding{}, fmt.Errorf("marshal posture proof: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return receipt.PostureBinding{
		CapsuleSHA256:    hex.EncodeToString(sum[:]),
		SignerKeyID:      capsule.SignerKeyID,
		ContainmentNonce: capsule.Signature,
		ContainedUID:     capsule.Evidence.Containment.TargetUID,
	}, nil
}
