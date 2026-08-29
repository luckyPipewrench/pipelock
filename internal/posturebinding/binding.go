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
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

// Availability describes whether this process could obtain containment posture
// evidence for its receipt session_open record.
type Availability string

const (
	// AvailabilityAttested means a proof file was read and verified. Its binding
	// can be empty when the verified capsule carries no containment evidence.
	AvailabilityAttested Availability = "attested"
	// AvailabilityAbsent means the configured proof path does not exist.
	AvailabilityAbsent Availability = "absent"
	// AvailabilityUnreadable means reading the proof or traversing one of its
	// parents was denied. It does not establish whether a proof exists.
	AvailabilityUnreadable Availability = "unreadable"
	// AvailabilityInvalid means a present proof was malformed, unverifiable, or
	// expired. Invalid proofs always return an error and are never bound.
	AvailabilityInvalid Availability = "invalid"
)

// Result is the typed outcome of loading a runtime posture proof. Invalid
// outcomes carry AvailabilityInvalid together with a non-nil error.
type Result struct {
	Binding      receipt.PostureBinding
	Availability Availability
	Path         string
	Cause        error
}

// RuntimeReceiptOptions controls the shared receipt-runtime policy applied to
// every caller that opens a receipt emitter.
type RuntimeReceiptOptions struct {
	// ReceiptSigningEnabled reports whether this runtime will create signed
	// action receipts. Posture binding is not loaded for a recorder-only
	// runtime, which has no session_open record to bind.
	ReceiptSigningEnabled bool
	Stderr                io.Writer
}

const (
	// RuntimeProofEnv overrides the posture proof path used for receipt
	// session_open binding.
	RuntimeProofEnv = "PIPELOCK_POSTURE_PROOF"
	// DefaultContainRunProofPath is where `pipelock contain run` writes the
	// signed runtime posture capsule by default.
	DefaultContainRunProofPath = "/var/lib/pipelock/contain/posture/proof.json"
	maxRuntimeProofBytes       = 4 << 20
)

// LoadRuntime returns the typed outcome for the configured runtime proof path.
// Missing proof files are absent. A permission denial is unreadable, which
// means this process cannot determine whether containment evidence exists.
// Malformed present proof files are invalid and return an error.
//
// A non-empty PIPELOCK_POSTURE_PROOF override must be an ABSOLUTE path. A
// relative value would resolve against the runtime process cwd and could
// silently read the wrong file, so it is rejected outright rather than
// filepath.Abs-resolved (resolving would hide the operator's mistake against an
// ambiguous cwd). The default DefaultContainRunProofPath is already absolute.
func LoadRuntime() (Result, error) {
	path := strings.TrimSpace(os.Getenv(RuntimeProofEnv))
	switch {
	case path == "":
		path = DefaultContainRunProofPath
	case !filepath.IsAbs(path):
		err := fmt.Errorf("%s must be an absolute path, got %q", RuntimeProofEnv, path)
		result := resultWithAvailability(path, AvailabilityInvalid)
		result.Cause = err
		return result, err
	}
	return LoadFile(path)
}

// LoadRuntimeForReceipts applies the one shared availability policy used by
// every receipt-enabled runtime. An unreadable proof records an actionable
// warning and binds nothing, so the runtime starts without claiming
// containment it could not confirm. A malformed present proof still fails.
func LoadRuntimeForReceipts(opts RuntimeReceiptOptions) (receipt.PostureBinding, error) {
	if !opts.ReceiptSigningEnabled {
		return receipt.PostureBinding{}, nil
	}
	result, err := LoadRuntime()
	if err != nil {
		return receipt.PostureBinding{}, err
	}
	if result.Availability == AvailabilityUnreadable && opts.Stderr != nil {
		_, _ = fmt.Fprint(opts.Stderr, unreadableProofWarning(result))
	}
	return result.Binding, nil
}

func resultWithAvailability(path string, availability Availability) Result {
	return Result{
		Availability: availability,
		Path:         path,
	}
}

func unreadableProofWarning(result Result) string {
	owner, group, known := proofOwnerGroup(result.Path)
	ownerGroup := "owner/group could not be inspected because directory traversal was denied"
	if known {
		ownerGroup = fmt.Sprintf("owner %s, group %s", owner, group)
	}
	return fmt.Sprintf(
		"WARNING: containment posture proof %q is unreadable: %v\n"+
			"         %s. Containment-run proofs are only readable by the containment user.\n"+
			"         Run this runtime as that user, or grant this runtime user read access to the proof and traverse access to each parent directory.\n",
		result.Path, result.Cause, ownerGroup)
}

// LoadFile derives a typed receipt posture result from a signed posture proof
// file.
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
// A missing proof file is absent. A present proof that this principal cannot
// read is unreadable, not absent: it does not establish that containment exists.
// A present-but-invalid capsule returns AvailabilityInvalid and an error so it
// never binds misleading fields.
func LoadFile(path string) (Result, error) {
	result := resultWithAvailability(path, AvailabilityAbsent)
	if strings.TrimSpace(path) == "" {
		return result, nil
	}
	data, err := securefile.Read(path, securefile.Options{MaxBytes: maxRuntimeProofBytes, DisallowedPerms: 0o022})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		if errors.Is(err, os.ErrPermission) {
			result = resultWithAvailability(path, AvailabilityUnreadable)
			result.Cause = err
			return result, nil
		}
		result = resultWithAvailability(path, AvailabilityInvalid)
		result.Cause = err
		return result, fmt.Errorf("read posture proof: %w", err)
	}
	var capsule posture.Capsule
	if err := json.Unmarshal(data, &capsule); err != nil {
		result = resultWithAvailability(path, AvailabilityInvalid)
		result.Cause = err
		return result, fmt.Errorf("parse posture proof: %w", err)
	}
	pub, err := hex.DecodeString(capsule.SignerKeyID)
	if err != nil {
		result = resultWithAvailability(path, AvailabilityInvalid)
		result.Cause = err
		return result, fmt.Errorf("decode posture proof signer key: %w", err)
	}
	if err := posture.VerifyAt(&capsule, ed25519.PublicKey(pub), time.Now().UTC()); err != nil {
		result = resultWithAvailability(path, AvailabilityInvalid)
		result.Cause = err
		return result, fmt.Errorf("verify posture proof: %w", err)
	}
	// Only AFTER verification may a no-containment capsule report attested.
	// This branch used to sit before VerifyAt, so any readable JSON without
	// containment evidence, including a bare {}, was labeled attested in the
	// signed session_open. Assessment never granted containment from it, but
	// the signed availability value violated its own documented contract:
	// attested means read AND verified. An unverifiable capsule is invalid
	// and stays fatal, like every other malformed present proof.
	if capsule.Evidence.Containment == nil {
		result = resultWithAvailability(path, AvailabilityAttested)
		return result, nil
	}
	// CapsuleSHA256 binds the canonical posture capsule, not the raw proof.json
	// bytes. That matches contain-run proofs and verifier-side canonical capsule
	// hashing: insignificant JSON whitespace/key-order differences in a
	// hand-written proof file do not change the signed receipt binding. Operators
	// comparing the receipt field directly to sha256sum(proof.json) must
	// canonicalize the file first.
	canonical, err := json.Marshal(&capsule)
	if err != nil {
		result = resultWithAvailability(path, AvailabilityInvalid)
		result.Cause = err
		return result, fmt.Errorf("marshal posture proof: %w", err)
	}
	sum := sha256.Sum256(canonical)
	result = resultWithAvailability(path, AvailabilityAttested)
	result.Binding = receipt.PostureBinding{
		CapsuleSHA256:    hex.EncodeToString(sum[:]),
		SignerKeyID:      capsule.SignerKeyID,
		ContainmentNonce: capsule.Signature,
		ContainedUID:     capsule.Evidence.Containment.TargetUID,
	}
	return result, nil
}
