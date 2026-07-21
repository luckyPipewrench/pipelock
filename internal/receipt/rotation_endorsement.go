// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
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

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	// RotationEndorsementVersion is the current receipt-key rotation
	// endorsement schema.
	RotationEndorsementVersion = 1
	// RotationEndorsementEntryType identifies endorsements in recorder logs.
	RotationEndorsementEntryType = "rotation_endorsement"

	rotationEndorsementDomain   = "pipelock-rotation-endorsement-v1\x00"
	maxRotationEndorsementBytes = 64 << 10
)

// RotationEndorsement is the retiring key's authorization of its successor.
// Binding the exact prior tail prevents a write-only attacker from truncating
// a chain and laundering the shorter tail through a fabricated key rotation.
type RotationEndorsement struct {
	Version        int    `json:"version"`
	SessionID      string `json:"session_id"`
	PriorSignerKey string `json:"prior_signer_key"`
	PriorFinalSeq  uint64 `json:"prior_final_seq"`
	PriorTailHash  string `json:"prior_tail_hash"`
	NewSignerKey   string `json:"new_signer_key"`
	RotatedAt      string `json:"rotated_at"`
	Endorsement    string `json:"endorsement"`
}

type rotationEndorsementCanonical struct {
	Version        int    `json:"version"`
	SessionID      string `json:"session_id"`
	PriorSignerKey string `json:"prior_signer_key"`
	PriorFinalSeq  uint64 `json:"prior_final_seq"`
	PriorTailHash  string `json:"prior_tail_hash"`
	NewSignerKey   string `json:"new_signer_key"`
	RotatedAt      string `json:"rotated_at"`
}

// SignRotationEndorsement signs an endorsement with the retiring private key.
// The embedded prior key is derived from privKey rather than trusted input.
func SignRotationEndorsement(e RotationEndorsement, privKey ed25519.PrivateKey) (RotationEndorsement, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return RotationEndorsement{}, fmt.Errorf("invalid prior private key size: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	e.Version = RotationEndorsementVersion
	e.PriorSignerKey = hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	e.Endorsement = ""
	if err := validateRotationEndorsementFields(e, false); err != nil {
		return RotationEndorsement{}, err
	}
	digest, err := rotationEndorsementDigest(e)
	if err != nil {
		return RotationEndorsement{}, err
	}
	e.Endorsement = signaturePrefix + hex.EncodeToString(ed25519.Sign(privKey, digest))
	return e, nil
}

// VerifyRotationEndorsement verifies the endorsement's structure and retiring
// key signature. A chain verifier must additionally match every boundary field
// against the presented receipt chain before treating the successor as trusted.
func VerifyRotationEndorsement(e RotationEndorsement) error {
	if err := validateRotationEndorsementFields(e, true); err != nil {
		return err
	}
	pubBytes, err := hex.DecodeString(e.PriorSignerKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid prior_signer_key")
	}
	sigHex, ok := strings.CutPrefix(e.Endorsement, signaturePrefix)
	if !ok {
		return fmt.Errorf("invalid endorsement signature format: missing %s prefix", signaturePrefix)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid endorsement signature")
	}
	digest, err := rotationEndorsementDigest(e)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), digest, sig) {
		return errors.New("rotation endorsement signature verification failed")
	}
	return nil
}

func validateRotationEndorsementFields(e RotationEndorsement, requireSignature bool) error {
	if e.Version != RotationEndorsementVersion {
		return fmt.Errorf("unsupported rotation endorsement version %d", e.Version)
	}
	if strings.TrimSpace(e.SessionID) == "" {
		return errors.New("rotation endorsement session_id is empty")
	}
	if !validEd25519PublicKeyHex(e.PriorSignerKey) {
		return errors.New("rotation endorsement prior_signer_key is invalid")
	}
	if !validEd25519PublicKeyHex(e.NewSignerKey) {
		return errors.New("rotation endorsement new_signer_key is invalid")
	}
	if e.PriorSignerKey == e.NewSignerKey {
		return errors.New("rotation endorsement successor key must differ from prior key")
	}
	if !validSHA256Hex(e.PriorTailHash) {
		return errors.New("rotation endorsement prior_tail_hash is invalid")
	}
	rotatedAt, err := time.Parse(time.RFC3339Nano, e.RotatedAt)
	if err != nil || rotatedAt.IsZero() || e.RotatedAt != rotatedAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("rotation endorsement rotated_at must be canonical UTC RFC3339Nano")
	}
	if requireSignature && e.Endorsement == "" {
		return errors.New("rotation endorsement signature is empty")
	}
	return nil
}

func validEd25519PublicKeyHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == ed25519.PublicKeySize && value == strings.ToLower(value)
}

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func rotationEndorsementDigest(e RotationEndorsement) ([]byte, error) {
	canonical, err := json.Marshal(rotationEndorsementCanonical{
		Version:        e.Version,
		SessionID:      e.SessionID,
		PriorSignerKey: e.PriorSignerKey,
		PriorFinalSeq:  e.PriorFinalSeq,
		PriorTailHash:  e.PriorTailHash,
		NewSignerKey:   e.NewSignerKey,
		RotatedAt:      e.RotatedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rotation endorsement: %w", err)
	}
	sum := sha256.Sum256(append([]byte(rotationEndorsementDomain), canonical...))
	return sum[:], nil
}

// UnmarshalRotationEndorsement strictly decodes one endorsement. Duplicate,
// unknown, and trailing fields are rejected because every accepted field is a
// security claim covered by the retiring key's signature.
func UnmarshalRotationEndorsement(data []byte) (RotationEndorsement, error) {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return RotationEndorsement{}, fmt.Errorf("unmarshal rotation endorsement: %w", err)
	}
	var endorsement RotationEndorsement
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&endorsement); err != nil {
		return RotationEndorsement{}, fmt.Errorf("unmarshal rotation endorsement: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return RotationEndorsement{}, errors.New("unmarshal rotation endorsement: trailing tokens")
	}
	if err := VerifyRotationEndorsement(endorsement); err != nil {
		return RotationEndorsement{}, err
	}
	return endorsement, nil
}

// LoadRotationEndorsementFile reads and strictly verifies one bounded
// endorsement file for offline chain verification.
func LoadRotationEndorsementFile(path string) (RotationEndorsement, error) {
	file, err := os.Open(filepath.Clean(path)) // #nosec G304 -- explicit operator-supplied verification input.
	if err != nil {
		return RotationEndorsement{}, fmt.Errorf("read rotation endorsement: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxRotationEndorsementBytes+1))
	if err != nil {
		return RotationEndorsement{}, fmt.Errorf("read rotation endorsement: %w", err)
	}
	if len(data) > maxRotationEndorsementBytes {
		return RotationEndorsement{}, fmt.Errorf("rotation endorsement exceeds %d bytes", maxRotationEndorsementBytes)
	}
	return UnmarshalRotationEndorsement(data)
}
