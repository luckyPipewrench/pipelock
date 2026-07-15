// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// IssuanceExportVersion is the wire version of a signed issuance export.
const IssuanceExportVersion = 1

// maxIssuanceExportSize caps the decoded export size to prevent memory
// exhaustion from a maliciously large blob. An export is a small JSON record;
// 64 KiB is generous.
const maxIssuanceExportSize = 64 * 1024

// IssuanceExportPayload is the signed record that lets a license token minted by
// a standalone signer (the offline-root break-glass path) be durably imported
// into the issuing service's revocation surface. It carries the FULL token hash
// (sha256 of the exact token string) so the import is bound to the real
// credential, not the truncated, unsigned local JSONL ledger hash.
//
// IssuerKeyID is the hex-encoded Ed25519 public key (or intermediate serial)
// whose private half signed BOTH the license token and this export. Binding the
// export and the token to the same signer means an attacker cannot pair a token
// signed by key A with an export signed by key B.
type IssuanceExportPayload struct {
	Version        int    `json:"version"`
	LicenseID      string `json:"license_id"`
	TokenSHA256    string `json:"token_sha256"` // hex, full 32-byte sha256 of the token string
	SubscriptionID string `json:"subscription_id,omitempty"`
	IssuerKeyID    string `json:"issuer_key_id"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at,omitempty"`
	Features       string `json:"features,omitempty"` // JSON array, informational
	Org            string `json:"org,omitempty"`
	Email          string `json:"email,omitempty"`
}

// IssuanceExport is a signed issuance export. The wire format stores the exact
// signed payload bytes as base64url JSON; signature verification covers those
// bytes, not a re-marshaled struct (so field reordering can never break it).
type IssuanceExport struct {
	Payload   IssuanceExportPayload
	Signature string
	SHA256    string
	payload   []byte
}

type issuanceExportWire struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// TokenSHA256Hex returns the full hex sha256 of a license token string. This is
// the import-table key: it binds an import to the exact credential, unlike the
// truncated, unsigned local JSONL ledger hash, which cannot be the import
// source.
func TokenSHA256Hex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SignIssuanceExport signs an issuance-export payload with the same private key
// that signed the license token. The signer's public half is recorded as the
// IssuerKeyID so a verifier can confirm token and export share one signer.
func SignIssuanceExport(payload IssuanceExportPayload, privateKey ed25519.PrivateKey) (IssuanceExport, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return IssuanceExport{}, errors.New("invalid private key size")
	}
	if payload.Version == 0 {
		payload.Version = IssuanceExportVersion
	}
	if payload.IssuerKeyID == "" {
		pub, ok := privateKey.Public().(ed25519.PublicKey)
		if !ok {
			return IssuanceExport{}, errors.New("signing key has no public half")
		}
		payload.IssuerKeyID = hex.EncodeToString(pub)
	}
	if err := validateIssuanceExportPayload(payload); err != nil {
		return IssuanceExport{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return IssuanceExport{}, fmt.Errorf("marshal issuance export payload: %w", err)
	}
	sig := ed25519.Sign(privateKey, data)
	sum := sha256.Sum256(data)
	export := IssuanceExport{
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
		SHA256:    hex.EncodeToString(sum[:]),
		payload:   append([]byte(nil), data...),
	}
	return export, nil
}

// MarshalJSON serializes the export to the wire format (base64url payload +
// signature), preserving the exact signed bytes.
func (x IssuanceExport) MarshalJSON() ([]byte, error) {
	payload := x.payload
	if len(payload) == 0 {
		var err error
		payload, err = json.Marshal(x.Payload)
		if err != nil {
			return nil, fmt.Errorf("marshal issuance export payload: %w", err)
		}
	}
	return json.Marshal(issuanceExportWire{
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: x.Signature,
	})
}

// ParseAndVerifyIssuanceExport decodes a signed export, verifies its Ed25519
// signature against publicKey, and structurally validates the payload. It fails
// closed on a bad signature, a payload/IssuerKeyID mismatch, or a malformed
// record. publicKey must be the signer's public half (which also must equal the
// payload's IssuerKeyID) so an attacker cannot present an export signed by a key
// other than the one named in the record.
func ParseAndVerifyIssuanceExport(data []byte, publicKey ed25519.PublicKey) (IssuanceExport, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return IssuanceExport{}, errors.New("invalid public key")
	}
	if len(data) > maxIssuanceExportSize {
		return IssuanceExport{}, errors.New("issuance export exceeds maximum size")
	}
	var wire issuanceExportWire
	if err := decodeLicenseJSON(data, &wire); err != nil {
		return IssuanceExport{}, fmt.Errorf("parse issuance export: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(wire.Payload)
	if err != nil {
		return IssuanceExport{}, fmt.Errorf("decode issuance export payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(wire.Signature)
	if err != nil {
		return IssuanceExport{}, fmt.Errorf("decode issuance export signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return IssuanceExport{}, errors.New("invalid issuance export signature size")
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return IssuanceExport{}, errors.New("invalid issuance export signature")
	}
	var claims IssuanceExportPayload
	if err := decodeLicenseJSON(payload, &claims); err != nil {
		return IssuanceExport{}, fmt.Errorf("parse issuance export payload: %w", err)
	}
	if err := validateIssuanceExportPayload(claims); err != nil {
		return IssuanceExport{}, err
	}
	// The payload names its signer; the caller verified against publicKey. They
	// MUST be the same key, otherwise a record signed by a trusted key could
	// carry a forged IssuerKeyID (display/reality divergence).
	if claims.IssuerKeyID != hex.EncodeToString(publicKey) {
		return IssuanceExport{}, errors.New("issuance export issuer_key_id does not match verifying key")
	}
	sum := sha256.Sum256(payload)
	return IssuanceExport{
		Payload:   claims,
		Signature: wire.Signature,
		SHA256:    hex.EncodeToString(sum[:]),
		payload:   append([]byte(nil), payload...),
	}, nil
}

// validateIssuanceExportPayload enforces the structural invariants every export
// must satisfy regardless of trust path.
func validateIssuanceExportPayload(p IssuanceExportPayload) error {
	if p.Version != IssuanceExportVersion {
		return fmt.Errorf("unsupported issuance export version: %d", p.Version)
	}
	if p.LicenseID == "" {
		return errors.New("issuance export missing license_id")
	}
	if p.IssuerKeyID == "" {
		return errors.New("issuance export missing issuer_key_id")
	}
	if p.IssuedAt <= 0 {
		return errors.New("issuance export missing issued_at")
	}
	// The full token hash is the load-bearing field: it binds the import to the
	// real credential. Require it and require it to be a full sha256 in hex.
	if len(p.TokenSHA256) != sha256.Size*2 {
		return fmt.Errorf("issuance export token_sha256 must be a %d-char hex sha256", sha256.Size*2)
	}
	if _, err := hex.DecodeString(p.TokenSHA256); err != nil {
		return fmt.Errorf("issuance export token_sha256 is not valid hex: %w", err)
	}
	return nil
}

// BuildIssuanceExportFromToken constructs an export payload from a token and its
// decoded claims, computing the full token hash. The signer key id is filled in
// by SignIssuanceExport from the private key.
func BuildIssuanceExportFromToken(token string, lic License, features string, now time.Time) IssuanceExportPayload {
	issued := lic.IssuedAt
	if issued <= 0 {
		issued = now.Unix()
	}
	return IssuanceExportPayload{
		Version:        IssuanceExportVersion,
		LicenseID:      lic.ID,
		TokenSHA256:    TokenSHA256Hex(token),
		SubscriptionID: lic.SubscriptionID,
		IssuedAt:       issued,
		ExpiresAt:      lic.ExpiresAt,
		Features:       features,
		Org:            lic.Org,
		Email:          lic.Email,
	}
}
