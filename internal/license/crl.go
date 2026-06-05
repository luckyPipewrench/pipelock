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
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	CRLVersion     = 1
	maxCRLFileSize = 256 * 1024
)

var (
	ErrLicenseRevoked = errors.New("license revoked")
	// ErrIntermediateRevoked is returned when an intermediate signing
	// certificate's serial appears in the CRL. Rotation revokes the prior
	// intermediate, so any token signed by it must fail closed.
	ErrIntermediateRevoked = errors.New("intermediate certificate revoked")
)

// RevokedLicense records one revoked license ID in a signed CRL.
type RevokedLicense struct {
	ID        string `json:"id"`
	Reason    string `json:"reason,omitempty"`
	RevokedAt int64  `json:"revoked_at"`
}

// RevokedIntermediate records one revoked intermediate signing certificate,
// keyed by its serial / key id. Revoking an intermediate invalidates every
// license token it signed - this is the rotation/compromise kill switch for the
// intermediate-key PKI tier.
type RevokedIntermediate struct {
	Serial    string `json:"serial"`
	Reason    string `json:"reason,omitempty"`
	RevokedAt int64  `json:"revoked_at"`
}

// CRLPayload is the signed revocation-list payload. RevokedIntermediates is an
// optional field added for the intermediate-key PKI tier; CRLs that predate it
// simply carry an empty list, and the wire version stays 1 (a pre-PKI verifier
// only does direct-root verification and never trusts an intermediate anyway).
type CRLPayload struct {
	Version              int                   `json:"version"`
	IssuedAt             int64                 `json:"issued_at"`
	ExpiresAt            int64                 `json:"expires_at"`
	Revoked              []RevokedLicense      `json:"revoked"`
	RevokedIntermediates []RevokedIntermediate `json:"revoked_intermediates,omitempty"`
}

// CRL is a signed license revocation list. The wire format stores the exact
// signed payload bytes as base64url JSON. Signature verification covers those
// bytes, not a re-marshaled struct.
type CRL struct {
	Payload   CRLPayload     `json:"-"`
	Signature string         `json:"-"`
	SHA256    string         `json:"-"`
	payload   []byte         `json:"-"`
	index     map[string]int `json:"-"`
	intIndex  map[string]int `json:"-"`
}

type crlWire struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func SignCRL(payload CRLPayload, privateKey ed25519.PrivateKey) (CRL, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return CRL{}, errors.New("invalid private key size")
	}
	if payload.Version == 0 {
		payload.Version = CRLVersion
	}
	if err := validateCRLPayload(payload, time.Now()); err != nil {
		return CRL{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return CRL{}, fmt.Errorf("marshal CRL payload: %w", err)
	}
	sig := ed25519.Sign(privateKey, data)
	sum := sha256.Sum256(data)
	crl := CRL{
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
		SHA256:    hex.EncodeToString(sum[:]),
		payload:   slices.Clone(data),
	}
	crl.buildIndex()
	return crl, nil
}

func (c CRL) MarshalJSON() ([]byte, error) {
	payload := c.payload
	if len(payload) == 0 {
		var err error
		payload, err = json.Marshal(c.Payload)
		if err != nil {
			return nil, fmt.Errorf("marshal CRL payload: %w", err)
		}
	}
	return json.Marshal(crlWire{
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: c.Signature,
	})
}

func (c *CRL) UnmarshalJSON(data []byte) error {
	var wire crlWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	payload, err := base64.RawURLEncoding.DecodeString(wire.Payload)
	if err != nil {
		return fmt.Errorf("decode CRL payload: %w", err)
	}
	if err := json.Unmarshal(payload, &c.Payload); err != nil {
		return fmt.Errorf("parse CRL payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	c.Signature = wire.Signature
	c.SHA256 = hex.EncodeToString(sum[:])
	c.payload = slices.Clone(payload)
	c.buildIndex()
	return nil
}

func ParseAndVerifyCRL(data []byte, publicKey ed25519.PublicKey, now time.Time) (CRL, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return CRL{}, errors.New("invalid public key")
	}
	if len(data) > maxCRLFileSize {
		return CRL{}, errors.New("license CRL exceeds maximum size")
	}
	var wire crlWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return CRL{}, fmt.Errorf("parse license CRL: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(wire.Payload)
	if err != nil {
		return CRL{}, fmt.Errorf("decode CRL payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(wire.Signature)
	if err != nil {
		return CRL{}, fmt.Errorf("decode CRL signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return CRL{}, errors.New("invalid CRL signature size")
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return CRL{}, errors.New("invalid CRL signature")
	}
	var payloadClaims CRLPayload
	if err := json.Unmarshal(payload, &payloadClaims); err != nil {
		return CRL{}, fmt.Errorf("parse CRL payload: %w", err)
	}
	if err := validateCRLPayload(payloadClaims, now); err != nil {
		return CRL{}, err
	}
	sum := sha256.Sum256(payload)
	crl := CRL{
		Payload:   payloadClaims,
		Signature: wire.Signature,
		SHA256:    hex.EncodeToString(sum[:]),
		payload:   slices.Clone(payload),
	}
	crl.buildIndex()
	return crl, nil
}

func LoadAndVerifyCRL(path string, publicKey ed25519.PublicKey, now time.Time) (CRL, error) {
	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return CRL{}, fmt.Errorf("stat license CRL: %w", err)
	}
	if !info.Mode().IsRegular() {
		return CRL{}, errors.New("license CRL must be a regular file")
	}
	if info.Size() > maxCRLFileSize {
		return CRL{}, errors.New("license CRL exceeds maximum size")
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return CRL{}, fmt.Errorf("read license CRL: %w", err)
	}
	return ParseAndVerifyCRL(data, publicKey, now)
}

func (c CRL) RevocationFor(id string) (RevokedLicense, bool) {
	if c.index != nil {
		i, ok := c.index[id]
		if !ok || i < 0 || i >= len(c.Payload.Revoked) {
			return RevokedLicense{}, false
		}
		return c.Payload.Revoked[i], true
	}
	for _, revoked := range c.Payload.Revoked {
		if revoked.ID == id {
			return revoked, true
		}
	}
	return RevokedLicense{}, false
}

func (c CRL) CheckLicense(lic License) error {
	revoked, ok := c.RevocationFor(lic.ID)
	if !ok {
		return nil
	}
	if revoked.Reason == "" {
		return fmt.Errorf("%w: %s", ErrLicenseRevoked, lic.ID)
	}
	return fmt.Errorf("%w: %s (%s)", ErrLicenseRevoked, lic.ID, revoked.Reason)
}

// RevocationForIntermediate returns the revocation record for an intermediate
// serial, if present.
func (c CRL) RevocationForIntermediate(serial string) (RevokedIntermediate, bool) {
	if c.intIndex != nil {
		i, ok := c.intIndex[serial]
		if !ok || i < 0 || i >= len(c.Payload.RevokedIntermediates) {
			return RevokedIntermediate{}, false
		}
		return c.Payload.RevokedIntermediates[i], true
	}
	for _, revoked := range c.Payload.RevokedIntermediates {
		if revoked.Serial == serial {
			return revoked, true
		}
	}
	return RevokedIntermediate{}, false
}

// CheckIntermediate returns ErrIntermediateRevoked when the given intermediate
// serial is revoked. An empty serial is treated as revoked (fail closed): an
// intermediate with no serial cannot be tracked for rotation.
func (c CRL) CheckIntermediate(serial string) error {
	if serial == "" {
		return fmt.Errorf("%w: missing serial", ErrIntermediateRevoked)
	}
	revoked, ok := c.RevocationForIntermediate(serial)
	if !ok {
		return nil
	}
	if revoked.Reason == "" {
		return fmt.Errorf("%w: %s", ErrIntermediateRevoked, serial)
	}
	return fmt.Errorf("%w: %s (%s)", ErrIntermediateRevoked, serial, revoked.Reason)
}

func VerifyWithCRL(token string, publicKey ed25519.PublicKey, crl *CRL) (License, error) {
	lic, err := Verify(token, publicKey)
	if err != nil {
		return lic, err
	}
	if crl != nil {
		if err := crl.CheckLicense(lic); err != nil {
			return lic, err
		}
	}
	return lic, nil
}

func validateCRLPayload(payload CRLPayload, now time.Time) error {
	if payload.Version != CRLVersion {
		return fmt.Errorf("unsupported CRL version %d", payload.Version)
	}
	if payload.IssuedAt <= 0 {
		return errors.New("CRL missing issued_at")
	}
	if payload.ExpiresAt <= 0 {
		return errors.New("CRL missing expires_at")
	}
	if payload.ExpiresAt <= payload.IssuedAt {
		return errors.New("CRL expires_at must be after issued_at")
	}
	if now.Unix() > payload.ExpiresAt {
		return fmt.Errorf("license CRL expired on %s", time.Unix(payload.ExpiresAt, 0).UTC().Format(time.DateOnly))
	}
	ids := make([]string, 0, len(payload.Revoked))
	for _, revoked := range payload.Revoked {
		if revoked.ID == "" {
			return errors.New("CRL contains revoked license with empty id")
		}
		if revoked.RevokedAt <= 0 {
			return fmt.Errorf("CRL revocation %s missing revoked_at", revoked.ID)
		}
		ids = append(ids, revoked.ID)
	}
	slices.Sort(ids)
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return fmt.Errorf("CRL contains duplicate license id %s", ids[i])
		}
	}
	serials := make([]string, 0, len(payload.RevokedIntermediates))
	for _, revoked := range payload.RevokedIntermediates {
		if revoked.Serial == "" {
			return errors.New("CRL contains revoked intermediate with empty serial")
		}
		if revoked.RevokedAt <= 0 {
			return fmt.Errorf("CRL intermediate revocation %s missing revoked_at", revoked.Serial)
		}
		serials = append(serials, revoked.Serial)
	}
	slices.Sort(serials)
	for i := 1; i < len(serials); i++ {
		if serials[i] == serials[i-1] {
			return fmt.Errorf("CRL contains duplicate intermediate serial %s", serials[i])
		}
	}
	return nil
}

func (c *CRL) buildIndex() {
	c.index = make(map[string]int, len(c.Payload.Revoked))
	for i, revoked := range c.Payload.Revoked {
		c.index[revoked.ID] = i
	}
	c.intIndex = make(map[string]int, len(c.Payload.RevokedIntermediates))
	for i, revoked := range c.Payload.RevokedIntermediates {
		c.intIndex[revoked.Serial] = i
	}
}
