// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	OrchestratorDelegationFormat = "pipelock-playground-delegation/v1"
	delegationDomainSeparator    = "pipelock-playground-delegation-v1\x00"
)

var (
	lowerHex64Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lowerHex128Pattern = regexp.MustCompile(`^[0-9a-f]{128}$`)
	runNoncePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// OrchestratorDelegation authorizes one short-lived session signing key for
// exactly one playground run and immutable VM image. The stable root signs this
// object; the delegated private key signs the launch manifest.
//
// INVARIANT: fields stay map-free and declaration-ordered because SignedBytes
// is a public wire contract.
type OrchestratorDelegation struct {
	Format           string `json:"format"`
	RootKeyID        string `json:"root_key_id"`
	DelegationID     string `json:"delegation_id"`
	RunNonce         string `json:"run_nonce"`
	SessionPublicKey string `json:"session_public_key"`
	ImageDigest      string `json:"image_digest"`
	IssuedAtUnix     int64  `json:"issued_at_unix"`
	NotBeforeUnix    int64  `json:"not_before_unix"`
	ExpiresAtUnix    int64  `json:"expires_at_unix"`
	Signature        string `json:"signature,omitempty"`
}

// DelegationExpectations applies caller-known bounds without weakening the
// format's intrinsic validation. Zero values mean the caller has no additional
// expectation for that field.
type DelegationExpectations struct {
	RootKeyID   string
	RunNonce    string
	ImageDigest string
	MaxLifetime time.Duration
}

// RootKeyID returns the stable identifier for an Ed25519 root public key. It
// reuses the locked, cross-implementation signing.Fingerprint format rather than
// duplicating it, so the delegation root_key_id can never drift from the
// fingerprint the rest of pipelock (and the Python verifier) computes. A key of
// the wrong length has no canonical fingerprint; RootKeyID returns a sentinel
// that fails the root_key_id claim check rather than a plausible-looking digest.
func RootKeyID(pub ed25519.PublicKey) string {
	fp, err := signing.Fingerprint(pub)
	if err != nil {
		return "sha256:invalid"
	}
	return fp
}

// SignedBytes returns the exact domain-separated bytes signed by the root.
func (d OrchestratorDelegation) SignedBytes() []byte {
	d.Signature = ""
	b, _ := json.Marshal(d)
	return append([]byte(delegationDomainSeparator), b...)
}

// ParseOrchestratorDelegation strictly decodes and validates a delegation's
// structure and claims. It does NOT authenticate the root signature (it has no
// key to verify against); a returned delegation is well-formed, not trusted.
// Callers MUST pass the result to VerifyOrchestratorDelegation with the trusted
// root key before relying on any field.
func ParseOrchestratorDelegation(data []byte) (OrchestratorDelegation, error) {
	var d OrchestratorDelegation
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return OrchestratorDelegation{}, fmt.Errorf("%s is invalid JSON: %w", orchestratorDelegationFile, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return OrchestratorDelegation{}, fmt.Errorf("parse %s: %w", orchestratorDelegationFile, err)
	}
	if err := ensureDelegationJSONEOF(dec); err != nil {
		return OrchestratorDelegation{}, err
	}
	if err := ValidateOrchestratorDelegationClaims(d, DelegationExpectations{}); err != nil {
		return OrchestratorDelegation{}, err
	}
	if d.Signature == "" {
		return OrchestratorDelegation{}, fmt.Errorf("delegation signature is required")
	}
	return d, nil
}

func ensureDelegationJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("parse %s trailer: %w", orchestratorDelegationFile, err)
	}
	return fmt.Errorf("parse %s: multiple JSON values", orchestratorDelegationFile)
}

// ValidateOrchestratorDelegationClaims validates intrinsic field constraints
// plus any broker/verifier expectations supplied by the caller.
func ValidateOrchestratorDelegationClaims(d OrchestratorDelegation, want DelegationExpectations) error {
	if d.Format != OrchestratorDelegationFormat {
		return fmt.Errorf("delegation format %q, want %q", d.Format, OrchestratorDelegationFormat)
	}
	if !strings.HasPrefix(d.RootKeyID, "sha256:") || !lowerHex64Pattern.MatchString(strings.TrimPrefix(d.RootKeyID, "sha256:")) {
		return fmt.Errorf("delegation root_key_id is not canonical sha256")
	}
	if !lowerHex64Pattern.MatchString(d.DelegationID) {
		return fmt.Errorf("delegation_id must be 32-byte lowercase hex")
	}
	if !runNoncePattern.MatchString(d.RunNonce) {
		return fmt.Errorf("delegation run_nonce must be 1-128 URL-safe characters")
	}
	if !lowerHex64Pattern.MatchString(d.SessionPublicKey) {
		return fmt.Errorf("session_public_key must be 32-byte lowercase hex")
	}
	if !strings.HasPrefix(d.ImageDigest, "sha256:") || !lowerHex64Pattern.MatchString(strings.TrimPrefix(d.ImageDigest, "sha256:")) {
		return fmt.Errorf("image_digest must be canonical sha256")
	}
	if d.IssuedAtUnix <= 0 || d.NotBeforeUnix <= 0 || d.ExpiresAtUnix <= 0 {
		return fmt.Errorf("delegation timestamps must be positive Unix seconds")
	}
	if d.NotBeforeUnix > d.IssuedAtUnix {
		return fmt.Errorf("delegation not_before is after issued_at")
	}
	if d.IssuedAtUnix >= d.ExpiresAtUnix {
		return fmt.Errorf("delegation expires_at must be after issued_at")
	}
	if want.MaxLifetime > 0 {
		maxSeconds := int64(want.MaxLifetime / time.Second)
		if want.MaxLifetime%time.Second != 0 {
			maxSeconds++
		}
		if d.ExpiresAtUnix-d.NotBeforeUnix > maxSeconds {
			return fmt.Errorf("delegation lifetime exceeds %s", want.MaxLifetime)
		}
	}
	if want.RootKeyID != "" && d.RootKeyID != want.RootKeyID {
		return fmt.Errorf("delegation root_key_id does not match expected root")
	}
	if want.RunNonce != "" && d.RunNonce != want.RunNonce {
		return fmt.Errorf("delegation run_nonce does not match expected run")
	}
	if want.ImageDigest != "" && d.ImageDigest != want.ImageDigest {
		return fmt.Errorf("delegation image_digest does not match expected image")
	}
	if d.Signature != "" && !lowerHex128Pattern.MatchString(d.Signature) {
		return fmt.Errorf("delegation signature must be 64-byte lowercase hex")
	}
	return nil
}

// SignOrchestratorDelegation signs a validated delegation with the root key.
func SignOrchestratorDelegation(priv ed25519.PrivateKey, d OrchestratorDelegation) (OrchestratorDelegation, error) {
	if err := signing.ValidatePrivateKeyConsistency(priv); err != nil {
		return OrchestratorDelegation{}, fmt.Errorf("delegation root key: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := ValidateOrchestratorDelegationClaims(d, DelegationExpectations{RootKeyID: RootKeyID(pub)}); err != nil {
		return OrchestratorDelegation{}, err
	}
	d.Signature = hex.EncodeToString(ed25519.Sign(priv, d.SignedBytes()))
	return d, nil
}

// VerifyOrchestratorDelegation verifies claims and the root signature.
func VerifyOrchestratorDelegation(pub ed25519.PublicKey, d OrchestratorDelegation, want DelegationExpectations) error {
	return verifyOrchestratorDelegationAt(pub, d, want, time.Now().UTC())
}

func verifyOrchestratorDelegationAt(pub ed25519.PublicKey, d OrchestratorDelegation, want DelegationExpectations, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("delegation root public key has wrong size")
	}
	want.RootKeyID = RootKeyID(pub)
	if err := ValidateOrchestratorDelegationClaims(d, want); err != nil {
		return err
	}
	sig, err := hex.DecodeString(d.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, d.SignedBytes(), sig) {
		return fmt.Errorf("delegation signature invalid under root key")
	}
	nowUnix := now.Unix()
	if nowUnix < d.NotBeforeUnix {
		return fmt.Errorf("delegation is not valid yet")
	}
	if nowUnix >= d.ExpiresAtUnix {
		return fmt.Errorf("delegation has expired")
	}
	return nil
}

// DelegationBindsLaunchManifest reports whether a delegated manifest repeats
// the exact run, delegation, and immutable image authorized by the root.
func DelegationBindsLaunchManifest(d OrchestratorDelegation, lm LaunchManifest) bool {
	return d.RunNonce != "" &&
		d.DelegationID != "" &&
		d.ImageDigest != "" &&
		lm.RunNonce == d.RunNonce &&
		lm.DelegationID == d.DelegationID &&
		lm.ImageDigest == d.ImageDigest
}
