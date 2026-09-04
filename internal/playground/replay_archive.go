// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	ReplayArchiveAuthorizationFormat = "pipelock-playground-replay-archive/v1"
	replayArchiveAuthorizationFile   = "replay-archive-authorization.json"
	replayArchiveDomainSeparator     = "pipelock-playground-replay-archive-v1\x00"
)

// ReplayArchiveAuthorization is a root-signed, durable authorization for one
// sealed delegated run. It authorizes no signing key and cannot start or extend
// a live session.
type ReplayArchiveAuthorization struct {
	Format               string `json:"format"`
	RootKeyID            string `json:"root_key_id"`
	RunNonce             string `json:"run_nonce"`
	ImageDigest          string `json:"image_digest"`
	LaunchManifestHash   string `json:"launch_manifest_hash"`
	DelegationArtifactID string `json:"delegation_artifact_id"`
	Signature            string `json:"signature,omitempty"`
}

func (a ReplayArchiveAuthorization) SignedBytes() []byte {
	a.Signature = ""
	b, _ := json.Marshal(a)
	return append([]byte(replayArchiveDomainSeparator), b...)
}

func ParseReplayArchiveAuthorization(data []byte) (ReplayArchiveAuthorization, error) {
	var a ReplayArchiveAuthorization
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return ReplayArchiveAuthorization{}, fmt.Errorf("%s is invalid JSON: %w", replayArchiveAuthorizationFile, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return ReplayArchiveAuthorization{}, fmt.Errorf("parse %s: %w", replayArchiveAuthorizationFile, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return ReplayArchiveAuthorization{}, fmt.Errorf("parse %s: multiple JSON values", replayArchiveAuthorizationFile)
		}
		return ReplayArchiveAuthorization{}, fmt.Errorf("parse %s trailer: %w", replayArchiveAuthorizationFile, err)
	}
	if err := validateReplayArchiveAuthorization(a, ""); err != nil {
		return ReplayArchiveAuthorization{}, err
	}
	if a.Signature == "" {
		return ReplayArchiveAuthorization{}, fmt.Errorf("%s signature is required", replayArchiveAuthorizationFile)
	}
	return a, nil
}

// SignReplayArchiveAuthorization creates a durable authorization for the exact
// signed manifest and delegation artifact. The resulting authorization contains
// public evidence, never key material.
func SignReplayArchiveAuthorization(priv ed25519.PrivateKey, lm LaunchManifest, delegationBytes []byte) (ReplayArchiveAuthorization, error) {
	if err := signing.ValidatePrivateKeyConsistency(priv); err != nil {
		return ReplayArchiveAuthorization{}, fmt.Errorf("archive authorization root key: %w", err)
	}
	delegation, err := ParseOrchestratorDelegation(delegationBytes)
	if err != nil {
		return ReplayArchiveAuthorization{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := verifyOrchestratorDelegationSignature(pub, delegation, DelegationExpectations{RunNonce: lm.RunNonce, ImageDigest: lm.ImageDigest}); err != nil {
		return ReplayArchiveAuthorization{}, fmt.Errorf("archive authorization delegation: %w", err)
	}
	if !DelegationBindsLaunchManifest(delegation, lm) {
		return ReplayArchiveAuthorization{}, fmt.Errorf("archive authorization delegation does not bind launch manifest")
	}
	a := ReplayArchiveAuthorization{
		Format:               ReplayArchiveAuthorizationFormat,
		RootKeyID:            RootKeyID(pub),
		RunNonce:             lm.RunNonce,
		ImageDigest:          lm.ImageDigest,
		LaunchManifestHash:   lm.Hash(),
		DelegationArtifactID: replayArchiveArtifactID(delegationBytes),
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(priv, a.SignedBytes()))
	return a, nil
}

// VerifyReplayArchiveAuthorization authenticates the archive authorization
// under the caller-pinned root and binds it to these exact run artifacts. It
// intentionally performs no time check: it authorizes a record, not a live
// signing credential.
func VerifyReplayArchiveAuthorization(pub ed25519.PublicKey, a ReplayArchiveAuthorization, lm LaunchManifest, delegationBytes []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("archive authorization root public key has wrong size")
	}
	if err := validateReplayArchiveAuthorization(a, RootKeyID(pub)); err != nil {
		return err
	}
	if a.RunNonce != lm.RunNonce || a.ImageDigest != lm.ImageDigest || a.LaunchManifestHash != lm.Hash() || a.DelegationArtifactID != replayArchiveArtifactID(delegationBytes) {
		return fmt.Errorf("archive authorization does not bind these run artifacts")
	}
	sig, err := hex.DecodeString(a.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, a.SignedBytes(), sig) {
		return fmt.Errorf("archive authorization signature invalid under root key")
	}
	return nil
}

func validateReplayArchiveAuthorization(a ReplayArchiveAuthorization, wantRootKeyID string) error {
	if a.Format != ReplayArchiveAuthorizationFormat {
		return fmt.Errorf("archive authorization format %q, want %q", a.Format, ReplayArchiveAuthorizationFormat)
	}
	if !strings.HasPrefix(a.RootKeyID, "sha256:") || !lowerHex64Pattern.MatchString(strings.TrimPrefix(a.RootKeyID, "sha256:")) {
		return fmt.Errorf("archive authorization root_key_id is not canonical sha256")
	}
	if wantRootKeyID != "" && a.RootKeyID != wantRootKeyID {
		return fmt.Errorf("archive authorization root_key_id does not match expected root")
	}
	if !runNoncePattern.MatchString(a.RunNonce) {
		return fmt.Errorf("archive authorization run_nonce must be 1-128 URL-safe characters")
	}
	if err := ValidateCanonicalImageDigest(a.ImageDigest); err != nil {
		return fmt.Errorf("archive authorization %w", err)
	}
	if !lowerHex64Pattern.MatchString(a.LaunchManifestHash) {
		return fmt.Errorf("archive authorization launch_manifest_hash must be 32-byte lowercase hex")
	}
	if !strings.HasPrefix(a.DelegationArtifactID, "sha256:") || !lowerHex64Pattern.MatchString(strings.TrimPrefix(a.DelegationArtifactID, "sha256:")) {
		return fmt.Errorf("archive authorization delegation_artifact_id is not canonical sha256")
	}
	if a.Signature != "" && !lowerHex128Pattern.MatchString(a.Signature) {
		return fmt.Errorf("archive authorization signature must be 64-byte lowercase hex")
	}
	return nil
}

func replayArchiveArtifactID(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
