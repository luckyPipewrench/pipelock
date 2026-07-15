// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package release verifies Pipelock release manifests with the embedded
// Ed25519 release keyring.
package release

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	ManifestFile    = "release.json"
	ManifestSigFile = "release.json.sig"

	manifestSignaturePrefix = "ed25519:"
	signingDomain           = "Pipelock release manifest signature v1\n"
)

// PublicKeyringHex is set at build time via ldflags. Official releases embed
// one or more comma-separated raw Ed25519 public keys encoded as 64 hex chars.
var PublicKeyringHex string

var (
	ErrNoReleaseKey      = errors.New("release verification keyring is empty")
	ErrReleaseSignature  = errors.New("release manifest signature verification failed")
	ErrReleaseManifest   = errors.New("release manifest invalid")
	ErrReleaseAsset      = errors.New("release manifest asset invalid")
	ErrReleaseTrustInput = errors.New("release trust input invalid")
)

type Manifest struct {
	Schema             string  `json:"schema"`
	Repo               string  `json:"repo"`
	Tag                string  `json:"tag"`
	Commit             string  `json:"commit"`
	CreatedUTC         string  `json:"created_utc"`
	ChecksumFileSHA256 string  `json:"checksum_file_sha256"`
	Assets             []Asset `json:"assets"`
	SignerKeyID        string  `json:"signer_key_id"`
}

type Asset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Binary string `json:"binary"`
}

type Verification struct {
	Manifest       Manifest
	SignerKeyHex   string
	SignerKeyIndex int
}

func VerifyManifest(data, sig []byte, keyringHex string) (Verification, error) {
	keys, err := parseKeyring(keyringHex)
	if err != nil {
		return Verification{}, err
	}
	rawSig, err := parseSignature(sig)
	if err != nil {
		return Verification{}, err
	}
	preimage := append([]byte(signingDomain), data...)
	for i, key := range keys {
		if ed25519.Verify(key, preimage, rawSig) {
			manifest, err := ParseManifest(data)
			if err != nil {
				return Verification{}, err
			}
			// Bind the verifying key to the manifest's declared signer_key_id
			// (the signer's public key hex, set at sign time). Accepting any
			// trusted key that validates the signature would let a manifest claim
			// it was signed by key A while actually signed by key B during a
			// keyring rotation, weakening release custody/audit. Require the key
			// that produced the signature to be the one the manifest names.
			if !strings.EqualFold(hex.EncodeToString(key), strings.TrimSpace(manifest.SignerKeyID)) {
				return Verification{}, fmt.Errorf("%w: signature verified by a key not matching manifest signer_key_id", ErrReleaseSignature)
			}
			return Verification{
				Manifest:       manifest,
				SignerKeyHex:   hex.EncodeToString(key),
				SignerKeyIndex: i,
			}, nil
		}
	}
	return Verification{}, ErrReleaseSignature
}

func SignManifest(data []byte, priv ed25519.PrivateKey) string {
	preimage := append([]byte(signingDomain), data...)
	return manifestSignaturePrefix + hex.EncodeToString(ed25519.Sign(priv, preimage))
}

func FindAsset(m Manifest, name, goos, goarch, binary string) (Asset, error) {
	for _, asset := range m.Assets {
		if asset.Name == name {
			if asset.GOOS != goos || asset.GOARCH != goarch || asset.Binary != binary {
				return Asset{}, fmt.Errorf("%w: %s metadata mismatch", ErrReleaseAsset, name)
			}
			if !isSHA256Hex(asset.SHA256) {
				return Asset{}, fmt.Errorf("%w: %s has invalid sha256", ErrReleaseAsset, name)
			}
			return asset, nil
		}
	}
	return Asset{}, fmt.Errorf("%w: missing %s", ErrReleaseAsset, name)
}

func ValidateManifest(m Manifest) error {
	if m.Schema != "pipelock-release-v1" {
		return fmt.Errorf("%w: unsupported schema %q", ErrReleaseManifest, m.Schema)
	}
	if m.Repo != "github.com/luckyPipewrench/pipelock" {
		return fmt.Errorf("%w: repo %q", ErrReleaseManifest, m.Repo)
	}
	if strings.TrimSpace(m.Tag) == "" {
		return fmt.Errorf("%w: tag is required", ErrReleaseManifest)
	}
	if strings.TrimSpace(m.Commit) == "" {
		return fmt.Errorf("%w: commit is required", ErrReleaseManifest)
	}
	if strings.TrimSpace(m.SignerKeyID) == "" {
		return fmt.Errorf("%w: signer_key_id is required", ErrReleaseManifest)
	}
	if !isSHA256Hex(m.ChecksumFileSHA256) {
		return fmt.Errorf("%w: checksum_file_sha256 is invalid", ErrReleaseManifest)
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedUTC); err != nil {
		return fmt.Errorf("%w: created_utc: %w", ErrReleaseManifest, err)
	}
	if len(m.Assets) == 0 {
		return fmt.Errorf("%w: no assets", ErrReleaseManifest)
	}
	seen := make(map[string]struct{}, len(m.Assets))
	for _, asset := range m.Assets {
		if strings.TrimSpace(asset.Name) == "" {
			return fmt.Errorf("%w: asset name is required", ErrReleaseManifest)
		}
		if _, ok := seen[asset.Name]; ok {
			return fmt.Errorf("%w: duplicate asset %q", ErrReleaseManifest, asset.Name)
		}
		seen[asset.Name] = struct{}{}
		if !isSHA256Hex(asset.SHA256) {
			return fmt.Errorf("%w: asset %q sha256 is invalid", ErrReleaseManifest, asset.Name)
		}
		if strings.TrimSpace(asset.GOOS) == "" || strings.TrimSpace(asset.GOARCH) == "" || strings.TrimSpace(asset.Binary) == "" {
			return fmt.Errorf("%w: asset %q platform metadata is incomplete", ErrReleaseManifest, asset.Name)
		}
	}
	return nil
}

// ParseManifest decodes an unsigned or signed release manifest using the same
// unambiguous JSON and schema contract enforced during signature verification.
func ParseManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrReleaseManifest, err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrReleaseManifest, err)
	}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func parseKeyring(keyringHex string) ([]ed25519.PublicKey, error) {
	keyringHex = strings.TrimSpace(keyringHex)
	if keyringHex == "" {
		return nil, ErrNoReleaseKey
	}
	parts := strings.Split(keyringHex, ",")
	keys := make([]ed25519.PublicKey, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		raw, err := hex.DecodeString(part)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: malformed release public key", ErrReleaseTrustInput)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

func parseSignature(sig []byte) ([]byte, error) {
	text := strings.TrimSpace(string(sig))
	if !strings.HasPrefix(text, manifestSignaturePrefix) {
		return nil, fmt.Errorf("%w: missing %s prefix", ErrReleaseSignature, manifestSignaturePrefix)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(text, manifestSignaturePrefix))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: malformed signature", ErrReleaseSignature)
	}
	return raw, nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
