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
	ErrKeyringParity     = errors.New("release keyring parity check failed")
)

// KeyringPreflightResult reports whether a candidate binary's embedded release
// keyring satisfies the parity contract required before an RC can be used to
// prove self-update.
type KeyringPreflightResult struct {
	// KeyCount is the number of valid Ed25519 public keys parsed from the
	// candidate keyring. Zero means the keyring was empty or unset.
	KeyCount int

	// CustomBuild is true when the caller explicitly acknowledged that the
	// binary is an unofficial/custom build and opted into out-of-band
	// verification. The preflight still validates keyring format when a
	// keyring is present, but does not require a non-empty keyring.
	CustomBuild bool
}

// CheckKeyringPreflight validates that candidateKeyringHex is non-empty and
// contains only well-formed Ed25519 public keys. When expectKeyringHex is
// non-empty the candidate must match it exactly (order-sensitive).
//
// For legitimately unofficial/custom builds where the keyring is intentionally
// absent, pass customBuild=true. The preflight will succeed with an empty
// keyring ONLY in that mode, and the caller is responsible for out-of-band
// verification. A non-empty but malformed keyring always fails regardless of
// customBuild.
//
// Failure direction: empty, malformed, mismatched, or any ambiguity fails
// closed. An unknown state is never a passing state.
func CheckKeyringPreflight(candidateKeyringHex, expectKeyringHex string, customBuild bool) (KeyringPreflightResult, error) {
	candidateKeyringHex = strings.TrimSpace(candidateKeyringHex)

	// Empty keyring: fail unless explicitly custom-build-acknowledged.
	//
	// The acknowledgement waives the REQUIREMENT for a keyring, never a parity
	// check that the caller explicitly asked for. When an expected keyring is
	// supplied, an empty candidate cannot match it, so returning success here
	// would answer "yes, parity holds" to a question whose answer is plainly
	// no. Custom-build is an admission that this binary has no keyring, not a
	// claim that it has the right one.
	if candidateKeyringHex == "" {
		if customBuild && strings.TrimSpace(expectKeyringHex) == "" {
			return KeyringPreflightResult{KeyCount: 0, CustomBuild: true}, nil
		}
		if customBuild {
			return KeyringPreflightResult{}, fmt.Errorf(
				"%w: candidate binary has no embedded release keyring, so it cannot "+
					"match the expected keyring; a custom build waives the keyring "+
					"requirement, not a parity check",
				ErrKeyringParity)
		}
		return KeyringPreflightResult{}, fmt.Errorf(
			"%w: candidate binary has no embedded release keyring; "+
				"official RC builds must embed the release keyring via ldflags",
			ErrKeyringParity)
	}

	// Parse and validate every key in the candidate keyring.
	candidateKeys, err := parseKeyring(candidateKeyringHex)
	if err != nil {
		return KeyringPreflightResult{}, fmt.Errorf(
			"%w: candidate keyring is malformed: %w", ErrKeyringParity, err)
	}

	result := KeyringPreflightResult{
		KeyCount:    len(candidateKeys),
		CustomBuild: customBuild,
	}

	// When an expected keyring is provided, require exact parity.
	expectKeyringHex = strings.TrimSpace(expectKeyringHex)
	if expectKeyringHex != "" {
		expectKeys, err := parseKeyring(expectKeyringHex)
		if err != nil {
			return KeyringPreflightResult{}, fmt.Errorf(
				"%w: expected keyring is malformed: %w", ErrKeyringParity, err)
		}
		if len(candidateKeys) != len(expectKeys) {
			return KeyringPreflightResult{}, fmt.Errorf(
				"%w: keyring length mismatch: candidate has %d keys, expected %d",
				ErrKeyringParity, len(candidateKeys), len(expectKeys))
		}
		for i := range candidateKeys {
			if hex.EncodeToString(candidateKeys[i]) != hex.EncodeToString(expectKeys[i]) {
				return KeyringPreflightResult{}, fmt.Errorf(
					"%w: key %d mismatch: candidate=%s expected=%s",
					ErrKeyringParity, i,
					hex.EncodeToString(candidateKeys[i]),
					hex.EncodeToString(expectKeys[i]))
			}
		}
	}

	return result, nil
}

// EmbeddedKeyringPreflight is a convenience that runs CheckKeyringPreflight
// against the process's own PublicKeyringHex. It is the one-call gate for
// release tooling to verify whether this binary has a real keyring.
func EmbeddedKeyringPreflight(expectKeyringHex string, customBuild bool) (KeyringPreflightResult, error) {
	return CheckKeyringPreflight(PublicKeyringHex, expectKeyringHex, customBuild)
}

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
