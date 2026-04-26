// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrCompileManifestSchemaVersion rejects CompileManifests with unsupported schema versions.
var ErrCompileManifestSchemaVersion = errors.New("unsupported compile_manifest schema_version; expected 1")

// ErrModuleDigestRootMismatch rejects CompileManifests whose module_digest_root
// does not match the value derived from module_digests.
var ErrModuleDigestRootMismatch = errors.New("module_digest_root does not match computed value")

// ErrCompileSettingsDisallowedKey rejects compile settings that include a key outside
// the documented allowlist. See design doc R2 "Compile settings allowlist".
var ErrCompileSettingsDisallowedKey = errors.New("compile manifest: disallowed key in settings")

// allowedTopLevelSettings is the closed set of top-level keys permitted in
// CompileManifest.Settings.
var allowedTopLevelSettings = map[string]bool{
	"confidence":    true,
	"normalization": true,
	"shadow":        true,
	"drift":         true,
	"privacy":       true,
	"redaction":     true,
}

// allowedPrivacySettings is the closed set of privacy.* sub-keys.
var allowedPrivacySettings = map[string]bool{
	"default_data_class":                  true,
	"forbid_classes":                      true,
	"require_explicit_opt_in_for_classes": true,
}

// allowedRedactionSettings is the closed set of redaction.* sub-keys.
var allowedRedactionSettings = map[string]bool{
	"public_allowlist": true,
	"salt_hash":        true,
}

// allowedSaltHashSettings is the closed set of redaction.salt_hash.* sub-keys.
var allowedSaltHashSettings = map[string]bool{
	"private_suffixes":          true,
	"private_cidrs":             true,
	"private_mcp_name_patterns": true,
	"salt_epoch":                true,
}

// validateSettingsAllowlist walks the Settings tree and rejects any key not in
// the documented allowlist for its position in the hierarchy.
func validateSettingsAllowlist(settings map[string]any) error {
	for k, v := range settings {
		if !allowedTopLevelSettings[k] {
			return fmt.Errorf("%w: %q at top level", ErrCompileSettingsDisallowedKey, k)
		}
		switch k {
		case "privacy":
			sub, ok := v.(map[string]any)
			if !ok {
				continue
			}
			for sk := range sub {
				if !allowedPrivacySettings[sk] {
					return fmt.Errorf("%w: %q under privacy", ErrCompileSettingsDisallowedKey, sk)
				}
			}
		case "redaction":
			sub, ok := v.(map[string]any)
			if !ok {
				continue
			}
			for sk, sv := range sub {
				if !allowedRedactionSettings[sk] {
					return fmt.Errorf("%w: %q under redaction", ErrCompileSettingsDisallowedKey, sk)
				}
				if sk == "salt_hash" {
					sh, ok := sv.(map[string]any)
					if !ok {
						continue
					}
					for shk := range sh {
						if !allowedSaltHashSettings[shk] {
							return fmt.Errorf("%w: %q under redaction.salt_hash", ErrCompileSettingsDisallowedKey, shk)
						}
					}
				}
			}
		}
	}
	return nil
}

// schemaVersionCompileManifest is the current CompileManifest schema version.
const schemaVersionCompileManifest = 1

// InputRef is a single observed input file bound into the compile manifest.
type InputRef struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	EventCount uint64 `json:"event_count"`
}

// CompileManifest is the typed signable body of a compile-provenance manifest.
// It binds build toolchain, module integrity, and observation-window evidence
// into a single JCS-canonicalized structure.
type CompileManifest struct {
	SchemaVersion         int               `json:"schema_version"`
	ContractHash          string            `json:"contract_hash"`
	CompileStartedAt      time.Time         `json:"compile_started_at"`
	CompileFinishedAt     time.Time         `json:"compile_finished_at"`
	PipelockVersion       string            `json:"pipelock_version"`
	PipelockBuildSHA      string            `json:"pipelock_build_sha"`
	GoVersion             string            `json:"go_version"`
	ModuleDigestRoot      string            `json:"module_digest_root"`
	ModuleDigests         map[string]string `json:"module_digests"`
	CompileConfigHash     string            `json:"compile_config_hash"`
	Inputs                []InputRef        `json:"inputs"`
	ObservationWindowRoot string            `json:"observation_window_root"`
	Settings              map[string]any    `json:"settings,omitempty"`
	SignerKeyID           string            `json:"signer_key_id"`
	KeyPurpose            string            `json:"key_purpose"`
}

// CompileManifestEnvelope wraps a CompileManifest body with its detached signature.
type CompileManifestEnvelope struct {
	Body      CompileManifest `json:"body"`
	Signature string          `json:"signature"`
}

// SignablePreimage returns JCS bytes over the manifest body.
// The signature is detached (stored in CompileManifestEnvelope.Signature).
func (m CompileManifest) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal compile manifest: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse compile manifest for canonicalization: %w", err)
	}
	return Canonicalize(tree)
}

// ComputeModuleDigestRoot derives the canonical module_digest_root from m.ModuleDigests.
// Recipe: sha256(jcs(module_digests)). Map keys are sorted by JCS (lexicographic codepoint)
// so the result is insertion-order-invariant.
func (m CompileManifest) ComputeModuleDigestRoot() (string, error) {
	raw, err := json.Marshal(m.ModuleDigests)
	if err != nil {
		return "", fmt.Errorf("marshal module_digests: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return "", fmt.Errorf("parse module_digests for canonicalization: %w", err)
	}
	canon, err := Canonicalize(tree)
	if err != nil {
		return "", fmt.Errorf("canonicalize module_digests: %w", err)
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Validate runs structural checks on the CompileManifest.
// Cryptographic signature verification is in verify.go.
func (m CompileManifest) Validate() error {
	if m.SchemaVersion != schemaVersionCompileManifest {
		return fmt.Errorf("%w: got %d", ErrCompileManifestSchemaVersion, m.SchemaVersion)
	}
	computed, err := m.ComputeModuleDigestRoot()
	if err != nil {
		return fmt.Errorf("compute module_digest_root: %w", err)
	}
	if m.ModuleDigestRoot != computed {
		return fmt.Errorf("%w: stored %q, computed %q", ErrModuleDigestRootMismatch, m.ModuleDigestRoot, computed)
	}
	if err := validateSettingsAllowlist(m.Settings); err != nil {
		return err
	}
	return nil
}
