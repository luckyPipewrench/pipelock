// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// metaKey is the _meta key under which provenance attestations are stored.
const metaKey = "com.pipelock/provenance"

// ToolAttestation pairs a tool name with its extracted attestation.
type ToolAttestation struct {
	ToolName    string
	Attestation Attestation
}

// VerificationResult describes the outcome of verifying a single tool's provenance.
type VerificationResult struct {
	ToolName string `json:"tool_name"`
	Status   string `json:"status"` // "verified", "unsigned", "failed", "error"
	Detail   string `json:"detail,omitempty"`
}

// Verification status constants.
const (
	StatusVerified = "verified"
	StatusUnsigned = "unsigned"
	StatusFailed   = "failed"
	StatusError    = "error"
)

// toolWithMeta is a minimal tool representation that includes _meta.
type toolWithMeta struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	InputSchema json.RawMessage            `json:"inputSchema"`
	Meta        map[string]json.RawMessage `json:"_meta,omitempty"`
}

// toolsListResult wraps the tools array from a tools/list response.
type toolsListResult struct {
	Tools []json.RawMessage `json:"tools"`
}

// ExtractFromToolsList parses a tools/list JSON-RPC response and extracts
// provenance attestations from each tool's _meta field.
// Returns attestations found (may be empty). Tools without _meta or without
// the provenance key are not included.
func ExtractFromToolsList(response []byte) []ToolAttestation {
	var rpc struct {
		Result toolsListResult `json:"result"`
	}
	if err := json.Unmarshal(response, &rpc); err != nil {
		return nil
	}

	var results []ToolAttestation
	for _, raw := range rpc.Result.Tools {
		var tool toolWithMeta
		if err := json.Unmarshal(raw, &tool); err != nil {
			continue
		}

		if tool.Meta == nil {
			continue
		}

		provRaw, exists := tool.Meta[metaKey]
		if !exists {
			continue
		}

		var att Attestation
		if err := json.Unmarshal(provRaw, &att); err != nil {
			continue
		}

		results = append(results, ToolAttestation{
			ToolName:    tool.Name,
			Attestation: att,
		})
	}

	return results
}

// VerifyConfig holds verification parameters.
type VerifyConfig struct {
	// TrustedKeys maps key IDs to Ed25519 public keys (pipelock mode).
	TrustedKeys map[string]ed25519.PublicKey

	// Mode restricts which attestation modes are accepted.
	// "pipelock" = Ed25519 only, "sigstore" = keyless OIDC only, "any" = either.
	Mode string

	// OfflineOnly prevents network calls for sigstore verification (default true).
	OfflineOnly bool
}

// VerifyTool verifies a single tool's provenance attestation against the tool
// definition and trusted keys. Returns a VerificationResult describing the outcome.
//
// The digest is recomputed from the tool definition and compared against the
// attestation's digest to detect tampering of tool content.
func VerifyTool(tool ToolDef, att Attestation, cfg VerifyConfig) VerificationResult {
	result := VerificationResult{ToolName: tool.Name}

	// Check mode is accepted.
	if cfg.Mode != "" && cfg.Mode != "any" && att.Mode != cfg.Mode {
		result.Status = StatusError
		result.Detail = fmt.Sprintf("attestation mode %q not accepted (want %q)", att.Mode, cfg.Mode)
		return result
	}

	// Recompute digest from the tool definition.
	expectedDigest := ToolDigest(tool.Name, tool.Description, tool.InputSchema)
	if expectedDigest != att.Digest.SHA256 {
		result.Status = StatusFailed
		result.Detail = fmt.Sprintf("digest mismatch: computed %s, attestation has %s", expectedDigest, att.Digest.SHA256)
		return result
	}

	switch att.Mode {
	case ModePipelock:
		return verifyPipelockTool(tool, att, cfg)
	case ModeSigstore:
		if cfg.OfflineOnly {
			result.Status = StatusError
			result.Detail = "sigstore verification requires network but offline_only is true"
			return result
		}
		result.Status = StatusError
		result.Detail = "sigstore verification not yet implemented"
		return result
	default:
		result.Status = StatusError
		result.Detail = fmt.Sprintf("unknown attestation mode: %q", att.Mode)
		return result
	}
}

// verifyPipelockTool verifies an Ed25519-signed attestation.
func verifyPipelockTool(tool ToolDef, att Attestation, cfg VerifyConfig) VerificationResult {
	result := VerificationResult{ToolName: tool.Name}

	if len(cfg.TrustedKeys) == 0 {
		result.Status = StatusError
		result.Detail = "no trusted keys configured for pipelock mode"
		return result
	}

	// Try all trusted keys. The signer_id hints which key to use,
	// but we verify against all as a fallback for key rotation.
	pubKey, found := cfg.TrustedKeys[att.SignerID]
	if found {
		ok, err := VerifyPipelock(att, pubKey)
		if err != nil {
			result.Status = StatusError
			result.Detail = fmt.Sprintf("verification error: %v", err)
			return result
		}
		if ok {
			result.Status = StatusVerified
			return result
		}
	}

	// Fallback: try all keys (supports key rotation where signer_id
	// may reference an old key format).
	for keyID, key := range cfg.TrustedKeys {
		if keyID == att.SignerID {
			continue // Already tried above.
		}
		ok, err := VerifyPipelock(att, key)
		if err != nil {
			continue
		}
		if ok {
			result.Status = StatusVerified
			return result
		}
	}

	result.Status = StatusFailed
	result.Detail = "signature does not match any trusted key"
	return result
}

// VerifyToolsList verifies all tools in a tools/list response.
// For each tool, it either finds and verifies an attestation, or reports
// the tool as unsigned.
//
// Response behavior by status:
//   - StatusVerified: tool has valid provenance
//   - StatusUnsigned: tool has no _meta or no provenance key
//   - StatusFailed: attestation present but verification failed (ALWAYS BLOCK)
//   - StatusError: attestation malformed or misconfigured
func VerifyToolsList(response []byte, cfg VerifyConfig) ([]VerificationResult, error) {
	var rpc struct {
		Result toolsListResult `json:"result"`
	}
	if err := json.Unmarshal(response, &rpc); err != nil {
		return nil, fmt.Errorf("parsing tools/list response: %w", err)
	}

	// Extract attestations indexed by tool name.
	attestations := ExtractFromToolsList(response)
	attByName := make(map[string]Attestation, len(attestations))
	for _, ta := range attestations {
		attByName[ta.ToolName] = ta.Attestation
	}

	var results []VerificationResult
	for _, raw := range rpc.Result.Tools {
		var tool toolWithMeta
		if err := json.Unmarshal(raw, &tool); err != nil {
			results = append(results, VerificationResult{
				ToolName: "<unparseable>",
				Status:   StatusError,
				Detail:   fmt.Sprintf("failed to parse tool: %v", err),
			})
			continue
		}

		att, hasAtt := attByName[tool.Name]
		if !hasAtt {
			// Distinguish: _meta present but no provenance key vs no _meta at all.
			detail := "no _meta field present"
			if tool.Meta != nil {
				if _, hasKey := tool.Meta[metaKey]; !hasKey {
					detail = "_meta present but no provenance key"
				}
			}
			results = append(results, VerificationResult{
				ToolName: tool.Name,
				Status:   StatusUnsigned,
				Detail:   detail,
			})
			continue
		}

		td := ToolDef{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
		}
		results = append(results, VerifyTool(td, att, cfg))
	}

	return results, nil
}

// ErrFailedVerification is returned when an attestation is present but invalid.
// This always results in blocking regardless of the configured action.
var ErrFailedVerification = errors.New("provenance verification failed")

// ErrUnsigned is returned when a tool has no provenance attestation.
// The configured action determines whether this is blocked or warned.
var ErrUnsigned = errors.New("tool has no provenance attestation")

// ShouldBlock determines whether verification results warrant blocking the
// tools/list response. actionOnUnsigned is the configured action for missing
// provenance ("block", "warn", "allow").
//
// Rules:
//   - Any StatusFailed -> always block (tampering detected)
//   - Any StatusError -> always block (fail-closed)
//   - StatusUnsigned + actionOnUnsigned=="block" -> block
//   - StatusUnsigned + actionOnUnsigned=="warn" -> don't block (caller should log)
//   - StatusUnsigned + actionOnUnsigned=="allow" -> don't block
func ShouldBlock(results []VerificationResult, actionOnUnsigned string) (bool, error) {
	for _, r := range results {
		switch r.Status {
		case StatusFailed:
			return true, fmt.Errorf("%w: tool %q: %s", ErrFailedVerification, r.ToolName, r.Detail)
		case StatusError:
			return true, fmt.Errorf("provenance error for tool %q: %s", r.ToolName, r.Detail)
		case StatusUnsigned:
			if actionOnUnsigned == "block" {
				return true, fmt.Errorf("%w: tool %q: %s", ErrUnsigned, r.ToolName, r.Detail)
			}
		case StatusVerified:
			// OK.
		}
	}
	return false, nil
}

// HasAnyUnsigned returns true if any result is unsigned. Used for logging
// in warn mode even when not blocking.
func HasAnyUnsigned(results []VerificationResult) bool {
	for _, r := range results {
		if r.Status == StatusUnsigned {
			return true
		}
	}
	return false
}
