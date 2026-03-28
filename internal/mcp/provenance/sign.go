// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package provenance provides cryptographic attestation generation and
// verification for MCP tool definitions. It supports two signing modes:
// "pipelock" (offline Ed25519) and "sigstore" (keyless OIDC, future).
package provenance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// predicateType is the SLSA predicate type used in attestations.
const predicateType = "https://slsa.dev/provenance/v1"

// Signing mode constants.
const (
	ModePipelock = "pipelock"
	ModeSigstore = "sigstore"
)

// Attestation is a signed provenance record for a single tool definition.
// Embeddable in MCP tool _meta under the key "com.pipelock/provenance".
type Attestation struct {
	PredicateType string `json:"predicateType"`
	Digest        Digest `json:"digest"`
	Mode          string `json:"mode"`
	Bundle        string `json:"bundle"`
	SignerID      string `json:"signer_id"`
}

// Digest holds cryptographic hashes of a tool definition.
type Digest struct {
	SHA256 string `json:"sha256"`
}

// ToolDef is a tool definition to sign. Mirrors the MCP tools/list structure.
type ToolDef struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

// canonicalTool is the sorted-key struct used for deterministic hashing.
// Field order is alphabetical: description, inputSchema, name.
type canonicalTool struct {
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Name        string          `json:"name"`
}

// ToolDigest computes a canonical SHA-256 of a tool definition.
// The canonical form is JSON with sorted keys and no extraneous whitespace,
// making the digest format-independent. InputSchema is re-serialized through
// a round-trip to normalize whitespace and key ordering.
func ToolDigest(name, description string, inputSchema json.RawMessage) string {
	normalized := normalizeSchema(inputSchema)

	ct := canonicalTool{
		Description: description,
		InputSchema: normalized,
		Name:        name,
	}

	// json.Marshal produces sorted keys for structs (field order = declaration order,
	// which is alphabetical here). No indent = no extraneous whitespace.
	data, err := json.Marshal(ct)
	if err != nil {
		// Should never happen with string/RawMessage fields.
		// Return empty digest so verification always fails rather than panicking.
		return ""
	}

	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// normalizeSchema round-trips JSON through interface{} to normalize
// whitespace and produce sorted keys, making the digest format-independent.
func normalizeSchema(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage("null")
	}

	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		// If the schema is invalid JSON, use it as-is.
		// Verification will catch mismatches.
		return raw
	}

	normalized := sortAndMarshal(parsed)
	out, err := json.Marshal(normalized)
	if err != nil {
		return raw
	}
	return out
}

// sortAndMarshal recursively sorts map keys for deterministic JSON output.
func sortAndMarshal(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		sorted := make(map[string]interface{}, len(val))
		for k, inner := range val {
			sorted[k] = sortAndMarshal(inner)
		}
		return sorted
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, inner := range val {
			result[i] = sortAndMarshal(inner)
		}
		return result
	default:
		return v
	}
}

// SignPipelock signs tool definitions with an Ed25519 private key (offline, no network).
// keyID identifies the signing key (typically the encoded public key or a fingerprint).
// Returns one Attestation per tool.
func SignPipelock(tools []ToolDef, privKey ed25519.PrivateKey, keyID string) ([]Attestation, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key size")
	}

	attestations := make([]Attestation, 0, len(tools))
	for _, tool := range tools {
		digest := ToolDigest(tool.Name, tool.Description, tool.InputSchema)
		if digest == "" {
			return nil, fmt.Errorf("failed to compute digest for tool %q", tool.Name)
		}

		// Sign the hex-encoded digest bytes.
		sig := ed25519.Sign(privKey, []byte(digest))
		bundle := base64.StdEncoding.EncodeToString(sig)

		attestations = append(attestations, Attestation{
			PredicateType: predicateType,
			Digest:        Digest{SHA256: digest},
			Mode:          ModePipelock,
			Bundle:        bundle,
			SignerID:      keyID,
		})
	}

	return attestations, nil
}

// VerifyPipelock verifies a pipelock-mode attestation against an Ed25519 public key.
// Returns (true, nil) if the signature is valid, (false, nil) if invalid,
// or (false, error) if the attestation is malformed.
func VerifyPipelock(att Attestation, pubKey ed25519.PublicKey) (bool, error) {
	if att.Mode != ModePipelock {
		return false, fmt.Errorf("expected mode %q, got %q", ModePipelock, att.Mode)
	}

	sig, err := base64.StdEncoding.DecodeString(att.Bundle)
	if err != nil {
		return false, fmt.Errorf("decoding bundle: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid Ed25519 public key size")
	}

	return ed25519.Verify(pubKey, []byte(att.Digest.SHA256), sig), nil
}

// SignSigstore signs tool definitions via Sigstore keyless signing.
// This is a stub for future implementation. Returns "not implemented" error.
func SignSigstore(_ context.Context, _ []ToolDef, _ string) ([]Attestation, error) {
	return nil, errors.New("sigstore signing mode is not yet implemented")
}

// VerifySigstore verifies a sigstore-mode attestation.
// This is a stub for future implementation. Returns "not implemented" error.
func VerifySigstore(_ Attestation) (bool, error) {
	return false, errors.New("sigstore verification mode is not yet implemented")
}

// InjectMeta produces the _meta JSON for embedding attestations into a
// tools/list response. Each attestation is keyed by tool name.
// Output format: {"com.pipelock/provenance": attestation}.
func InjectMeta(att Attestation) json.RawMessage {
	wrapper := map[string]Attestation{
		metaKey: att,
	}
	data, err := json.Marshal(wrapper)
	if err != nil {
		return nil
	}
	return data
}

// EmbedInToolsList takes a raw tools/list JSON-RPC response and injects
// provenance attestations into each tool's _meta field. Tools are matched
// by name. Returns the modified response bytes.
func EmbedInToolsList(response []byte, attestations []Attestation) ([]byte, error) {
	// Parse the response to inject _meta.
	var rpc struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response, &rpc); err != nil {
		return nil, fmt.Errorf("parsing tools/list response: %w", err)
	}

	// Build digest->attestation index for matching tools by content hash.
	byDigest := make(map[string]Attestation, len(attestations))
	for _, att := range attestations {
		byDigest[att.Digest.SHA256] = att
	}

	modified := make([]json.RawMessage, 0, len(rpc.Result.Tools))
	for _, raw := range rpc.Result.Tools {
		// Parse tool to compute digest and find matching attestation.
		var td struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		}
		if err := json.Unmarshal(raw, &td); err != nil {
			// Unparseable tool entry: keep as-is.
			modified = append(modified, raw)
			continue
		}

		digest := ToolDigest(td.Name, td.Description, td.InputSchema)
		att, found := byDigest[digest]
		if !found {
			modified = append(modified, raw)
			continue
		}

		// Inject _meta into the tool object.
		var toolMap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &toolMap); err != nil {
			modified = append(modified, raw)
			continue
		}

		toolMap["_meta"] = InjectMeta(att)

		out, err := json.Marshal(toolMap)
		if err != nil {
			modified = append(modified, raw)
			continue
		}
		modified = append(modified, out)
	}

	rpc.Result.Tools = modified
	result, err := json.Marshal(rpc.Result)
	if err != nil {
		return nil, fmt.Errorf("marshaling modified result: %w", err)
	}

	// Reconstruct the full response, preserving the original jsonrpc value.
	output := map[string]json.RawMessage{
		"jsonrpc": mustMarshal(rpc.JSONRPC),
		"id":      rpc.ID,
		"result":  result,
	}
	return json.Marshal(output)
}

func mustMarshal(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// SortAttestations sorts attestations by digest for deterministic output.
func SortAttestations(atts []Attestation) {
	sort.Slice(atts, func(i, j int) bool {
		return atts[i].Digest.SHA256 < atts[j].Digest.SHA256
	})
}
