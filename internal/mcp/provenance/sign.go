// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package provenance provides cryptographic attestation generation and
// verification for MCP tool definitions. It signs the canonical tool object
// with the embedded Pipelock provenance _meta member removed, so extension
// fields and non-provenance _meta members are covered by the attestation. It
// supports two signing modes: "pipelock" (offline Ed25519) and "sigstore"
// (keyless OIDC, future).
package provenance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// ExtraFields carries additional MCP tool-definition fields that should be
	// covered by the attestation, such as annotations, title, outputSchema, or
	// non-provenance _meta members.
	ExtraFields map[string]json.RawMessage
}

// ToolDigest computes a canonical SHA-256 of a core tool definition.
// The canonical form is JSON with sorted keys and no extraneous whitespace,
// making the digest format-independent. InputSchema is re-serialized through
// a round-trip to normalize whitespace and key ordering. Use ToolDef.ExtraFields
// with SignPipelock to include additional MCP tool-definition fields.
func ToolDigest(name, description string, inputSchema json.RawMessage) string {
	return toolDigest(ToolDef{
		Name:        name,
		Description: description,
		InputSchema: inputSchema,
	})
}

// ToolDigestRaw computes the same canonical SHA-256 that provenance verification
// uses for a raw MCP tool object. The digest covers the full tool object with
// only Pipelock's embedded provenance _meta member removed.
func ToolDigestRaw(raw json.RawMessage) string {
	return toolDigestRaw(raw)
}

func toolDigest(tool ToolDef) string {
	fields := map[string]json.RawMessage{
		"name":        mustMarshal(tool.Name),
		"description": mustMarshal(tool.Description),
		"inputSchema": normalizeSchema(tool.InputSchema),
	}
	for key, value := range tool.ExtraFields {
		if key == "name" || key == "description" || key == "inputSchema" {
			continue
		}
		fields[key] = value
	}
	return digestToolFields(fields)
}

func toolDigestRaw(raw json.RawMessage) string {
	fields, ok := toolFieldsRaw(raw)
	if !ok {
		return ""
	}
	return digestToolFields(fields)
}

func toolFieldsRaw(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false
	}
	if fields == nil {
		return nil, false
	}
	if _, ok := fields["name"]; !ok {
		fields["name"] = mustMarshal("")
	}
	if _, ok := fields["description"]; !ok {
		fields["description"] = mustMarshal("")
	}
	if _, ok := fields["inputSchema"]; !ok {
		fields["inputSchema"] = json.RawMessage("null")
	}
	return fields, true
}

func canonicalToolFieldsRaw(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	fields, ok := toolFieldsRaw(raw)
	if !ok {
		return nil, false
	}
	canonical := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		canonical[key] = normalizeJSON(value)
	}
	return canonical, true
}

func digestToolFields(fields map[string]json.RawMessage) string {
	canonical := make(map[string]json.RawMessage, len(fields))
	for key, raw := range fields {
		if key == "_meta" {
			stripped, keep := stripProvenanceMeta(raw)
			if !keep {
				continue
			}
			raw = stripped
		}

		normalized := normalizeJSON(raw)
		if !json.Valid(normalized) {
			return ""
		}
		canonical[key] = normalized
	}

	data, err := json.Marshal(canonical)
	if err != nil {
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
	return normalizeJSON(raw)
}

func normalizeJSON(raw json.RawMessage) json.RawMessage {
	var parsed interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return raw
	}
	if err := dec.Decode(new(interface{})); err != io.EOF {
		return raw
	}

	normalized := sortAndMarshal(parsed)
	out, err := json.Marshal(normalized)
	if err != nil {
		return raw
	}
	return out
}

func stripProvenanceMeta(raw json.RawMessage) (json.RawMessage, bool) {
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(raw, &meta); err != nil {
		return raw, true
	}
	delete(meta, metaKey)
	if len(meta) == 0 {
		return nil, false
	}
	out, err := json.Marshal(meta)
	if err != nil {
		return raw, true
	}
	return out, true
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

// provenanceSigContext domain-separates pipelock-mode signatures. The signed
// bytes are this context string followed by the tool digest, so a signature
// produced here can never be replayed as evidence in another context that
// signs a SHA-256 hex string with the same key (the JWT-style cross-protocol
// reuse problem). The ":" delimiter is unambiguous because the digest is hex.
// The "/v1" segment versions the scheme for future agility.
const provenanceSigContext = "pipelock/provenance/v1:"

// pipelockSigningInput returns the domain-separated bytes signed and verified
// for a pipelock-mode attestation over the given tool digest.
func pipelockSigningInput(digest string) []byte {
	return []byte(provenanceSigContext + digest)
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
		digest := toolDigest(tool)
		if digest == "" {
			return nil, fmt.Errorf("failed to compute digest for tool %q", tool.Name)
		}

		// Sign the domain-separated digest (context-bound, see provenanceSigContext).
		sig := ed25519.Sign(privKey, pipelockSigningInput(digest))
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

	return ed25519.Verify(pubKey, pipelockSigningInput(att.Digest.SHA256), sig), nil
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
		digest := toolDigestRaw(raw)
		att, found := byDigest[digest]
		if !found {
			modified = append(modified, raw)
			continue
		}

		// Inject _meta into the tool object.
		toolMap, ok := canonicalToolFieldsRaw(raw)
		if !ok {
			modified = append(modified, raw)
			continue
		}

		toolMap["_meta"] = injectMeta(toolMap["_meta"], att)

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

func injectMeta(existing json.RawMessage, att Attestation) json.RawMessage {
	meta := make(map[string]json.RawMessage)
	if len(existing) > 0 && string(existing) != "null" {
		if err := json.Unmarshal(existing, &meta); err != nil {
			return existing
		}
	}
	attRaw, err := json.Marshal(att)
	if err != nil {
		return existing
	}
	meta[metaKey] = attRaw
	out, err := json.Marshal(meta)
	if err != nil {
		return existing
	}
	return out
}

// SortAttestations sorts attestations by digest for deterministic output.
func SortAttestations(atts []Attestation) {
	sort.Slice(atts, func(i, j int) bool {
		return atts[i].Digest.SHA256 < atts[j].Digest.SHA256
	})
}
