// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testToolName = "get_weather"
	testToolDesc = "Get weather"
)

func testSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}

func generateTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}
	return pub, priv
}

func TestToolDigest_Canonical(t *testing.T) {
	// Same tool, different JSON formatting -> same digest.
	d1 := ToolDigest(testToolName, testToolDesc, json.RawMessage(`{"type":"object"}`))
	d2 := ToolDigest(testToolName, testToolDesc, json.RawMessage(`{ "type" : "object" }`))
	if d1 != d2 {
		t.Errorf("canonical digest should be format-independent: %s != %s", d1, d2)
	}

	// Different tool -> different digest.
	d3 := ToolDigest("set_weather", testToolDesc, json.RawMessage(`{"type":"object"}`))
	if d1 == d3 {
		t.Error("different tools should have different digests")
	}
}

func TestToolDigest_SortedKeys(t *testing.T) {
	// Schema with keys in different order -> same digest.
	schema1 := json.RawMessage(`{"properties":{"city":{"type":"string"},"country":{"type":"string"}},"type":"object"}`)
	schema2 := json.RawMessage(`{"type":"object","properties":{"country":{"type":"string"},"city":{"type":"string"}}}`)

	d1 := ToolDigest(testToolName, testToolDesc, schema1)
	d2 := ToolDigest(testToolName, testToolDesc, schema2)
	if d1 != d2 {
		t.Errorf("key order should not affect digest: %s != %s", d1, d2)
	}
}

func TestToolDigest_NilSchema(t *testing.T) {
	// Nil schema -> consistent digest.
	d1 := ToolDigest(testToolName, testToolDesc, nil)
	d2 := ToolDigest(testToolName, testToolDesc, json.RawMessage("null"))
	if d1 != d2 {
		t.Errorf("nil and null schema should produce same digest: %s != %s", d1, d2)
	}
}

func TestToolDigest_EmptySchema(t *testing.T) {
	// Empty schema -> consistent digest.
	d1 := ToolDigest(testToolName, testToolDesc, json.RawMessage(""))
	d2 := ToolDigest(testToolName, testToolDesc, json.RawMessage("null"))
	if d1 != d2 {
		t.Errorf("empty and null schema should produce same digest: %s != %s", d1, d2)
	}
}

func TestToolDigest_NonEmpty(t *testing.T) {
	d := ToolDigest(testToolName, testToolDesc, testSchema())
	if d == "" {
		t.Error("digest should not be empty")
	}
	// SHA-256 hex is always 64 characters.
	if len(d) != 64 {
		t.Errorf("digest should be 64 hex chars, got %d", len(d))
	}
}

func TestToolDigest_DescriptionChange(t *testing.T) {
	d1 := ToolDigest(testToolName, "Get weather", testSchema())
	d2 := ToolDigest(testToolName, "Get the current weather", testSchema())
	if d1 == d2 {
		t.Error("different descriptions should produce different digests")
	}
}

func TestSignPipelock(t *testing.T) {
	pub, priv := generateTestKeys(t)

	tools := []ToolDef{
		{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()},
	}

	keyID := signing.EncodePublicKey(pub)
	attestations, err := SignPipelock(tools, priv, keyID)
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}
	if len(attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(attestations))
	}

	att := attestations[0]
	if att.Mode != ModePipelock {
		t.Errorf("expected mode %q, got %q", ModePipelock, att.Mode)
	}
	if att.Bundle == "" {
		t.Error("bundle should not be empty")
	}
	if att.Digest.SHA256 == "" {
		t.Error("digest should not be empty")
	}
	if att.SignerID != keyID {
		t.Errorf("signer_id should be %q, got %q", keyID, att.SignerID)
	}
	if att.PredicateType != predicateType {
		t.Errorf("predicateType should be %q, got %q", predicateType, att.PredicateType)
	}

	// Verify the attestation.
	ok, err := VerifyPipelock(att, pub)
	if err != nil {
		t.Fatalf("VerifyPipelock: %v", err)
	}
	if !ok {
		t.Error("verification should succeed for valid attestation")
	}
}

func TestSignPipelock_MultipleTools(t *testing.T) {
	_, priv := generateTestKeys(t)

	tools := []ToolDef{
		{Name: "tool_a", Description: "Tool A", InputSchema: testSchema()},
		{Name: "tool_b", Description: "Tool B", InputSchema: testSchema()},
		{Name: "tool_c", Description: "Tool C", InputSchema: json.RawMessage(`{"type":"string"}`)},
	}

	attestations, err := SignPipelock(tools, priv, "key-1")
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}
	if len(attestations) != 3 {
		t.Fatalf("expected 3 attestations, got %d", len(attestations))
	}

	// All should have unique digests.
	digests := make(map[string]bool)
	for _, att := range attestations {
		if digests[att.Digest.SHA256] {
			t.Errorf("duplicate digest: %s", att.Digest.SHA256)
		}
		digests[att.Digest.SHA256] = true
	}
}

func TestSignPipelock_InvalidKey(t *testing.T) {
	_, err := SignPipelock(
		[]ToolDef{{Name: "t", Description: "d", InputSchema: testSchema()}},
		ed25519.PrivateKey([]byte("short")),
		"key-1",
	)
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestVerifyPipelock_WrongKey(t *testing.T) {
	_, priv1 := generateTestKeys(t)
	pub2, _ := generateTestKeys(t)

	tools := []ToolDef{
		{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()},
	}

	attestations, err := SignPipelock(tools, priv1, "key-1")
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	ok, err := VerifyPipelock(attestations[0], pub2)
	if err != nil {
		t.Fatalf("VerifyPipelock: %v", err)
	}
	if ok {
		t.Error("verification should fail with wrong key")
	}
}

func TestVerifyPipelock_WrongMode(t *testing.T) {
	pub, _ := generateTestKeys(t)

	att := Attestation{
		Mode:   ModeSigstore,
		Bundle: "irrelevant",
		Digest: Digest{SHA256: "abc"},
	}

	_, err := VerifyPipelock(att, pub)
	if err == nil {
		t.Error("expected error for wrong mode")
	}
}

func TestVerifyPipelock_InvalidBundle(t *testing.T) {
	pub, _ := generateTestKeys(t)

	att := Attestation{
		Mode:   ModePipelock,
		Bundle: "not-base64!@#$",
		Digest: Digest{SHA256: "abc"},
	}

	_, err := VerifyPipelock(att, pub)
	if err == nil {
		t.Error("expected error for invalid bundle")
	}
}

func TestVerifyPipelock_ShortSignature(t *testing.T) {
	pub, _ := generateTestKeys(t)

	att := Attestation{
		Mode:   ModePipelock,
		Bundle: "AQID", // 3 bytes, too short for Ed25519.
		Digest: Digest{SHA256: "abc"},
	}

	_, err := VerifyPipelock(att, pub)
	if err == nil {
		t.Error("expected error for short signature")
	}
}

func TestVerifyPipelock_InvalidPubKey(t *testing.T) {
	_, priv := generateTestKeys(t)

	tools := []ToolDef{
		{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()},
	}

	attestations, err := SignPipelock(tools, priv, "key-1")
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	_, err = VerifyPipelock(attestations[0], ed25519.PublicKey([]byte("short")))
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

func TestSignSigstore_NotImplemented(t *testing.T) {
	_, err := SignSigstore(t.Context(), nil, "")
	if err == nil {
		t.Error("expected not-implemented error")
	}
}

func TestVerifySigstore_NotImplemented(t *testing.T) {
	_, err := VerifySigstore(Attestation{})
	if err == nil {
		t.Error("expected not-implemented error")
	}
}

func TestInjectMeta(t *testing.T) {
	att := Attestation{
		PredicateType: predicateType,
		Digest:        Digest{SHA256: "abc123"},
		Mode:          ModePipelock,
		Bundle:        "sig-data",
		SignerID:      "key-1",
	}

	meta := InjectMeta(att)
	if meta == nil {
		t.Fatal("InjectMeta returned nil")
	}

	var parsed map[string]Attestation
	if err := json.Unmarshal(meta, &parsed); err != nil {
		t.Fatalf("parsing meta: %v", err)
	}

	got, exists := parsed[metaKey]
	if !exists {
		t.Fatal("expected provenance key in meta")
	}
	if got.Digest.SHA256 != "abc123" {
		t.Errorf("expected digest abc123, got %s", got.Digest.SHA256)
	}
}

func TestSortAttestations(t *testing.T) {
	atts := []Attestation{
		{Digest: Digest{SHA256: "zzz"}},
		{Digest: Digest{SHA256: "aaa"}},
		{Digest: Digest{SHA256: "mmm"}},
	}

	SortAttestations(atts)

	if atts[0].Digest.SHA256 != "aaa" || atts[1].Digest.SHA256 != "mmm" || atts[2].Digest.SHA256 != "zzz" {
		t.Errorf("attestations not sorted: %v", atts)
	}
}

func TestEmbedInToolsList(t *testing.T) {
	pub, priv := generateTestKeys(t)

	tools := []ToolDef{
		{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()},
	}

	attestations, err := SignPipelock(tools, priv, signing.EncodePublicKey(pub))
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"}}]}}`)

	modified, err := EmbedInToolsList(response, attestations)
	if err != nil {
		t.Fatalf("EmbedInToolsList: %v", err)
	}

	// Verify the modified response contains _meta.
	var rpc struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(modified, &rpc); err != nil {
		t.Fatalf("parsing modified response: %v", err)
	}

	if len(rpc.Result.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(rpc.Result.Tools))
	}

	var tool map[string]json.RawMessage
	if err := json.Unmarshal(rpc.Result.Tools[0], &tool); err != nil {
		t.Fatalf("parsing tool: %v", err)
	}

	metaRaw, exists := tool["_meta"]
	if !exists {
		t.Fatal("expected _meta in tool")
	}

	var meta map[string]Attestation
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("parsing _meta: %v", err)
	}

	att, exists := meta[metaKey]
	if !exists {
		t.Fatal("expected provenance key in _meta")
	}

	// Verify the embedded attestation is valid.
	ok, err := VerifyPipelock(att, pub)
	if err != nil {
		t.Fatalf("VerifyPipelock: %v", err)
	}
	if !ok {
		t.Error("embedded attestation should verify successfully")
	}
}

func TestEmbedInToolsList_InvalidJSON(t *testing.T) {
	_, err := EmbedInToolsList([]byte("not-json"), nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestEmbedInToolsList_NoMatchingTool(t *testing.T) {
	// Attestation for a different tool than what's in the response.
	_, priv := generateTestKeys(t)

	attestations, err := SignPipelock(
		[]ToolDef{{Name: "other_tool", Description: "Other", InputSchema: testSchema()}},
		priv, "key-1",
	)
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"}}]}}`)

	modified, err := EmbedInToolsList(response, attestations)
	if err != nil {
		t.Fatalf("EmbedInToolsList: %v", err)
	}

	// Tool should remain unmodified (no _meta).
	var rpc struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(modified, &rpc); err != nil {
		t.Fatalf("parsing modified response: %v", err)
	}

	var tool map[string]json.RawMessage
	if err := json.Unmarshal(rpc.Result.Tools[0], &tool); err != nil {
		t.Fatalf("parsing tool: %v", err)
	}

	if _, exists := tool["_meta"]; exists {
		t.Error("unmatched tool should not have _meta injected")
	}
}

func TestToolDigest_ArraySchema(t *testing.T) {
	// Schema containing arrays -- exercises sortAndMarshal array branch.
	schema := json.RawMessage(`{"type":"object","required":["city","country"],"properties":{"city":{"type":"string"}}}`)
	d := ToolDigest(testToolName, testToolDesc, schema)
	if d == "" {
		t.Error("digest should not be empty for array-containing schema")
	}
	if len(d) != 64 {
		t.Errorf("digest should be 64 hex chars, got %d", len(d))
	}
}

func TestToolDigest_NestedArraySchema(t *testing.T) {
	// Deeply nested schema with arrays and objects.
	schema := json.RawMessage(`{"type":"object","properties":{"tags":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"}}}}}}`)
	d := ToolDigest(testToolName, testToolDesc, schema)
	if d == "" {
		t.Error("digest should not be empty for nested schema")
	}
}

func TestToolDigest_InvalidJSON(t *testing.T) {
	// Invalid JSON schema cannot be marshaled, so digest is empty (fail-closed).
	// This means verification always fails for tools with invalid schemas,
	// which is the correct security posture.
	d := ToolDigest(testToolName, testToolDesc, json.RawMessage(`{invalid`))
	if d != "" {
		t.Errorf("digest should be empty for invalid JSON schema, got %s", d)
	}
}

func TestEmbedInToolsList_EmptyTools(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	modified, err := EmbedInToolsList(response, nil)
	if err != nil {
		t.Fatalf("EmbedInToolsList with empty tools: %v", err)
	}
	if modified == nil {
		t.Error("modified response should not be nil")
	}
}

func TestEmbedInToolsList_MalformedToolJSON(t *testing.T) {
	// A tool entry that is valid JSON but cannot be parsed as a tool object.
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":["not-an-object"]}}`)
	_, priv := generateTestKeys(t)
	attestations, err := SignPipelock(
		[]ToolDef{{Name: "x", Description: "y", InputSchema: testSchema()}},
		priv, "key-1",
	)
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	// Should not panic, just skip the malformed tool.
	modified, err := EmbedInToolsList(response, attestations)
	if err != nil {
		t.Fatalf("EmbedInToolsList: %v", err)
	}
	if modified == nil {
		t.Error("modified response should not be nil")
	}
}
