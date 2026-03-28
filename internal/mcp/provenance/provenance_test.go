// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestExtractFromToolsList(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"},
		 "_meta":{"com.pipelock/provenance":{"predicateType":"https://slsa.dev/provenance/v1",
		 "digest":{"sha256":"abc123"},"mode":"pipelock","bundle":"base64sig","signer_id":"keyid"}}}
	]}}`)

	extraction := ExtractFromToolsList(response)
	if len(extraction.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(extraction.Attestations))
	}

	ta := extraction.Attestations[0]
	if ta.ToolName != testToolName {
		t.Errorf("expected tool name %q, got %q", testToolName, ta.ToolName)
	}
	if ta.Attestation.Mode != ModePipelock {
		t.Errorf("expected mode %q, got %q", ModePipelock, ta.Attestation.Mode)
	}
	if ta.Attestation.Digest.SHA256 != "abc123" {
		t.Errorf("expected digest abc123, got %s", ta.Attestation.Digest.SHA256)
	}
}

func TestExtractFromToolsList_NoMeta(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"}}
	]}}`)

	extraction := ExtractFromToolsList(response)
	if len(extraction.Attestations) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(extraction.Attestations))
	}
}

func TestExtractFromToolsList_MetaWithoutProvenance(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"},
		 "_meta":{"other_key":"value"}}
	]}}`)

	extraction := ExtractFromToolsList(response)
	if len(extraction.Attestations) != 0 {
		t.Errorf("expected 0 attestations for _meta without provenance key, got %d", len(extraction.Attestations))
	}
}

func TestExtractFromToolsList_InvalidJSON(t *testing.T) {
	extraction := ExtractFromToolsList([]byte("not-json"))
	if len(extraction.Attestations) != 0 || len(extraction.Malformed) != 0 {
		t.Error("expected empty result for invalid JSON")
	}
}

func TestExtractFromToolsList_InvalidProvenance(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"},
		 "_meta":{"com.pipelock/provenance":"not-an-object"}}
	]}}`)

	extraction := ExtractFromToolsList(response)
	if len(extraction.Attestations) != 0 {
		t.Errorf("expected 0 attestations for invalid provenance, got %d", len(extraction.Attestations))
	}
	if len(extraction.Malformed) != 1 {
		t.Errorf("expected 1 malformed entry for invalid provenance, got %d", len(extraction.Malformed))
	}
}

func TestExtractFromToolsList_MultipleTools(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		{"name":"tool_a","description":"A","inputSchema":{"type":"object"},
		 "_meta":{"com.pipelock/provenance":{"predicateType":"p","digest":{"sha256":"d1"},"mode":"pipelock","bundle":"b1","signer_id":"k1"}}},
		{"name":"tool_b","description":"B","inputSchema":{"type":"object"}},
		{"name":"tool_c","description":"C","inputSchema":{"type":"object"},
		 "_meta":{"com.pipelock/provenance":{"predicateType":"p","digest":{"sha256":"d2"},"mode":"pipelock","bundle":"b2","signer_id":"k2"}}}
	]}}`)

	extraction := ExtractFromToolsList(response)
	if len(extraction.Attestations) != 2 {
		t.Fatalf("expected 2 attestations, got %d", len(extraction.Attestations))
	}

	if extraction.Attestations[0].ToolName != "tool_a" {
		t.Errorf("first tool should be tool_a, got %s", extraction.Attestations[0].ToolName)
	}
	if extraction.Attestations[1].ToolName != "tool_c" {
		t.Errorf("second tool should be tool_c, got %s", extraction.Attestations[1].ToolName)
	}
}

func TestVerifyTool_PipelockMode(t *testing.T) {
	pub, priv := generateTestKeys(t)

	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	attestations, err := SignPipelock([]ToolDef{tool}, priv, signing.EncodePublicKey(pub))
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{
			signing.EncodePublicKey(pub): pub,
		},
		Mode: ModePipelock,
	}

	result := VerifyTool(tool, attestations[0], cfg)
	if result.Status != StatusVerified {
		t.Errorf("expected %q, got %q: %s", StatusVerified, result.Status, result.Detail)
	}
}

func TestVerifyTool_DigestMismatch(t *testing.T) {
	pub, priv := generateTestKeys(t)

	originalTool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	attestations, err := SignPipelock([]ToolDef{originalTool}, priv, signing.EncodePublicKey(pub))
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	// Tamper with the tool description.
	tamperedTool := ToolDef{Name: testToolName, Description: "EXECUTE EVIL STUFF", InputSchema: testSchema()}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{
			signing.EncodePublicKey(pub): pub,
		},
		Mode: ModePipelock,
	}

	result := VerifyTool(tamperedTool, attestations[0], cfg)
	if result.Status != StatusFailed {
		t.Errorf("expected %q for tampered tool, got %q: %s", StatusFailed, result.Status, result.Detail)
	}
}

func TestVerifyTool_WrongKey(t *testing.T) {
	_, priv1 := generateTestKeys(t)
	pub2, _ := generateTestKeys(t)

	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	attestations, err := SignPipelock([]ToolDef{tool}, priv1, "key-1")
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{
			"key-2": pub2,
		},
		Mode: ModePipelock,
	}

	result := VerifyTool(tool, attestations[0], cfg)
	if result.Status != StatusFailed {
		t.Errorf("expected %q for wrong key, got %q: %s", StatusFailed, result.Status, result.Detail)
	}
}

func TestVerifyTool_KeyRotation(t *testing.T) {
	// Attestation signed with key-1, but trusted keys include key-1 under a different ID.
	pub1, priv1 := generateTestKeys(t)

	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	attestations, err := SignPipelock([]ToolDef{tool}, priv1, "old-key-id")
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	// Trust the same key under a new ID (simulates key rotation with same key).
	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{
			"new-key-id": pub1,
		},
		Mode: ModePipelock,
	}

	result := VerifyTool(tool, attestations[0], cfg)
	if result.Status != StatusVerified {
		t.Errorf("expected %q for rotated key, got %q: %s", StatusVerified, result.Status, result.Detail)
	}
}

func TestVerifyTool_WrongMode(t *testing.T) {
	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	att := Attestation{
		Mode:   ModeSigstore,
		Digest: Digest{SHA256: ToolDigest(testToolName, testToolDesc, testSchema())},
	}

	cfg := VerifyConfig{Mode: ModePipelock}

	result := VerifyTool(tool, att, cfg)
	if result.Status != StatusError {
		t.Errorf("expected %q for wrong mode, got %q: %s", StatusError, result.Status, result.Detail)
	}
}

func TestVerifyTool_NoTrustedKeys(t *testing.T) {
	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	att := Attestation{
		Mode:   ModePipelock,
		Digest: Digest{SHA256: ToolDigest(testToolName, testToolDesc, testSchema())},
		Bundle: "irrelevant",
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{},
		Mode:        ModePipelock,
	}

	result := VerifyTool(tool, att, cfg)
	if result.Status != StatusError {
		t.Errorf("expected %q for no trusted keys, got %q: %s", StatusError, result.Status, result.Detail)
	}
}

func TestVerifyTool_SigstoreOffline(t *testing.T) {
	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	att := Attestation{
		Mode:   ModeSigstore,
		Digest: Digest{SHA256: ToolDigest(testToolName, testToolDesc, testSchema())},
	}

	cfg := VerifyConfig{
		Mode:        "any",
		OfflineOnly: true,
	}

	result := VerifyTool(tool, att, cfg)
	if result.Status != StatusError {
		t.Errorf("expected %q for sigstore+offline, got %q: %s", StatusError, result.Status, result.Detail)
	}
}

func TestVerifyTool_UnknownMode(t *testing.T) {
	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	att := Attestation{
		Mode:   "unknown",
		Digest: Digest{SHA256: ToolDigest(testToolName, testToolDesc, testSchema())},
	}

	cfg := VerifyConfig{Mode: "any"}

	result := VerifyTool(tool, att, cfg)
	if result.Status != StatusError {
		t.Errorf("expected %q for unknown mode, got %q: %s", StatusError, result.Status, result.Detail)
	}
}

func TestVerifyToolsList_EndToEnd(t *testing.T) {
	pub, priv := generateTestKeys(t)
	keyID := signing.EncodePublicKey(pub)

	tools := []ToolDef{
		{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()},
	}

	attestations, err := SignPipelock(tools, priv, keyID)
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	// Build a tools/list response with embedded attestations.
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"}}]}}`)
	modified, err := EmbedInToolsList(response, attestations)
	if err != nil {
		t.Fatalf("EmbedInToolsList: %v", err)
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{keyID: pub},
		Mode:        ModePipelock,
	}

	results, err := VerifyToolsList(modified, cfg)
	if err != nil {
		t.Fatalf("VerifyToolsList: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusVerified {
		t.Errorf("expected %q, got %q: %s", StatusVerified, results[0].Status, results[0].Detail)
	}
}

func TestVerifyToolsList_UnsignedTool(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"}}
	]}}`)

	cfg := VerifyConfig{Mode: ModePipelock}

	results, err := VerifyToolsList(response, cfg)
	if err != nil {
		t.Fatalf("VerifyToolsList: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusUnsigned {
		t.Errorf("expected %q, got %q: %s", StatusUnsigned, results[0].Status, results[0].Detail)
	}
	if results[0].Detail != "no _meta field present" {
		t.Errorf("unexpected detail: %s", results[0].Detail)
	}
}

func TestVerifyToolsList_MetaWithoutProvenance(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"},
		 "_meta":{"other_key":"value"}}
	]}}`)

	cfg := VerifyConfig{Mode: ModePipelock}

	results, err := VerifyToolsList(response, cfg)
	if err != nil {
		t.Fatalf("VerifyToolsList: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusUnsigned {
		t.Errorf("expected %q, got %q", StatusUnsigned, results[0].Status)
	}
	if results[0].Detail != "_meta present but no provenance key" {
		t.Errorf("expected distinguishing detail, got: %s", results[0].Detail)
	}
}

func TestVerifyToolsList_InvalidJSON(t *testing.T) {
	cfg := VerifyConfig{Mode: ModePipelock}
	_, err := VerifyToolsList([]byte("not-json"), cfg)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestVerifyToolsList_MixedSignedUnsigned(t *testing.T) {
	pub, priv := generateTestKeys(t)
	keyID := signing.EncodePublicKey(pub)

	// Sign only tool_a, leave tool_b unsigned.
	attestations, err := SignPipelock(
		[]ToolDef{{Name: "tool_a", Description: "A", InputSchema: testSchema()}},
		priv, keyID,
	)
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
		{"name":"tool_a","description":"A","inputSchema":{"type":"object"}},
		{"name":"tool_b","description":"B","inputSchema":{"type":"object"}}
	]}}`)

	modified, err := EmbedInToolsList(response, attestations)
	if err != nil {
		t.Fatalf("EmbedInToolsList: %v", err)
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{keyID: pub},
		Mode:        ModePipelock,
	}

	results, err := VerifyToolsList(modified, cfg)
	if err != nil {
		t.Fatalf("VerifyToolsList: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Find results by tool name.
	statusByName := make(map[string]string)
	for _, r := range results {
		statusByName[r.ToolName] = r.Status
	}

	if statusByName["tool_a"] != StatusVerified {
		t.Errorf("tool_a should be verified, got %s", statusByName["tool_a"])
	}
	if statusByName["tool_b"] != StatusUnsigned {
		t.Errorf("tool_b should be unsigned, got %s", statusByName["tool_b"])
	}
}

func TestShouldBlock_FailedAlwaysBlocks(t *testing.T) {
	results := []VerificationResult{
		{ToolName: "tool_a", Status: StatusVerified},
		{ToolName: "tool_b", Status: StatusFailed, Detail: "tampered"},
	}

	// Even with action=allow, failed verification blocks.
	block, err := ShouldBlock(results, "allow")
	if !block {
		t.Error("failed verification should always block")
	}
	if !errors.Is(err, ErrFailedVerification) {
		t.Errorf("expected ErrFailedVerification, got: %v", err)
	}
}

func TestShouldBlock_ErrorAlwaysBlocks(t *testing.T) {
	results := []VerificationResult{
		{ToolName: "tool_a", Status: StatusError, Detail: "malformed"},
	}

	block, err := ShouldBlock(results, "allow")
	if !block {
		t.Error("error status should always block")
	}
	if err == nil {
		t.Error("expected error")
	}
}

func TestShouldBlock_UnsignedBlockMode(t *testing.T) {
	results := []VerificationResult{
		{ToolName: "tool_a", Status: StatusUnsigned, Detail: "no _meta"},
	}

	block, err := ShouldBlock(results, "block")
	if !block {
		t.Error("unsigned in block mode should block")
	}
	if !errors.Is(err, ErrUnsigned) {
		t.Errorf("expected ErrUnsigned, got: %v", err)
	}
}

func TestShouldBlock_UnsignedWarnMode(t *testing.T) {
	results := []VerificationResult{
		{ToolName: "tool_a", Status: StatusUnsigned, Detail: "no _meta"},
	}

	block, _ := ShouldBlock(results, "warn")
	if block {
		t.Error("unsigned in warn mode should not block")
	}
}

func TestShouldBlock_UnsignedAllowMode(t *testing.T) {
	results := []VerificationResult{
		{ToolName: "tool_a", Status: StatusUnsigned, Detail: "no _meta"},
	}

	block, _ := ShouldBlock(results, "allow")
	if block {
		t.Error("unsigned in allow mode should not block")
	}
}

func TestShouldBlock_AllVerified(t *testing.T) {
	results := []VerificationResult{
		{ToolName: "tool_a", Status: StatusVerified},
		{ToolName: "tool_b", Status: StatusVerified},
	}

	block, _ := ShouldBlock(results, "block")
	if block {
		t.Error("all verified should not block")
	}
}

func TestHasAnyUnsigned(t *testing.T) {
	tests := []struct {
		name    string
		results []VerificationResult
		want    bool
	}{
		{
			name:    "all verified",
			results: []VerificationResult{{Status: StatusVerified}},
			want:    false,
		},
		{
			name:    "one unsigned",
			results: []VerificationResult{{Status: StatusVerified}, {Status: StatusUnsigned}},
			want:    true,
		},
		{
			name:    "empty",
			results: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasAnyUnsigned(tt.results)
			if got != tt.want {
				t.Errorf("HasAnyUnsigned = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyTool_SigstoreNotOffline(t *testing.T) {
	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	att := Attestation{
		Mode:   ModeSigstore,
		Digest: Digest{SHA256: ToolDigest(testToolName, testToolDesc, testSchema())},
	}

	// offline_only=false, but sigstore not implemented.
	cfg := VerifyConfig{
		Mode:        "any",
		OfflineOnly: false,
	}

	result := VerifyTool(tool, att, cfg)
	if result.Status != StatusError {
		t.Errorf("expected %q for unimplemented sigstore, got %q: %s", StatusError, result.Status, result.Detail)
	}
}

func TestVerifyTool_InvalidBundleInPipelockMode(t *testing.T) {
	pub, _ := generateTestKeys(t)

	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	att := Attestation{
		Mode:     ModePipelock,
		Digest:   Digest{SHA256: ToolDigest(testToolName, testToolDesc, testSchema())},
		Bundle:   "not-valid-base64!@#",
		SignerID: signing.EncodePublicKey(pub),
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{
			signing.EncodePublicKey(pub): pub,
		},
		Mode: ModePipelock,
	}

	result := VerifyTool(tool, att, cfg)
	if result.Status != StatusError {
		t.Errorf("expected %q for invalid bundle, got %q: %s", StatusError, result.Status, result.Detail)
	}
}

func TestVerifyToolsList_TamperedAttestation(t *testing.T) {
	pub, priv := generateTestKeys(t)
	keyID := signing.EncodePublicKey(pub)

	tools := []ToolDef{
		{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()},
	}

	attestations, err := SignPipelock(tools, priv, keyID)
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	// Embed valid attestation, then tamper with the tool description in the response.
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather","description":"Get weather","inputSchema":{"type":"object"}}]}}`)
	modified, err := EmbedInToolsList(response, attestations)
	if err != nil {
		t.Fatalf("EmbedInToolsList: %v", err)
	}

	// Tamper: change the description in the response.
	var rpc map[string]json.RawMessage
	if err := json.Unmarshal(modified, &rpc); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Tools []map[string]json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(rpc["result"], &result); err != nil {
		t.Fatal(err)
	}
	result.Tools[0]["description"] = json.RawMessage(`"EVIL INSTRUCTIONS"`)
	newResult, _ := json.Marshal(result)
	rpc["result"] = newResult
	tampered, _ := json.Marshal(rpc)

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{keyID: pub},
		Mode:        ModePipelock,
	}

	results, err := VerifyToolsList(tampered, cfg)
	if err != nil {
		t.Fatalf("VerifyToolsList: %v", err)
	}

	// The attestation's digest won't match the tampered tool's computed digest.
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Because the tool description changed, the attestation extracted by name
	// still exists, but the digest computed from the tampered tool won't match.
	// This should result in a failed verification or unsigned (depending on
	// whether the attestation was found by name match).
	status := results[0].Status
	if status != StatusFailed && status != StatusUnsigned {
		t.Errorf("tampered tool should be failed or unsigned, got %q: %s", status, results[0].Detail)
	}
}

func TestVerifyToolsList_UnparseableTool(t *testing.T) {
	// A tool that is not a valid JSON object.
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[42]}}`)

	cfg := VerifyConfig{Mode: ModePipelock}

	results, err := VerifyToolsList(response, cfg)
	if err != nil {
		t.Fatalf("VerifyToolsList: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusError {
		t.Errorf("expected %q for unparseable tool, got %q: %s", StatusError, results[0].Status, results[0].Detail)
	}
}

func TestExtractFromToolsList_InvalidToolInArray(t *testing.T) {
	// Valid JSON-RPC but tool entries that aren't objects.
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":["not-a-tool-object", 42]}}`)

	extraction := ExtractFromToolsList(response)
	if len(extraction.Attestations) != 0 {
		t.Errorf("expected 0 attestations for invalid tool entries, got %d", len(extraction.Attestations))
	}
}

func TestVerifyTool_ModeAny(t *testing.T) {
	// mode="any" should accept pipelock attestations.
	pub, priv := generateTestKeys(t)

	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	attestations, err := SignPipelock([]ToolDef{tool}, priv, signing.EncodePublicKey(pub))
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{
			signing.EncodePublicKey(pub): pub,
		},
		Mode: "any",
	}

	result := VerifyTool(tool, attestations[0], cfg)
	if result.Status != StatusVerified {
		t.Errorf("expected %q with mode=any, got %q: %s", StatusVerified, result.Status, result.Detail)
	}
}

func TestVerifyTool_FallbackKeyVerifyError(t *testing.T) {
	// Signer ID doesn't match any trusted key. Bundle is valid base64 but
	// wrong signature length, causing VerifyPipelock to return an error
	// for the fallback key, exercising the continue-on-error path.
	pub, _ := generateTestKeys(t)

	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	att := Attestation{
		Mode:     ModePipelock,
		Digest:   Digest{SHA256: ToolDigest(testToolName, testToolDesc, testSchema())},
		Bundle:   "AQID", // 3 bytes: valid base64 but wrong signature length.
		SignerID: "nonexistent-key",
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{
			"other-key": pub,
		},
		Mode: ModePipelock,
	}

	result := VerifyTool(tool, att, cfg)
	// The fallback loop tries pub, gets an error (wrong sig size), continues,
	// then falls through to "signature does not match any trusted key".
	if result.Status != StatusFailed {
		t.Errorf("expected %q for fallback error, got %q: %s", StatusFailed, result.Status, result.Detail)
	}
}

func TestVerifyTool_EmptyMode(t *testing.T) {
	// Empty mode string should accept any attestation mode.
	pub, priv := generateTestKeys(t)

	tool := ToolDef{Name: testToolName, Description: testToolDesc, InputSchema: testSchema()}
	attestations, err := SignPipelock([]ToolDef{tool}, priv, signing.EncodePublicKey(pub))
	if err != nil {
		t.Fatalf("SignPipelock: %v", err)
	}

	cfg := VerifyConfig{
		TrustedKeys: map[string]ed25519.PublicKey{
			signing.EncodePublicKey(pub): pub,
		},
		Mode: "",
	}

	result := VerifyTool(tool, attestations[0], cfg)
	if result.Status != StatusVerified {
		t.Errorf("expected %q with empty mode, got %q: %s", StatusVerified, result.Status, result.Detail)
	}
}
