// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return pub, priv
}

func signOne(t *testing.T, tool ToolDef, priv ed25519.PrivateKey, keyID string) Attestation {
	t.Helper()
	atts, err := SignPipelock([]ToolDef{tool}, priv, keyID)
	if err != nil || len(atts) != 1 {
		t.Fatalf("SignPipelock: atts=%d err=%v", len(atts), err)
	}
	return atts[0]
}

// TestVerifyPipelock_DomainSeparation proves the signing input is domain-bound:
// a signature produced over the BARE digest (the pre-hardening scheme, and the
// shape any other same-key SHA-256 signer would emit) must NOT verify under the
// context-bound scheme. This closes cross-protocol signature replay.
func TestVerifyPipelock_DomainSeparation(t *testing.T) {
	pub, priv := newKeyPair(t)
	tool := ToolDef{Name: "send", Description: "send mail", InputSchema: []byte(`{"type":"object"}`)}
	att := signOne(t, tool, priv, "k1")

	// Context-bound signature verifies.
	ok, err := VerifyPipelock(att, pub)
	if err != nil || !ok {
		t.Fatalf("context-bound signature must verify: ok=%v err=%v", ok, err)
	}

	// A signature over the bare digest (no context prefix) must be rejected.
	bareSig := ed25519.Sign(priv, []byte(att.Digest.SHA256))
	forged := att
	forged.Bundle = base64.StdEncoding.EncodeToString(bareSig)
	ok, err = VerifyPipelock(forged, pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("bare-digest signature must NOT verify under domain-separated scheme (replay vector open)")
	}
}

// TestVerifyTool_FailClosed exercises every non-verified outcome of VerifyTool.
// Each disguised/misconfigured input must yield Error or Failed, never Verified.
func TestVerifyTool_FailClosed(t *testing.T) {
	pub, priv := newKeyPair(t)
	keyID := "k1"
	tool := ToolDef{Name: "exec", Description: "run a command", InputSchema: []byte(`{"type":"object"}`)}
	good := signOne(t, tool, priv, keyID)
	keys := map[string]ed25519.PublicKey{keyID: pub}

	t.Run("happy path verifies", func(t *testing.T) {
		r := VerifyTool(tool, good, VerifyConfig{TrustedKeys: keys, Mode: ModePipelock})
		if r.Status != StatusVerified {
			t.Fatalf("status=%q detail=%q, want verified", r.Status, r.Detail)
		}
	})
	t.Run("mode mismatch blocks", func(t *testing.T) {
		att := good
		att.Mode = ModeSigstore
		r := VerifyTool(tool, att, VerifyConfig{TrustedKeys: keys, Mode: ModePipelock})
		if r.Status != StatusError {
			t.Fatalf("status=%q, want error", r.Status)
		}
	})
	t.Run("digest tamper fails", func(t *testing.T) {
		tampered := ToolDef{Name: "exec", Description: "run a DIFFERENT command", InputSchema: tool.InputSchema}
		r := VerifyTool(tampered, good, VerifyConfig{TrustedKeys: keys, Mode: ModePipelock})
		if r.Status != StatusFailed {
			t.Fatalf("status=%q, want failed", r.Status)
		}
	})
	t.Run("sigstore offline blocks", func(t *testing.T) {
		att := signOne(t, tool, priv, keyID)
		att.Mode = ModeSigstore
		// Recompute is unnecessary: digest still matches; mode switch path is the target.
		r := VerifyTool(tool, att, VerifyConfig{TrustedKeys: keys, Mode: "any", OfflineOnly: true})
		if r.Status != StatusError {
			t.Fatalf("status=%q, want error", r.Status)
		}
	})
	t.Run("sigstore online not implemented blocks", func(t *testing.T) {
		att := signOne(t, tool, priv, keyID)
		att.Mode = ModeSigstore
		r := VerifyTool(tool, att, VerifyConfig{TrustedKeys: keys, Mode: "any", OfflineOnly: false})
		if r.Status != StatusError {
			t.Fatalf("status=%q, want error", r.Status)
		}
	})
	t.Run("unknown mode blocks", func(t *testing.T) {
		att := signOne(t, tool, priv, keyID)
		att.Mode = "frobnicate"
		r := VerifyTool(tool, att, VerifyConfig{TrustedKeys: keys, Mode: "any"})
		if r.Status != StatusError {
			t.Fatalf("status=%q, want error", r.Status)
		}
	})
	t.Run("no trusted keys blocks", func(t *testing.T) {
		r := VerifyTool(tool, good, VerifyConfig{Mode: ModePipelock})
		if r.Status != StatusError {
			t.Fatalf("status=%q, want error", r.Status)
		}
	})
	t.Run("wrong key fails", func(t *testing.T) {
		otherPub, _ := newKeyPair(t)
		r := VerifyTool(tool, good, VerifyConfig{TrustedKeys: map[string]ed25519.PublicKey{keyID: otherPub}, Mode: ModePipelock})
		if r.Status != StatusFailed {
			t.Fatalf("status=%q, want failed", r.Status)
		}
	})
}

// TestShouldBlock_FailClosed locks the block-decision matrix, including the
// unknown-action fail-closed default.
func TestShouldBlock_FailClosed(t *testing.T) {
	cases := []struct {
		name      string
		results   []VerificationResult
		action    string
		wantBlock bool
		wantErr   bool
	}{
		{"unknown action fails closed", []VerificationResult{{Status: StatusVerified}}, "frobnicate", true, true},
		{"failed always blocks even on allow", []VerificationResult{{Status: StatusFailed}}, "allow", true, true},
		{"error always blocks even on warn", []VerificationResult{{Status: StatusError}}, "warn", true, true},
		{"unsigned blocks on block", []VerificationResult{{Status: StatusUnsigned}}, "block", true, true},
		{"unsigned allowed on warn", []VerificationResult{{Status: StatusUnsigned}}, "warn", false, false},
		{"unsigned allowed on allow", []VerificationResult{{Status: StatusUnsigned}}, "allow", false, false},
		{"verified does not block", []VerificationResult{{Status: StatusVerified}}, "block", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block, err := ShouldBlock(tc.results, tc.action)
			if block != tc.wantBlock {
				t.Errorf("block=%v, want %v", block, tc.wantBlock)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// TestVerifyToolsList_FailClosed covers the response-level structural attacks:
// duplicate names, malformed provenance, and unparseable tools all become
// Error (block), while a genuinely unsigned tool is distinguished as Unsigned.
func TestVerifyToolsList_FailClosed(t *testing.T) {
	pub, priv := newKeyPair(t)
	keyID := "k1"
	keys := map[string]ed25519.PublicKey{keyID: pub}
	cfg := VerifyConfig{TrustedKeys: keys, Mode: ModePipelock}

	statusFor := func(t *testing.T, response []byte, toolName string) string {
		t.Helper()
		results, err := VerifyToolsList(response, cfg)
		if err != nil {
			t.Fatalf("VerifyToolsList error: %v", err)
		}
		for _, r := range results {
			if r.ToolName == toolName {
				return r.Status
			}
		}
		t.Fatalf("no result for %q in %+v", toolName, results)
		return ""
	}

	t.Run("verified end to end", func(t *testing.T) {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d","inputSchema":{"type":"object"}}]}}`)
		att := signOne(t, ToolDef{Name: "t", Description: "d", InputSchema: []byte(`{"type":"object"}`)}, priv, keyID)
		embedded, err := EmbedInToolsList(raw, []Attestation{att})
		if err != nil {
			t.Fatalf("embed: %v", err)
		}
		if got := statusFor(t, embedded, "t"); got != StatusVerified {
			t.Fatalf("status=%q, want verified", got)
		}
	})
	t.Run("unsigned tool distinguished", func(t *testing.T) {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"plain","description":"d","inputSchema":{}}]}}`)
		if got := statusFor(t, raw, "plain"); got != StatusUnsigned {
			t.Fatalf("status=%q, want unsigned", got)
		}
	})
	t.Run("duplicate tool names block", func(t *testing.T) {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"dup","description":"a","inputSchema":{}},{"name":"dup","description":"b","inputSchema":{}}]}}`)
		att1 := signOne(t, ToolDef{Name: "dup", Description: "a", InputSchema: []byte(`{}`)}, priv, keyID)
		att2 := signOne(t, ToolDef{Name: "dup", Description: "b", InputSchema: []byte(`{}`)}, priv, keyID)
		embedded, err := EmbedInToolsList(raw, []Attestation{att1, att2})
		if err != nil {
			t.Fatalf("embed: %v", err)
		}
		if got := statusFor(t, embedded, "dup"); got != StatusError {
			t.Fatalf("status=%q, want error", got)
		}
	})
	t.Run("unsigned duplicate tool names block", func(t *testing.T) {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"dup","description":"a","inputSchema":{}},{"name":"dup","description":"b","inputSchema":{}}]}}`)
		if got := statusFor(t, raw, "dup"); got != StatusError {
			t.Fatalf("status=%q, want error", got)
		}
	})
	t.Run("malformed provenance is error not unsigned", func(t *testing.T) {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"m","description":"d","inputSchema":{},"_meta":{"com.pipelock/provenance":"not-an-object"}}]}}`)
		if got := statusFor(t, raw, "m"); got != StatusError {
			t.Fatalf("status=%q, want error (must not soften to unsigned)", got)
		}
	})
	t.Run("unparseable tool entry blocks", func(t *testing.T) {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":["not-an-object"]}}`)
		results, err := VerifyToolsList(raw, cfg)
		if err != nil {
			t.Fatalf("VerifyToolsList error: %v", err)
		}
		if len(results) != 1 || results[0].Status != StatusError {
			t.Fatalf("results=%+v, want single error", results)
		}
	})
	t.Run("whole response unparseable errors", func(t *testing.T) {
		if _, err := VerifyToolsList([]byte(`{not json`), cfg); err == nil {
			t.Fatal("expected error on unparseable response (caller fails closed)")
		}
	})
}
