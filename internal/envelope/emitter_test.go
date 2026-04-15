// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"net/http"
	"testing"
)

func TestEmitter_Build(t *testing.T) {
	t.Parallel()

	em := NewEmitter(EmitterConfig{
		ConfigHash: "sha256:abcd1234",
	})

	env := em.Build(BuildOpts{
		ActionID:   "01961f3a-7b2c-7000-8000-000000000001",
		Action:     "write",
		Verdict:    "allow",
		SideEffect: "external_write",
		Actor:      "claude-code",
		ActorAuth:  ActorAuthBound,
	})

	if env.Version != 1 {
		t.Errorf("Version = %d, want 1", env.Version)
	}
	if env.Action != "write" {
		t.Errorf("Action = %q, want %q", env.Action, "write")
	}
	if env.ReceiptID != "01961f3a-7b2c-7000-8000-000000000001" {
		t.Errorf("ReceiptID = %q, want matching ActionID", env.ReceiptID)
	}
	if env.Timestamp == 0 {
		t.Error("Timestamp should be non-zero")
	}
	if len(env.PolicyHash) != 16 {
		t.Errorf("PolicyHash length = %d, want 16", len(env.PolicyHash))
	}
}

func TestEmitter_Build_Nil(t *testing.T) {
	t.Parallel()

	var em *Emitter
	env := em.Build(BuildOpts{
		ActionID: "test",
		Action:   "read",
		Verdict:  "allow",
	})

	if env.Version != 0 {
		t.Errorf("nil emitter Build() returned non-zero Version: %d", env.Version)
	}
}

func TestEmitter_InjectHTTPEnvelope(t *testing.T) {
	t.Parallel()

	em := NewEmitter(EmitterConfig{
		ConfigHash: "sha256:abcd1234",
	})

	h := http.Header{}
	err := em.InjectHTTPEnvelope(h, BuildOpts{
		ActionID:   "01961f3a-7b2c-7000-8000-000000000001",
		Action:     "write",
		Verdict:    "allow",
		SideEffect: "external_write",
		Actor:      "test-agent",
		ActorAuth:  ActorAuthSelfDeclared,
	})
	if err != nil {
		t.Fatalf("InjectHTTPEnvelope() error: %v", err)
	}
	if h.Get(HeaderName) == "" {
		t.Fatal("header not set")
	}
}

func TestEmitter_InjectHTTPEnvelope_Nil(t *testing.T) {
	t.Parallel()

	var em *Emitter
	h := http.Header{}
	err := em.InjectHTTPEnvelope(h, BuildOpts{})
	if err != nil {
		t.Fatalf("nil emitter should return nil, got: %v", err)
	}
	if h.Get(HeaderName) != "" {
		t.Error("nil emitter should not inject headers")
	}
}

func TestEmitter_InjectMCPEnvelope(t *testing.T) {
	t.Parallel()

	em := NewEmitter(EmitterConfig{
		ConfigHash: "sha256:test",
	})

	meta := make(map[string]any)
	em.InjectMCPEnvelope(meta, BuildOpts{
		ActionID:   "01961f3a-7b2c-7000-8000-000000000001",
		Action:     "read",
		Verdict:    "allow",
		SideEffect: "external_read",
		Actor:      "test",
		ActorAuth:  ActorAuthMatched,
	})

	if _, ok := meta[MCPMetaKey]; !ok {
		t.Fatal("InjectMCPEnvelope() did not set meta key")
	}
}

func TestEmitter_InjectMCPEnvelope_Nil(t *testing.T) {
	t.Parallel()

	var em *Emitter
	meta := make(map[string]any)
	em.InjectMCPEnvelope(meta, BuildOpts{})
	if _, ok := meta[MCPMetaKey]; ok {
		t.Error("nil emitter should not inject meta")
	}
}

func TestEmitter_UpdateConfigHash(t *testing.T) {
	t.Parallel()

	em := NewEmitter(EmitterConfig{ConfigHash: "v1"})

	env1 := em.Build(BuildOpts{Action: "read", Verdict: "allow", ActorAuth: ActorAuthBound})
	hash1 := env1.PolicyHash

	em.UpdateConfigHash("v2")

	env2 := em.Build(BuildOpts{Action: "read", Verdict: "allow", ActorAuth: ActorAuthBound})
	hash2 := env2.PolicyHash

	// Different config hashes must produce different policy hashes.
	if string(hash1) == string(hash2) {
		t.Error("UpdateConfigHash() did not change policy hash")
	}
}

func TestEmitter_UpdateConfigHash_Nil(t *testing.T) {
	t.Parallel()
	var em *Emitter
	em.UpdateConfigHash("test") // Must not panic.
}

// TestEmitter_Build_PolicyHashOverride confirms that BuildOpts.PolicyHash,
// when non-empty, wins over the emitter's fallback atomic hash. This is
// how per-agent inject sites stamp an effective canonical ph without
// clobbering the global reload-time default.
func TestEmitter_Build_PolicyHashOverride(t *testing.T) {
	t.Parallel()

	em := NewEmitter(EmitterConfig{
		ConfigHash: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	})
	perAgent := PolicyHashFromHex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")

	env := em.Build(BuildOpts{
		ActionID:   "01961f3a-7b2c-7000-8000-000000000001",
		Action:     "write",
		Verdict:    "allow",
		ActorAuth:  ActorAuthBound,
		PolicyHash: perAgent,
	})

	if len(env.PolicyHash) != 16 {
		t.Fatalf("PolicyHash length = %d, want 16", len(env.PolicyHash))
	}
	if string(env.PolicyHash) != string(perAgent) {
		t.Errorf("BuildOpts.PolicyHash did not override fallback:\n  got  = %x\n  want = %x",
			env.PolicyHash, perAgent)
	}
}

// TestEmitter_Build_PolicyHashFallback confirms that when BuildOpts.PolicyHash
// is empty, the emitter's atomic fallback drives ph — preserving backward
// compatibility for transports that do not yet thread per-agent config
// through inject calls.
func TestEmitter_Build_PolicyHashFallback(t *testing.T) {
	t.Parallel()

	const globalHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	em := NewEmitter(EmitterConfig{ConfigHash: globalHex})

	env := em.Build(BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000002",
		Action:    "read",
		Verdict:   "allow",
		ActorAuth: ActorAuthMatched,
	})

	want := PolicyHashFromHex(globalHex)
	if string(env.PolicyHash) != string(want) {
		t.Errorf("fallback PolicyHash:\n  got  = %x\n  want = %x", env.PolicyHash, want)
	}
}

// TestPolicyHashFromHex_64CharHex confirms the exported helper decodes a
// 64-char canonical-hash string into the 16-byte wire form.
func TestPolicyHashFromHex_64CharHex(t *testing.T) {
	t.Parallel()
	const in = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	got := PolicyHashFromHex(in)
	if len(got) != 16 {
		t.Fatalf("PolicyHashFromHex length = %d, want 16", len(got))
	}
	// Expected first 16 bytes are the left half of the input hex string
	// (each pair of hex nibbles → 1 byte).
	wantBytes := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
	}
	for i := range wantBytes {
		if got[i] != wantBytes[i] {
			t.Errorf("PolicyHashFromHex bytes = %x, want %x", got, wantBytes)
			break
		}
	}
}

func TestPolicyHashTruncated_EmptyString(t *testing.T) {
	t.Parallel()
	hash := policyHashTruncated("")
	if len(hash) != 16 {
		t.Fatalf("length = %d, want 16", len(hash))
	}
	// All zeros for empty input.
	for i, b := range hash {
		if b != 0 {
			t.Fatalf("byte[%d] = %d, want 0", i, b)
		}
	}
}

func TestPolicyHashTruncated_ValidHexLong(t *testing.T) {
	t.Parallel()
	// 32 hex bytes = 64 hex chars. Should decode and truncate to first 16 bytes.
	hexStr := "abcdef0123456789abcdef01234567890000000000000000ffffffffffffffff"
	hash := policyHashTruncated(hexStr)
	if len(hash) != 16 {
		t.Fatalf("length = %d, want 16", len(hash))
	}
	// First byte of "ab" = 0xab.
	if hash[0] != 0xab {
		t.Errorf("hash[0] = 0x%02x, want 0xab", hash[0])
	}
}

func TestPolicyHashTruncated_ValidHexShort(t *testing.T) {
	t.Parallel()
	// 4 hex bytes = 8 hex chars. Shorter than 16 -- should pad to 16 bytes.
	hexStr := "abcdef01"
	hash := policyHashTruncated(hexStr)
	if len(hash) != 16 {
		t.Fatalf("length = %d, want 16", len(hash))
	}
	if hash[0] != 0xab {
		t.Errorf("hash[0] = 0x%02x, want 0xab", hash[0])
	}
	// Trailing bytes should be zero (padding).
	for i := 4; i < 16; i++ {
		if hash[i] != 0 {
			t.Errorf("hash[%d] = 0x%02x, want 0x00 (padding)", i, hash[i])
		}
	}
}

func TestPolicyHashTruncated_NonHexString(t *testing.T) {
	t.Parallel()
	// "sha256:..." prefix is not valid hex -- should SHA-256 hash and truncate.
	hash := policyHashTruncated("sha256:not-hex-at-all")
	if len(hash) != 16 {
		t.Fatalf("length = %d, want 16", len(hash))
	}
	// Result is non-zero (SHA-256 of the input).
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("non-hex input should produce a non-zero hash")
	}
}

func TestConfigHashString_NonString(t *testing.T) {
	t.Parallel()
	if got := configHashString(42); got != "" {
		t.Errorf("configHashString(42) = %q, want empty", got)
	}
	if got := configHashString(nil); got != "" {
		t.Errorf("configHashString(nil) = %q, want empty", got)
	}
	if got := configHashString("hello"); got != "hello" {
		t.Errorf("configHashString(\"hello\") = %q, want \"hello\"", got)
	}
}
