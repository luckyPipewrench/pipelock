// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
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

// TestEmitter_HasSigner reports correctly for both sign-off and sign-on
// emitter configurations.
func TestEmitter_HasSigner(t *testing.T) {
	t.Parallel()

	offEmitter := NewEmitter(EmitterConfig{ConfigHash: "x"})
	if offEmitter.HasSigner() {
		t.Error("emitter built without Signer should report HasSigner()=false")
	}

	_, priv := testSignerKey(t)
	signer := newTestSigner(t, priv)
	onEmitter := NewEmitter(EmitterConfig{ConfigHash: "x", Signer: signer})
	if !onEmitter.HasSigner() {
		t.Error("emitter built with Signer should report HasSigner()=true")
	}
	if onEmitter.Signer() != signer {
		t.Error("Signer() did not return the installed signer")
	}

	var nilEmitter *Emitter
	if nilEmitter.HasSigner() || nilEmitter.Signer() != nil {
		t.Error("nil emitter should behave as signer-less")
	}
}

// TestEmitter_InjectAndSign_NoSigner proves that when the emitter has
// no signer, InjectAndSign still sets the Pipelock-Mediation header but
// does not touch Signature or Signature-Input.
func TestEmitter_InjectAndSign_NoSigner(t *testing.T) {
	t.Parallel()

	em := NewEmitter(EmitterConfig{
		ConfigHash: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
	})
	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)

	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000001",
		Action:    "read",
		Verdict:   "allow",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}

	if req.Header.Get(HeaderName) == "" {
		t.Error("Pipelock-Mediation header not set")
	}
	if req.Header.Get("Signature") != "" {
		t.Error("Signature should be absent when signer is nil")
	}
	if req.Header.Get("Signature-Input") != "" {
		t.Error("Signature-Input should be absent when signer is nil")
	}
}

// TestEmitter_InjectAndSign_WithSigner proves the end-to-end inject +
// sign path through an Emitter that has a signer attached: envelope
// header, Content-Digest, Signature-Input/Signature all present and
// the signature verifies.
func TestEmitter_InjectAndSign_WithSigner(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	signer := newTestSigner(t, priv)
	em := NewEmitter(EmitterConfig{
		ConfigHash: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		Signer:     signer,
	})

	body := []byte(`{"action":"write"}`)
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", strings.NewReader(string(body)))

	if err := em.InjectAndSign(req, body, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000002",
		Action:    "write",
		Verdict:   "allow",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}

	if req.Header.Get(HeaderName) == "" {
		t.Fatal("Pipelock-Mediation header not set")
	}
	if req.Header.Get("Content-Digest") == "" {
		t.Error("Content-Digest not set")
	}
	if req.Header.Get("Signature-Input") == "" {
		t.Fatal("Signature-Input not set")
	}
	if req.Header.Get("Signature") == "" {
		t.Fatal("Signature not set")
	}

	// Reconstruct signature base and verify.
	sigInputDict, err := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	if err != nil {
		t.Fatalf("Signature-Input parse: %v", err)
	}
	member, _ := sigInputDict.Get(pipelockSigLabel)
	inner := member.(httpsfv.InnerList) //nolint:errcheck // type known
	components := make([]string, 0, len(inner.Items))
	for _, it := range inner.Items {
		s, _ := it.Value.(string)
		components = append(components, s)
	}

	base, err := buildSignatureBase(req, body, components, inner)
	if err != nil {
		t.Fatalf("buildSignatureBase: %v", err)
	}

	sigDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature"))
	sigMember, _ := sigDict.Get(pipelockSigLabel)
	sigBytes, _ := sigMember.(httpsfv.Item).Value.([]byte)

	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		t.Errorf("signature verification failed over reconstructed base:\n%s", base)
	}
}

// TestEmitter_InjectAndSign_NilRequest rejects a nil *http.Request so
// transport call sites cannot quietly skip signing.
func TestEmitter_InjectAndSign_NilRequest(t *testing.T) {
	t.Parallel()
	em := NewEmitter(EmitterConfig{ConfigHash: "x"})
	if err := em.InjectAndSign(nil, nil, BuildOpts{}); err == nil {
		t.Error("nil request should produce an error")
	}
}

// TestEmitter_InjectAndSign_AutoBuffersBodyForSigner proves the
// "scanner disabled, signing enabled" path: the caller hands in
// body=nil but req.Body is populated. The Emitter drains req.Body,
// replaces it with a fresh reader, sets GetBody for redirect replay,
// and the signer digests the buffered bytes.
func TestEmitter_InjectAndSign_AutoBuffersBodyForSigner(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	signer := newTestSigner(t, priv)
	em := NewEmitter(EmitterConfig{
		ConfigHash: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		Signer:     signer,
	})

	body := []byte(`{"auto":true}`)
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", strings.NewReader(string(body)))

	// Caller does NOT have bytes in hand — mirrors "request body
	// scanning disabled, signing enabled."
	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000010",
		Action:    "write",
		Verdict:   "allow",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}

	// Content-Digest must reflect the original body.
	sum := sha256.Sum256(body)
	wantDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if got := req.Header.Get("Content-Digest"); got != wantDigest {
		t.Errorf("Content-Digest = %q, want %q", got, wantDigest)
	}

	// Body must still be readable — a fresh NopCloser was installed.
	drained, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading replaced body: %v", err)
	}
	if string(drained) != string(body) {
		t.Errorf("replaced body = %q, want %q", string(drained), string(body))
	}

	// GetBody must return a fresh reader (redirect replay path).
	if req.GetBody == nil {
		t.Fatal("GetBody was not set")
	}
	replay, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	replayBytes, _ := io.ReadAll(replay)
	if string(replayBytes) != string(body) {
		t.Errorf("GetBody replay = %q, want %q", replayBytes, body)
	}

	// Signature must verify over the reconstructed base.
	sigInputDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	member, _ := sigInputDict.Get(pipelockSigLabel)
	inner := member.(httpsfv.InnerList) //nolint:errcheck // type known
	components := make([]string, 0, len(inner.Items))
	for _, it := range inner.Items {
		s, _ := it.Value.(string)
		components = append(components, s)
	}
	base, err := buildSignatureBase(req, body, components, inner)
	if err != nil {
		t.Fatalf("buildSignatureBase: %v", err)
	}
	sigDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature"))
	sigMember, _ := sigDict.Get(pipelockSigLabel)
	sigBytes, _ := sigMember.(httpsfv.Item).Value.([]byte)
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		t.Error("signature verification failed over reconstructed base")
	}
}

// TestEmitter_InjectAndSign_OverCapBodyDropsDigest proves the
// over-cap fallback: when the body exceeds the signer's MaxBodyBytes,
// the signer drops content-digest from its declared list and still
// attaches a valid signature. The original request body must still be
// preserved for the upstream transport.
func TestEmitter_InjectAndSign_OverCapBodyDropsDigest(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "cap-test",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation},
		MaxBodyBytes:     32,
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash: "aa",
		Signer:     signer,
	})

	oversized := strings.Repeat("X", 4096)
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", strings.NewReader(oversized))

	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000011",
		Action:    "write",
		Verdict:   "allow",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}

	// Content-Digest must be absent — over-cap body cannot be digested.
	if got := req.Header.Get("Content-Digest"); got != "" {
		t.Errorf("Content-Digest = %q, want empty", got)
	}

	// Signature-Input must not list content-digest either.
	sigInputDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	member, _ := sigInputDict.Get(pipelockSigLabel)
	list := member.(httpsfv.InnerList) //nolint:errcheck // type known
	for _, it := range list.Items {
		if s, _ := it.Value.(string); s == headerContentDigest {
			t.Error("content-digest survived over-cap body case in declared list")
		}
	}

	// The original body must still be readable by the upstream path.
	drained, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading preserved body: %v", err)
	}
	if got := string(drained); got != oversized {
		t.Errorf("preserved body = %q, want %q", got, oversized)
	}

	// Existing GetBody support from http.NewRequest must survive so
	// redirect replay is still possible when the original request was
	// replayable.
	if req.GetBody == nil {
		t.Fatal("GetBody was lost on known-size over-cap request")
	}
	replay, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	replayBytes, err := io.ReadAll(replay)
	if err != nil {
		t.Fatalf("reading replay body: %v", err)
	}
	if got := string(replayBytes); got != oversized {
		t.Errorf("replay body = %q, want %q", got, oversized)
	}
}

// TestEmitter_InjectAndSign_OverCapUnknownLengthPreservesBody covers the
// unknown-length overflow path: the emitter reads past the cap to detect the
// overflow, then rebuilds req.Body so the upstream still receives the full
// payload even though content-digest is omitted.
func TestEmitter_InjectAndSign_OverCapUnknownLengthPreservesBody(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "cap-unknown-test",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation},
		MaxBodyBytes:     32,
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash: "aa",
		Signer:     signer,
	})

	oversized := strings.Repeat("Y", 4096)
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", nil)
	origBody := &trackingReadCloser{Reader: strings.NewReader(oversized)}
	req.Body = origBody
	req.ContentLength = -1
	req.GetBody = nil

	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000012",
		Action:    "write",
		Verdict:   "allow",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}

	if got := req.Header.Get("Content-Digest"); got != "" {
		t.Errorf("Content-Digest = %q, want empty", got)
	}

	sigInputDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	member, _ := sigInputDict.Get(pipelockSigLabel)
	list := member.(httpsfv.InnerList) //nolint:errcheck // type known
	for _, it := range list.Items {
		if s, _ := it.Value.(string); s == headerContentDigest {
			t.Error("content-digest survived unknown-length over-cap case in declared list")
		}
	}

	drained, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading preserved overflow body: %v", err)
	}
	if got := string(drained); got != oversized {
		t.Errorf("preserved overflow body = %q, want %q", got, oversized)
	}
	if req.GetBody != nil {
		t.Error("GetBody should stay nil when the original unknown-length body was not replayable")
	}
	if err := req.Body.Close(); err != nil {
		t.Fatalf("closing preserved overflow body: %v", err)
	}
	if !origBody.closed {
		t.Error("closing req.Body did not close the original body")
	}
}

type trackingReadCloser struct {
	Reader *strings.Reader
	closed bool
}

func (t *trackingReadCloser) Read(p []byte) (int, error) {
	return t.Reader.Read(p)
}

func (t *trackingReadCloser) Close() error {
	t.closed = true
	return nil
}

// TestEmitter_InjectAndSign_NilEmitter is a no-op.
func TestEmitter_InjectAndSign_NilEmitter(t *testing.T) {
	t.Parallel()
	var em *Emitter
	req := newTestRequest(t, http.MethodGet, "https://example.test/", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{}); err != nil {
		t.Errorf("nil emitter should return nil, got %v", err)
	}
	if req.Header.Get(HeaderName) != "" {
		t.Error("nil emitter should not touch headers")
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
