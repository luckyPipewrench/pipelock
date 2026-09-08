// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The message a verifier receives is attacker-shaped: the signer is not
// necessarily ours, so VerifyMessage cannot assume SignMessage produced the
// _meta it is reading. These cover the branches reached only by a message
// built outside the signing path.

// verifyConfigFor returns a config whose only variable is the trust anchor, so
// each case below changes exactly one thing about the message.
func verifyConfigFor(t *testing.T, pub []byte, now time.Time) MessageVerifyConfig {
	t.Helper()
	return MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     testMessageKeyID,
		MaxAge:    5 * time.Minute,
		Clock:     func() time.Time { return now },
	}
}

// extractSignedMessage has four distinct routes to "no signature found", and
// each one makes VerifyMessage report the message as UNSIGNED rather than
// invalid. That classification is the fail-direction that matters: an attacker
// who can corrupt signature extraction downgrades a signed message to an
// unsigned one, and the caller's policy decides what unsigned means. The
// property worth pinning is that no corrupted shape is ever reported as
// verified, and that the downgrade is reported honestly as unsigned rather
// than silently accepted.
func TestVerifyMessage_CorruptSignatureShapesReportUnsigned(t *testing.T) {
	t.Parallel()

	pub, priv := newTestKeypair(t)
	now := time.Unix(1_780_000_000, 0).UTC()

	// Control: a genuinely signed message verifies under this config, so a
	// later "unsigned" result is attributable to the corrupted shape rather
	// than to the fixture, the key, or the clock.
	t.Run("control_valid_signature_verifies", func(t *testing.T) {
		t.Parallel()
		sig, err := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), now)
		if err != nil {
			t.Fatalf("SignMessage: %v", err)
		}
		signed, err := EmbedMessageSignature([]byte(`{"jsonrpc":"2.0","method":"tools/call"}`), sig)
		if err != nil {
			t.Fatalf("EmbedMessageSignature: %v", err)
		}
		if res := VerifyMessage(signed, verifyConfigFor(t, pub, now)); res.Status != MessageSigVerified {
			t.Fatalf("control status = %q (%s), want %q", res.Status, res.Reason, MessageSigVerified)
		}
	})

	tests := []struct {
		name string
		msg  string
	}{
		{"meta absent", `{"jsonrpc":"2.0","method":"tools/call"}`},
		{"meta null", `{"jsonrpc":"2.0","method":"tools/call","_meta":null}`},
		{"meta is a string not an object", `{"jsonrpc":"2.0","method":"tools/call","_meta":"nope"}`},
		{"meta is an array not an object", `{"jsonrpc":"2.0","method":"tools/call","_meta":[1,2]}`},
		{"meta object without the signature key", `{"jsonrpc":"2.0","method":"tools/call","_meta":{"other":"value"}}`},
		{"signature value is a string not an object", `{"jsonrpc":"2.0","method":"tools/call","_meta":{"` + MessageMetaKey + `":"nope"}}`},
		{"signature value is an array", `{"jsonrpc":"2.0","method":"tools/call","_meta":{"` + MessageMetaKey + `":[]}}`},
		{"signature object carries neither alg nor signature", `{"jsonrpc":"2.0","method":"tools/call","_meta":{"` + MessageMetaKey + `":{"kid":"x","ts":1}}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The fixture must be a valid JSON envelope, or the case would be
			// testing the envelope parser instead of signature extraction.
			var probe map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tt.msg), &probe); err != nil {
				t.Fatalf("fixture is not a valid JSON envelope, so this case tests the wrong branch: %v", err)
			}

			res := VerifyMessage([]byte(tt.msg), verifyConfigFor(t, pub, now))
			if res.Status == MessageSigVerified {
				t.Fatalf("a corrupted signature shape was reported VERIFIED (reason %q)", res.Reason)
			}
			if res.Status != MessageSigUnsigned {
				t.Fatalf("status = %q (%s), want %q", res.Status, res.Reason, MessageSigUnsigned)
			}
		})
	}
}

// A malformed envelope is distinct from a corrupted signature: it cannot be
// classified as unsigned, because nothing about it was parseable. It must
// report malformed so an operator can tell a broken sender from an unsigned
// one.
func TestVerifyMessage_UnparseableEnvelopeReportsMalformed(t *testing.T) {
	t.Parallel()

	pub, _ := newTestKeypair(t)
	now := time.Unix(1_780_000_000, 0).UTC()

	for _, msg := range []string{``, `{`, `not json`, `[1,2,3]`} {
		res := VerifyMessage([]byte(msg), verifyConfigFor(t, pub, now))
		if res.Status != MessageSigMalformed {
			t.Errorf("VerifyMessage(%q) status = %q (%s), want %q", msg, res.Status, res.Reason, MessageSigMalformed)
		}
	}
}

// SignMessage refuses to produce a bad nonce, so the verifier's own nonce
// check is only reachable from a message built outside our signing path. That
// is exactly the untrusted case: a verifier that trusted the signer to have
// validated would accept a nonce too short to resist replay inside the
// max-age window.
func TestVerifyMessage_RejectsMalformedNonceFromAnUntrustedSigner(t *testing.T) {
	t.Parallel()

	pub, _ := newTestKeypair(t)
	now := time.Unix(1_780_000_000, 0).UTC()

	tests := []struct {
		name  string
		nonce string
	}{
		{"empty", ""},
		{"not base64", "not!!base64"},
		{"decodes below MinNonceLen", base64.StdEncoding.EncodeToString([]byte("12345678"))},
		{"decodes to a single byte", base64.StdEncoding.EncodeToString([]byte("x"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Built as a struct rather than through SignMessage, because
			// SignMessage rejects these before they can reach a verifier.
			sig := SignedMessage{
				Algorithm: MessageSigAlgEd25519,
				KeyID:     testMessageKeyID,
				Timestamp: now.Unix(),
				Nonce:     tt.nonce,
				Signature: base64.StdEncoding.EncodeToString([]byte("irrelevant, the nonce is checked first")),
			}
			msg, err := EmbedMessageSignature([]byte(`{"jsonrpc":"2.0","method":"tools/call"}`), sig)
			if err != nil {
				t.Fatalf("EmbedMessageSignature: %v", err)
			}

			res := VerifyMessage(msg, verifyConfigFor(t, pub, now))
			if res.Status == MessageSigVerified {
				t.Fatalf("a message with nonce %q was reported VERIFIED", tt.nonce)
			}
			if res.Status != MessageSigMalformed {
				t.Fatalf("status = %q (%s), want %q", res.Status, res.Reason, MessageSigMalformed)
			}
			if !strings.Contains(res.Reason, "nonce") {
				t.Errorf("reason = %q, want it to name the nonce so an operator can act on it", res.Reason)
			}
		})
	}
}

// EmbedMessageSignature is given caller-supplied bytes, so its parse failures
// must surface as errors rather than producing an envelope that silently drops
// the signature or the caller's existing _meta keys.
func TestEmbedMessageSignature_RejectsUnusableEnvelopes(t *testing.T) {
	t.Parallel()

	sig := SignedMessage{
		Algorithm: MessageSigAlgEd25519,
		KeyID:     testMessageKeyID,
		Timestamp: 1,
		Nonce:     base64.StdEncoding.EncodeToString(make([]byte, MinNonceLen)),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
	}

	t.Run("envelope is not JSON", func(t *testing.T) {
		t.Parallel()
		if _, err := EmbedMessageSignature([]byte(`not json`), sig); err == nil {
			t.Fatal("EmbedMessageSignature accepted a non-JSON envelope")
		}
	})

	t.Run("existing _meta is not an object", func(t *testing.T) {
		t.Parallel()
		if _, err := EmbedMessageSignature([]byte(`{"jsonrpc":"2.0","_meta":"scalar"}`), sig); err == nil {
			t.Fatal("EmbedMessageSignature accepted a scalar _meta, which would discard it")
		}
	})

	// The documented contract is that existing _meta keys survive. A signature
	// that silently dropped a caller's progress token would break the caller
	// while still verifying.
	t.Run("existing _meta keys are preserved", func(t *testing.T) {
		t.Parallel()
		out, err := EmbedMessageSignature([]byte(`{"jsonrpc":"2.0","_meta":{"progressToken":"abc"}}`), sig)
		if err != nil {
			t.Fatalf("EmbedMessageSignature: %v", err)
		}
		var env struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		}
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		// Compare the value, not just the key's presence. Checking presence
		// alone passes an implementation that rewrites the caller's token to
		// null or to anything else, which breaks the caller just as surely as
		// dropping the key would.
		if got := string(env.Meta["progressToken"]); got != `"abc"` {
			t.Errorf("progressToken = %s, want %q: embedding the signature must preserve the caller's existing _meta value", got, `"abc"`)
		}
		if _, ok := env.Meta[MessageMetaKey]; !ok {
			t.Error("embedding the signature did not add the signature key")
		}
	})
}
