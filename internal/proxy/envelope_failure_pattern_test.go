// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const testInboundVerifyMissingPattern = "inbound_verify_missing"

func TestInboundEnvelopeFailurePatternUsesVerifierCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code envelope.VerificationFailureCode
		want string
	}{
		{name: "replay", code: envelope.VerificationFailureReplay, want: "inbound_verify_replay"},
		{name: "expired", code: envelope.VerificationFailureExpired, want: "inbound_verify_expired"},
		{name: "not trusted", code: envelope.VerificationFailureNotTrusted, want: "inbound_verify_not_trusted"},
		{name: "missing", code: envelope.VerificationFailureMissing, want: testInboundVerifyMissingPattern},
		{name: "digest", code: envelope.VerificationFailureDigest, want: "inbound_verify_digest"},
		{name: "signature", code: envelope.VerificationFailureSignature, want: "inbound_verify_signature"},
		{name: "parse", code: envelope.VerificationFailureParse, want: "inbound_verify_parse"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := &envelope.VerificationError{
				Code: tt.code,
				Err:  errors.New("wording may change"),
			}
			if got := inboundEnvelopeFailurePattern(fmt.Errorf("wrapped: %w", err)); got != tt.want {
				t.Fatalf("pattern = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInboundEnvelopeFailurePatternFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: "inbound_verify"},
		{name: "replay", err: errors.New("signature replay detected"), want: "inbound_verify_replay"},
		{name: "expired", err: errors.New("signature expired"), want: "inbound_verify_expired"},
		{name: "not trusted", err: errors.New("trusted key not authorized"), want: "inbound_verify_not_trusted"},
		{name: "missing", err: errors.New("missing header"), want: testInboundVerifyMissingPattern},
		{name: "digest", err: errors.New("content-digest mismatch"), want: "inbound_verify_digest"},
		{name: "signature", err: errors.New("signature verification failed"), want: "inbound_verify_signature"},
		{name: "parse", err: errors.New("parse Signature-Input"), want: "inbound_verify_parse"},
		{name: "failed", err: errors.New("unexpected verifier failure"), want: "inbound_verify_failed"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := inboundEnvelopeFailurePattern(tt.err); got != tt.want {
				t.Fatalf("pattern for %v = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestBuildInboundEnvelopeVerifier(t *testing.T) {
	t.Parallel()

	if verifier, err := buildInboundEnvelopeVerifier(nil); err != nil || verifier != nil {
		t.Fatalf("nil config verifier = (%v, %v), want nil nil", verifier, err)
	}

	cfg := config.Defaults()
	if verifier, err := buildInboundEnvelopeVerifier(cfg); err != nil || verifier != nil {
		t.Fatalf("disabled verifier = (%v, %v), want nil nil", verifier, err)
	}

	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cfg.MediationEnvelope.VerifyInbound.Enabled = true
	cfg.MediationEnvelope.VerifyInbound.TrustList = []config.MediationEnvelopeTrustedKey{{
		KeyID:        "partner-key",
		PublicKey:    hex.EncodeToString(pub),
		TrustDomains: []string{"partner.example"},
	}}
	cfg.MediationEnvelope.VerifyInbound.ReplayCache.Window = "2m"
	cfg.MediationEnvelope.VerifyInbound.ReplayCache.MaxEntries = 16

	verifier, err := buildInboundEnvelopeVerifier(cfg)
	if err != nil {
		t.Fatalf("buildInboundEnvelopeVerifier: %v", err)
	}
	if verifier == nil {
		t.Fatal("expected verifier")
	}

	cfg.MediationEnvelope.VerifyInbound.TrustList[0].PublicKey = "not-hex"
	if _, err := buildInboundEnvelopeVerifier(cfg); err == nil {
		t.Fatal("expected invalid trusted key to fail")
	}
}

func TestVerifyInboundEnvelopeValidSignedRequest(t *testing.T) {
	t.Parallel()

	pub, priv := testInboundEnvelopeKey(t)
	cfg, verifier := testInboundVerifier(t, pub)
	req := signedInboundRequest(t, priv, "partner-key", "spiffe://partner.example/agent/proxy", "payload")

	if err := verifyInboundEnvelope(req, cfg, verifier); err != nil {
		t.Fatalf("verifyInboundEnvelope: %v", err)
	}
}

func TestVerifyInboundEnvelopeMissingHeaderSkipsBodyDrain(t *testing.T) {
	t.Parallel()

	pub, _ := testInboundEnvelopeKey(t)
	cfg, verifier := testInboundVerifier(t, pub)
	req := httptest.NewRequest(http.MethodPost, "https://upstream.example/api", &errorReader{
		n:   8,
		err: errors.New("body should not be read"),
	})

	err := verifyInboundEnvelope(req, cfg, verifier)
	if err == nil {
		t.Fatal("expected missing envelope header error")
	}
	if got := inboundEnvelopeFailurePattern(err); got != testInboundVerifyMissingPattern {
		t.Fatalf("pattern = %q, want %s", got, testInboundVerifyMissingPattern)
	}
}

func TestBufferInboundEnvelopeBodyClosesOverCapBody(t *testing.T) {
	t.Parallel()

	body := &closeTrackingReadCloser{Reader: strings.NewReader("abcdef")}
	req := httptest.NewRequest(http.MethodPost, "https://upstream.example/api", body)
	req.Body = body
	req.ContentLength = 6

	if _, err := bufferInboundEnvelopeBody(req, 5); err == nil {
		t.Fatal("expected over-cap body to fail")
	}
	if !body.closed {
		t.Fatal("over-cap request body was not closed")
	}
}

type closeTrackingReadCloser struct {
	io.Reader
	closed bool
}

func (c *closeTrackingReadCloser) Close() error {
	c.closed = true
	return nil
}

func testInboundEnvelopeKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, priv
}

func testInboundVerifier(t *testing.T, pub ed25519.PublicKey) (*config.Config, *envelope.Verifier) {
	t.Helper()

	cfg := config.Defaults()
	cfg.MediationEnvelope.MaxBodyBytes = 1024
	cfg.MediationEnvelope.VerifyInbound.Enabled = true
	cfg.MediationEnvelope.VerifyInbound.TrustList = []config.MediationEnvelopeTrustedKey{{
		KeyID:        "partner-key",
		PublicKey:    hex.EncodeToString(pub),
		TrustDomains: []string{"partner.example"},
	}}
	cfg.MediationEnvelope.VerifyInbound.ReplayCache.Window = "5m"
	cfg.MediationEnvelope.VerifyInbound.ReplayCache.MaxEntries = 32

	verifier, err := buildInboundEnvelopeVerifier(cfg)
	if err != nil {
		t.Fatalf("buildInboundEnvelopeVerifier: %v", err)
	}
	return cfg, verifier
}

func signedInboundRequest(t *testing.T, priv ed25519.PrivateKey, keyID, actor, body string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "https://upstream.example/api", strings.NewReader(body))
	env := envelope.Envelope{
		Version:   1,
		Action:    "write",
		Verdict:   config.ActionAllow,
		Actor:     actor,
		ActorAuth: envelope.ActorAuthBound,
		ReceiptID: "01961f3a-7b2c-7000-8000-000000000001",
		Timestamp: time.Now().UTC().Unix(),
	}
	if err := envelope.InjectHTTP(req.Header, env); err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	signer, err := envelope.NewSigner(envelope.SignerConfig{
		PrivKey:          priv,
		KeyID:            keyID,
		SignedComponents: config.DefaultEnvelopeSignedComponents(),
		Expires:          time.Minute,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if err := signer.SignRequest(req, []byte(body)); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	return req
}
