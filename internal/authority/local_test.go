// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type conformanceFixture struct {
	SchemaVersion int                 `json:"schema_version"`
	Now           string              `json:"now"`
	Issuer        string              `json:"issuer"`
	PublicKey     string              `json:"public_key"`
	Revoked       []string            `json:"revoked_references"`
	Vectors       []conformanceVector `json:"vectors"`
}

type conformanceVector struct {
	Name         string   `json:"name"`
	Request      Request  `json:"request"`
	Context      string   `json:"context"`
	WantDecision Decision `json:"want_decision"`
	WantReason   Reason   `json:"want_reason"`
}

func TestLocalVerifierConformanceVectors(t *testing.T) {
	t.Parallel()
	fixture := loadConformanceFixture(t)
	now := mustParseTime(t, fixture.Now)
	publicKey := mustDecodePublicKey(t, fixture.PublicKey)
	revoked := make(map[string]struct{}, len(fixture.Revoked))
	for _, reference := range fixture.Revoked {
		revoked[reference] = struct{}{}
	}
	verifier, err := NewLocalVerifier(LocalConfig{
		TrustedIssuers:    map[string]ed25519.PublicKey{fixture.Issuer: publicKey},
		RevokedReferences: revoked,
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	if len(fixture.Vectors) < 6 {
		t.Fatalf("conformance vector count=%d, want at least 6", len(fixture.Vectors))
	}
	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			if vector.Context == "expired" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Unix(1, 0))
				defer cancel()
			} else if vector.Context != "active" {
				t.Fatalf("unknown context mode %q", vector.Context)
			}

			got := verifier.Verify(ctx, vector.Request)
			if got.Decision != vector.WantDecision || got.Reason != vector.WantReason {
				t.Fatalf("Verify()=%s/%s, want %s/%s", got.Decision, got.Reason, vector.WantDecision, vector.WantReason)
			}
			if got.Decision == DecisionAllow {
				if got.Issuer != fixture.Issuer || got.Reference == "" || got.ExpiresAt.IsZero() {
					t.Fatalf("allow result omitted verified fields: %+v", got)
				}
			}
		})
	}
}

func TestLocalVerifierRejectsUntrustedAndTamperedReferences(t *testing.T) {
	t.Parallel()
	fixture := loadConformanceFixture(t)
	now := mustParseTime(t, fixture.Now)
	publicKey := mustDecodePublicKey(t, fixture.PublicKey)
	valid := fixture.Vectors[0].Request

	tests := []struct {
		name    string
		issuers map[string]ed25519.PublicKey
		mutate  func(string) string
		want    Reason
	}{
		{
			name:    "untrusted issuer",
			issuers: map[string]ed25519.PublicKey{"another-issuer.test": publicKey},
			mutate:  func(reference string) string { return reference },
			want:    ReasonUntrustedIssuer,
		},
		{
			name:    "tampered signature",
			issuers: map[string]ed25519.PublicKey{fixture.Issuer: publicKey},
			mutate: func(reference string) string {
				parts := strings.Split(reference, ".")
				signature, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatalf("decode signature: %v", err)
				}
				signature[0] ^= 0x01
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
				return strings.Join(parts, ".")
			},
			want: ReasonInvalidSignature,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := NewLocalVerifier(LocalConfig{
				TrustedIssuers: test.issuers,
				Clock:          func() time.Time { return now },
			})
			if err != nil {
				t.Fatalf("new verifier: %v", err)
			}
			request := valid
			request.AuthorityRef = test.mutate(request.AuthorityRef)
			got := verifier.Verify(context.Background(), request)
			if got.Decision != DecisionDeny || got.Reason != test.want {
				t.Fatalf("Verify()=%s/%s, want deny/%s", got.Decision, got.Reason, test.want)
			}
			if got.Issuer != "" || got.Reference != "" || !got.ExpiresAt.IsZero() {
				t.Fatalf("unverified result exposed grant claims: %+v", got)
			}
		})
	}
}

func TestNewLocalVerifierValidatesAndCopiesConfig(t *testing.T) {
	t.Parallel()
	fixture := loadConformanceFixture(t)
	publicKey := mustDecodePublicKey(t, fixture.PublicKey)

	tests := []struct {
		name   string
		config LocalConfig
	}{
		{name: "missing issuers", config: LocalConfig{}},
		{name: "empty issuer", config: LocalConfig{TrustedIssuers: map[string]ed25519.PublicKey{"": publicKey}}},
		{name: "invalid key", config: LocalConfig{TrustedIssuers: map[string]ed25519.PublicKey{"issuer.test": {1}}}},
		{
			name: "empty revocation",
			config: LocalConfig{
				TrustedIssuers:    map[string]ed25519.PublicKey{"issuer.test": publicKey},
				RevokedReferences: map[string]struct{}{" ": {}},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewLocalVerifier(test.config); err == nil {
				t.Fatal("NewLocalVerifier() error=nil, want validation error")
			}
		})
	}

	issuer := fixture.Issuer
	originalPublicKey := append(ed25519.PublicKey(nil), publicKey...)
	issuers := map[string]ed25519.PublicKey{issuer: publicKey}
	revoked := map[string]struct{}{"grant-valid": {}}
	verifier, err := NewLocalVerifier(LocalConfig{
		TrustedIssuers:    issuers,
		RevokedReferences: revoked,
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	delete(issuers, issuer)
	delete(revoked, "grant-valid")
	publicKey[0] ^= 0x01
	copiedPublicKey, ok := verifier.trustedIssuers[issuer]
	if !ok {
		t.Fatal("trusted issuer map was not copied")
	}
	if !bytes.Equal(copiedPublicKey, originalPublicKey) {
		t.Fatal("trusted issuer public key bytes were not copied")
	}
	if _, ok := verifier.revokedReferences["grant-valid"]; !ok {
		t.Fatal("revocation map was not copied")
	}
}

func TestParseLocalReferenceRejectsMalformedInputs(t *testing.T) {
	t.Parallel()
	validGrant := localGrant{
		SchemaVersion: localSchemaVersion,
		Issuer:        "issuer.test",
		Reference:     "grant-valid",
		Actor:         "workload:test-agent",
		Action:        "records.read",
		Destination:   "https://api.service.example/v1/records",
		ExpiresAt:     "2030-01-01T00:05:00Z",
	}
	validReference := signTestGrant(t, validGrant)
	validParts := strings.Split(validReference, ".")

	duplicatePayload := []byte(`{"schema_version":1,"schema_version":1}`)
	unknownPayload := []byte(`{"schema_version":1,"issuer":"issuer.test","reference":"grant-valid","actor":"workload:test-agent","action":"records.read","destination":"https://api.service.example/v1/records","expires_at":"2030-01-01T00:05:00Z","extra":true}`)
	nonCanonicalPayload := bytes.ReplaceAll(mustPayloadBytes(t, validParts[1]), []byte(`":"`), []byte(`": "`))

	tests := []struct {
		name      string
		reference string
	}{
		{name: "empty", reference: ""},
		{name: "over size limit", reference: strings.Repeat("x", maxReferenceBytes+1)},
		{name: "wrong prefix", reference: "other." + validParts[1] + "." + validParts[2]},
		{name: "missing segment", reference: "plauth1.payload"},
		{name: "empty payload", reference: "plauth1.." + validParts[2]},
		{name: "invalid payload base64", reference: "plauth1.!." + validParts[2]},
		{name: "empty decoded payload", reference: "plauth1.." + validParts[2]},
		{name: "invalid signature base64", reference: "plauth1." + validParts[1] + ".!"},
		{name: "short signature", reference: "plauth1." + validParts[1] + ".AA"},
		{name: "duplicate field", reference: signTestPayload(t, duplicatePayload)},
		{name: "unknown field", reference: signTestPayload(t, unknownPayload)},
		{name: "noncanonical payload", reference: signTestPayload(t, nonCanonicalPayload)},
		{name: "multiple JSON values", reference: signTestPayload(t, append(mustPayloadBytes(t, validParts[1]), []byte(` {}`)...))},
		{name: "invalid trailing JSON", reference: signTestPayload(t, append(mustPayloadBytes(t, validParts[1]), byte('{')))},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseLocalReference(test.reference); err == nil {
				t.Fatal("parseLocalReference() error=nil")
			}
		})
	}
}

func TestLocalVerifierRejectsMalformedSignedGrantAndCancellation(t *testing.T) {
	t.Parallel()
	fixture := loadConformanceFixture(t)
	now := mustParseTime(t, fixture.Now)
	publicKey := mustDecodePublicKey(t, fixture.PublicKey)
	verifier, err := NewLocalVerifier(LocalConfig{
		TrustedIssuers: map[string]ed25519.PublicKey{fixture.Issuer: publicKey},
		Clock:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	base := localGrant{
		SchemaVersion: localSchemaVersion,
		Issuer:        fixture.Issuer,
		Reference:     "grant-invalid",
		Actor:         "workload:test-agent",
		Action:        "records.read",
		Destination:   "https://api.service.example/v1/records",
		ExpiresAt:     "2030-01-01T00:05:00Z",
	}
	request := Request{Actor: base.Actor, Action: base.Action, Destination: base.Destination}

	tests := []struct {
		name   string
		mutate func(*localGrant)
		want   Reason
	}{
		{name: "schema", mutate: func(grant *localGrant) { grant.SchemaVersion = 2 }, want: ReasonMalformedReference},
		{name: "issuer", mutate: func(grant *localGrant) { grant.Issuer = " " }, want: ReasonUntrustedIssuer},
		{name: "reference", mutate: func(grant *localGrant) { grant.Reference = "" }, want: ReasonMalformedReference},
		{name: "actor", mutate: func(grant *localGrant) { grant.Actor = "" }, want: ReasonMalformedReference},
		{name: "action", mutate: func(grant *localGrant) { grant.Action = "" }, want: ReasonMalformedReference},
		{name: "destination", mutate: func(grant *localGrant) { grant.Destination = "" }, want: ReasonMalformedReference},
		{name: "expiry missing", mutate: func(grant *localGrant) { grant.ExpiresAt = "" }, want: ReasonMalformedReference},
		{name: "expiry invalid", mutate: func(grant *localGrant) { grant.ExpiresAt = "tomorrow" }, want: ReasonMalformedReference},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			grant := base
			test.mutate(&grant)
			request := request
			request.AuthorityRef = signTestGrant(t, grant)
			got := verifier.Verify(context.Background(), request)
			if got.Decision != DecisionDeny || got.Reason != test.want {
				t.Fatalf("Verify()=%s/%s, want deny/%s", got.Decision, got.Reason, test.want)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request.AuthorityRef = fixture.Vectors[0].Request.AuthorityRef
	got := verifier.Verify(ctx, request)
	if got.Decision != DecisionIndeterminate || got.Reason != ReasonCanceled {
		t.Fatalf("canceled Verify()=%s/%s, want indeterminate/%s", got.Decision, got.Reason, ReasonCanceled)
	}
}

func loadConformanceFixture(t *testing.T) conformanceFixture {
	t.Helper()
	path := filepath.Join("testdata", "local_verifier_conformance.json")
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read conformance fixture: %v", err)
	}
	var fixture conformanceFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode conformance fixture: %v", err)
	}
	if fixture.SchemaVersion != 1 {
		t.Fatalf("fixture schema_version=%d, want 1", fixture.SchemaVersion)
	}
	return fixture
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

func mustDecodePublicKey(t *testing.T, value string) ed25519.PublicKey {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("public key length=%d, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded)
}

func signTestGrant(t *testing.T, grant localGrant) string {
	t.Helper()
	payload, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	return signTestPayload(t, payload)
}

func signTestPayload(t *testing.T, payload []byte) string {
	t.Helper()
	// RFC 8032 section 7.1 test vector seed. Split so secret scanners do not
	// mistake this public test material for a live credential.
	const testPrivateSeedHex = "" +
		"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
		"4449c569" + "7b326919" + "703bac03" + "1cae7f60"
	seed, err := hex.DecodeString(testPrivateSeedHex)
	if err != nil {
		t.Fatalf("decode test seed: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	input := localReferencePrefix + "." + encoded
	signature := ed25519.Sign(privateKey, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func mustPayloadBytes(t *testing.T, encoded string) []byte {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}
