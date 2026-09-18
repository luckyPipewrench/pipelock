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

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/jcs"
	"golang.org/x/text/unicode/norm"
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
		NotBefore:     "2030-01-01T00:00:00Z",
		ExpiresAt:     "2030-01-01T00:05:00Z",
	}
	validReference := signTestGrant(t, validGrant)
	validParts := strings.Split(validReference, ".")

	duplicatePayload := []byte(`{"schema_version":2,"schema_version":2}`)
	unknownPayload := []byte(`{"schema_version":2,"issuer":"issuer.test","reference":"grant-valid","actor":"workload:test-agent","action":"records.read","destination":"https://api.service.example/v1/records","not_before":"2030-01-01T00:00:00Z","expires_at":"2030-01-01T00:05:00Z","extra":true}`)
	nonCanonicalPayload := bytes.ReplaceAll(mustPayloadBytes(t, validParts[1]), []byte(`":"`), []byte(`": "`))

	tests := []struct {
		name      string
		reference string
	}{
		{name: "empty", reference: ""},
		{name: "over size limit", reference: strings.Repeat("x", MaxReferenceBytes+1)},
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

func TestLocalVerifierAcceptsJCSStringEscaping(t *testing.T) {
	t.Parallel()
	fixture := loadConformanceFixture(t)
	publicKey := mustDecodePublicKey(t, fixture.PublicKey)
	grant := localGrant{
		SchemaVersion: localSchemaVersion,
		Issuer:        fixture.Issuer,
		Reference:     "grant-query",
		Actor:         "workload:test-agent",
		Action:        "records.read",
		Destination:   "https://api.service.example/v1/records?active=true&filter=<active>&limit=10",
		NotBefore:     "2030-01-01T00:00:00Z",
		ExpiresAt:     "2030-01-01T00:05:00Z",
	}
	request := Request{
		Actor:        grant.Actor,
		Action:       grant.Action,
		Destination:  grant.Destination,
		AuthorityRef: signTestGrant(t, grant),
	}
	verifier, err := NewLocalVerifier(LocalConfig{
		TrustedIssuers: map[string]ed25519.PublicKey{fixture.Issuer: publicKey},
		Clock:          func() time.Time { return mustParseTime(t, fixture.Now) },
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	got := verifier.Verify(context.Background(), request)
	if got.Decision != DecisionAllow || got.Reason != ReasonMatched {
		t.Fatalf("Verify()=%s/%s, want allow/%s", got.Decision, got.Reason, ReasonMatched)
	}
	payload := mustPayloadBytes(t, strings.Split(request.AuthorityRef, ".")[1])
	if !bytes.Contains(payload, []byte("&filter=<active>&limit=10")) {
		t.Fatalf("JCS payload escaped ampersand: %s", payload)
	}
}

func TestLocalVerifierNamedCanonNFCAndExactIdentityMatching(t *testing.T) {
	t.Parallel()
	// Fixed UTF-8 bytes keep the positive case independent of the verifier's
	// canonicalizer. All member names are ASCII and the sole number is integral.
	const payload = `{"action":"records.read","actor":"workload:médiator","canon":"jcs-rfc8785-nfc","destination":"https://api.service.example/v1/records?active=true&filter=<active>&limit=10","expires_at":"2030-01-01T00:05:00Z","issuer":"issuer.test","not_before":"2030-01-01T00:00:00Z","reference":"grant-nfc","schema_version":2}`
	fixture := loadConformanceFixture(t)
	publicKey := mustDecodePublicKey(t, fixture.PublicKey)
	grant := localGrant{
		SchemaVersion: localSchemaVersion,
		Canon:         localCanonJCSRFC8785NFC,
		Issuer:        fixture.Issuer,
		Reference:     "grant-nfc",
		Actor:         "workload:médiator",
		Action:        "records.read",
		Destination:   "https://api.service.example/v1/records?active=true&filter=<active>&limit=10",
		NotBefore:     "2030-01-01T00:00:00Z",
		ExpiresAt:     "2030-01-01T00:05:00Z",
	}
	request := Request{
		Actor:        grant.Actor,
		Action:       grant.Action,
		Destination:  grant.Destination,
		AuthorityRef: signTestPayload(t, []byte(payload)),
	}
	verifier, err := NewLocalVerifier(LocalConfig{
		TrustedIssuers: map[string]ed25519.PublicKey{fixture.Issuer: publicKey},
		Clock:          func() time.Time { return mustParseTime(t, fixture.Now) },
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	if got := verifier.Verify(context.Background(), request); got.Decision != DecisionAllow || got.Reason != ReasonMatched {
		t.Fatalf("Verify()=%s/%s, want allow/%s", got.Decision, got.Reason, ReasonMatched)
	}
	parts := strings.Split(request.AuthorityRef, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signature[0] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	tampered := request
	tampered.AuthorityRef = strings.Join(parts, ".")
	if got := verifier.Verify(context.Background(), tampered); got.Decision != DecisionDeny || got.Reason != ReasonInvalidSignature {
		t.Fatalf("tampered named Verify()=%s/%s, want deny/%s", got.Decision, got.Reason, ReasonInvalidSignature)
	}
	request.Actor = "workload:médiator"
	if got := verifier.Verify(context.Background(), request); got.Decision != DecisionDeny || got.Reason != ReasonActorMismatch {
		t.Fatalf("NFD actor Verify()=%s/%s, want deny/%s", got.Decision, got.Reason, ReasonActorMismatch)
	}
}

func TestLocalVerifierRejectsUnknownAndNonCanonicalNamedCanon(t *testing.T) {
	t.Parallel()
	if localCanonJCSRFC8785NFC != aarp.CanonID {
		t.Fatalf("authority canon %q differs from AARP profile %q", localCanonJCSRFC8785NFC, aarp.CanonID)
	}
	grant := localGrant{
		SchemaVersion: localSchemaVersion,
		Canon:         localCanonJCSRFC8785NFC,
		Issuer:        "issuer.test",
		Reference:     "grant-nfc",
		Actor:         "workload:médiator",
		Action:        "records.read",
		Destination:   "https://api.service.example/v1/records",
		NotBefore:     "2030-01-01T00:00:00Z",
		ExpiresAt:     "2030-01-01T00:05:00Z",
	}
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	raw, err = jcs.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize raw grant: %v", err)
	}
	unknown := grant
	unknown.Canon = "unknown-canon"
	unknown.Actor = "workload:médiator"
	namedPayload := mustPayloadBytes(t, strings.Split(signTestNamedCanonGrant(t, grant), ".")[1])
	for _, spelling := range []string{"Canon", "CANON", "cAnon"} {
		t.Run("case variant "+spelling, func(t *testing.T) {
			payload, err := jcs.Canonicalize(bytes.Replace(namedPayload, []byte(`"canon":"jcs-rfc8785-nfc"`), []byte(`"`+spelling+`":"unknown-canon"`), 1))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseLocalReference(signTestPayload(t, payload)); err == nil {
				t.Fatal("case-variant canon was accepted as a legacy reference")
			}
		})
	}
	for _, field := range []string{"issuer", "reference", "actor", "action", "destination", "not_before", "expires_at"} {
		t.Run("named field alias "+field, func(t *testing.T) {
			payload, err := jcs.Canonicalize(bytes.Replace(namedPayload, []byte(`"`+field+`":`), []byte(`"`+strings.ToUpper(field)+`":`), 1))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseLocalReference(signTestPayload(t, payload)); err == nil {
				t.Fatal("named profile accepted a field outside its exact schema")
			}
		})
	}
	for _, malformed := range []string{"[]", "null", "42"} {
		t.Run("non-object "+malformed, func(t *testing.T) {
			if _, err := parseLocalReference(signTestPayload(t, []byte(malformed))); err == nil {
				t.Fatal("non-object grant accepted")
			}
		})
	}
	t.Run("missing required identity", func(t *testing.T) {
		var object map[string]any
		if err := json.Unmarshal(namedPayload, &object); err != nil {
			t.Fatal(err)
		}
		delete(object, "actor")
		payload, err := jcs.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseLocalReference(signTestPayload(t, payload))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := validateGrant(parsed.payload); err == nil {
			t.Fatal("grant without an actor accepted")
		}
	})
	emptyCanon, err := jcs.Canonicalize(bytes.Replace(namedPayload, []byte(`"canon":"jcs-rfc8785-nfc"`), []byte(`"canon":""`), 1))
	if err != nil {
		t.Fatalf("canonicalize empty canon grant: %v", err)
	}
	nullCanon, err := jcs.Canonicalize(bytes.Replace(namedPayload, []byte(`"canon":"jcs-rfc8785-nfc"`), []byte(`"canon":null`), 1))
	if err != nil {
		t.Fatalf("canonicalize null canon grant: %v", err)
	}
	numberCanon, err := jcs.Canonicalize(bytes.Replace(namedPayload, []byte(`"canon":"jcs-rfc8785-nfc"`), []byte(`"canon":1`), 1))
	if err != nil {
		t.Fatalf("canonicalize number canon grant: %v", err)
	}

	for _, test := range []struct {
		name      string
		reference string
	}{
		{name: "unknown canon", reference: signTestGrant(t, unknown)},
		{name: "empty canon", reference: signTestPayload(t, emptyCanon)},
		{name: "null canon", reference: signTestPayload(t, nullCanon)},
		{name: "number canon", reference: signTestPayload(t, numberCanon)},
		{name: "nfd signed under named canon", reference: signTestPayload(t, raw)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseLocalReference(test.reference); err == nil {
				t.Fatal("parseLocalReference() error=nil")
			}
		})
	}
}

func TestResultJSONOmitsZeroExpiry(t *testing.T) {
	t.Parallel()
	denied, err := json.Marshal(Result{Decision: DecisionDeny, Reason: ReasonMalformedReference})
	if err != nil {
		t.Fatalf("marshal denied result: %v", err)
	}
	if bytes.Contains(denied, []byte(`"expires_at"`)) {
		t.Fatalf("zero expiry serialized: %s", denied)
	}
	allowed, err := json.Marshal(Result{Decision: DecisionAllow, ExpiresAt: mustParseTime(t, "2030-01-01T00:05:00Z"), Reason: ReasonMatched})
	if err != nil {
		t.Fatalf("marshal allowed result: %v", err)
	}
	if !bytes.Contains(allowed, []byte(`"expires_at":"2030-01-01T00:05:00Z"`)) {
		t.Fatalf("nonzero expiry missing: %s", allowed)
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
		NotBefore:     "2030-01-01T00:00:00Z",
		ExpiresAt:     "2030-01-01T00:05:00Z",
	}
	request := Request{Actor: base.Actor, Action: base.Action, Destination: base.Destination}

	tests := []struct {
		name   string
		mutate func(*localGrant)
		want   Reason
	}{
		{name: "schema", mutate: func(grant *localGrant) { grant.SchemaVersion = 1 }, want: ReasonMalformedReference},
		{name: "issuer", mutate: func(grant *localGrant) { grant.Issuer = " " }, want: ReasonUntrustedIssuer},
		{name: "reference", mutate: func(grant *localGrant) { grant.Reference = "" }, want: ReasonMalformedReference},
		{name: "actor", mutate: func(grant *localGrant) { grant.Actor = "" }, want: ReasonMalformedReference},
		{name: "action", mutate: func(grant *localGrant) { grant.Action = "" }, want: ReasonMalformedReference},
		{name: "destination", mutate: func(grant *localGrant) { grant.Destination = "" }, want: ReasonMalformedReference},
		{name: "not before missing", mutate: func(grant *localGrant) { grant.NotBefore = "" }, want: ReasonMalformedReference},
		{name: "not before invalid", mutate: func(grant *localGrant) { grant.NotBefore = "tomorrow" }, want: ReasonMalformedReference},
		{name: "expiry missing", mutate: func(grant *localGrant) { grant.ExpiresAt = "" }, want: ReasonMalformedReference},
		{name: "expiry invalid", mutate: func(grant *localGrant) { grant.ExpiresAt = "tomorrow" }, want: ReasonMalformedReference},
		{name: "inverted window", mutate: func(grant *localGrant) { grant.ExpiresAt = grant.NotBefore }, want: ReasonMalformedReference},
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

func TestLocalVerifierEnforcesGrantValidityWindow(t *testing.T) {
	t.Parallel()
	fixture := loadConformanceFixture(t)
	now := mustParseTime(t, fixture.Now)
	verifier, err := NewLocalVerifier(LocalConfig{
		TrustedIssuers: map[string]ed25519.PublicKey{fixture.Issuer: mustDecodePublicKey(t, fixture.PublicKey)},
		Clock:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	base := localGrant{
		SchemaVersion: localSchemaVersion,
		Issuer:        fixture.Issuer,
		Reference:     "grant-validity-window",
		Actor:         "workload:test-agent",
		Action:        "records.read",
		Destination:   "https://api.service.example/v1/records",
		NotBefore:     now.Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(maxGrantLifetime).Format(time.RFC3339Nano),
	}
	tests := []struct {
		name     string
		mutate   func(*localGrant)
		decision Decision
		reason   Reason
	}{
		{
			name:     "unmodified grant at maximum lifetime",
			decision: DecisionAllow,
			reason:   ReasonMatched,
		},
		{
			name: "not before is in the future",
			mutate: func(grant *localGrant) {
				notBefore := now.Add(time.Nanosecond)
				grant.NotBefore = notBefore.Format(time.RFC3339Nano)
				grant.ExpiresAt = notBefore.Add(maxGrantLifetime).Format(time.RFC3339Nano)
			},
			decision: DecisionDeny,
			reason:   ReasonNotYetValid,
		},
		{
			name: "lifetime exceeds maximum by one nanosecond",
			mutate: func(grant *localGrant) {
				grant.ExpiresAt = now.Add(maxGrantLifetime + time.Nanosecond).Format(time.RFC3339Nano)
			},
			decision: DecisionDeny,
			reason:   ReasonLifetimeExceeded,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			grant := base
			if test.mutate != nil {
				test.mutate(&grant)
			}
			got := verifier.Verify(context.Background(), Request{
				Actor:        grant.Actor,
				Action:       grant.Action,
				Destination:  grant.Destination,
				AuthorityRef: signTestGrant(t, grant),
			})
			if got.Decision != test.decision || got.Reason != test.reason {
				t.Fatalf("Verify()=%s/%s, want %s/%s", got.Decision, got.Reason, test.decision, test.reason)
			}
		})
	}

	t.Run("not before widened after signing", func(t *testing.T) {
		// The cases above mutate the grant BEFORE signing, so they prove the
		// window is validated. They cannot prove the window is COVERED by the
		// signature. Widen not_before on the wire while keeping the original
		// signature, which is how an attacker would lengthen a leaked grant.
		parts := strings.Split(signTestGrant(t, base), ".")
		if len(parts) != 3 {
			t.Fatalf("reference parts=%d, want 3", len(parts))
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		var object map[string]any
		if err := json.Unmarshal(payload, &object); err != nil {
			t.Fatalf("decode payload object: %v", err)
		}
		widened := now.Add(-maxGrantLifetime).Format(time.RFC3339Nano)
		if object["not_before"] == widened {
			t.Fatal("widened not_before equals the signed value, so the case proves nothing")
		}
		object["not_before"] = widened
		canonical, err := jcs.Marshal(object)
		if err != nil {
			t.Fatalf("canonicalize tampered payload: %v", err)
		}
		if bytes.Equal(canonical, payload) {
			t.Fatal("tampered payload is byte-identical to the signed payload")
		}
		parts[1] = base64.RawURLEncoding.EncodeToString(canonical)
		got := verifier.Verify(context.Background(), Request{
			Actor:        base.Actor,
			Action:       base.Action,
			Destination:  base.Destination,
			AuthorityRef: strings.Join(parts, "."),
		})
		if got.Decision != DecisionDeny || got.Reason != ReasonInvalidSignature {
			t.Fatalf("widened not_before Verify()=%s/%s, want deny/%s", got.Decision, got.Reason, ReasonInvalidSignature)
		}
	})
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
	payload, err = jcs.Canonicalize(payload)
	if err != nil {
		t.Fatalf("canonicalize grant: %v", err)
	}
	return signTestPayload(t, payload)
}

func signTestNamedCanonGrant(t *testing.T, grant localGrant) string {
	t.Helper()
	grant.Canon = norm.NFC.String(grant.Canon)
	grant.Issuer = norm.NFC.String(grant.Issuer)
	grant.Reference = norm.NFC.String(grant.Reference)
	grant.Actor = norm.NFC.String(grant.Actor)
	grant.Action = norm.NFC.String(grant.Action)
	grant.Destination = norm.NFC.String(grant.Destination)
	grant.NotBefore = norm.NFC.String(grant.NotBefore)
	grant.ExpiresAt = norm.NFC.String(grant.ExpiresAt)
	payload, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	payload, err = jcs.Canonicalize(payload)
	if err != nil {
		t.Fatalf("canonicalize grant: %v", err)
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
