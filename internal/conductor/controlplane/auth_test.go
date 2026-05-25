// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestParseFollowerIdentityURI(t *testing.T) {
	uri, err := url.Parse("spiffe://pipelock.test/orgs/org-main/fleets/prod/instances/pl-prod-1/environments/prod")
	if err != nil {
		t.Fatalf("Parse URL: %v", err)
	}
	identity, err := ParseFollowerIdentityURI(uri, "pipelock.test")
	if err != nil {
		t.Fatalf("ParseFollowerIdentityURI() error = %v", err)
	}
	if identity.OrgID != "org-main" || identity.FleetID != "prod" || identity.InstanceID != "pl-prod-1" || identity.Environment != "prod" {
		t.Fatalf("identity = %+v", identity)
	}

	// SPIFFE trust domains are restricted to lowercase ASCII per spec; a peer
	// cert with a non-conforming uppercase host should still match a lowercase
	// configured trust domain so operators can interop with non-conforming
	// issuers without weakening the path-segment match.
	upper, err := url.Parse("spiffe://Pipelock.test/orgs/org-main/fleets/prod/instances/pl-prod-1/environments/prod")
	if err != nil {
		t.Fatalf("Parse upper URL: %v", err)
	}
	if _, err := ParseFollowerIdentityURI(upper, "pipelock.test"); err != nil {
		t.Fatalf("ParseFollowerIdentityURI(mixed-case trust domain) error = %v, want nil", err)
	}
}

func TestParseFollowerIdentityURIRejectsMalformed(t *testing.T) {
	rejections := []struct {
		name string
		raw  string
	}{
		{"wrong scheme", "https://pipelock.test/orgs/org-main/fleets/prod/instances/pl-prod-1/environments/prod"},
		{"wrong trust domain", "spiffe://other.test/orgs/org-main/fleets/prod/instances/pl-prod-1/environments/prod"},
		{"short path", "spiffe://pipelock.test/orgs/org-main"},
		{"swapped segments", "spiffe://pipelock.test/orgs/org-main/instances/pl-prod-1/fleets/prod/environments/prod"},
		{"embedded null byte", "spiffe://pipelock.test/orgs/org-main%00x/fleets/prod/instances/pl-prod-1/environments/prod"},
		{"embedded slash", "spiffe://pipelock.test/orgs/org%2Fmain/fleets/prod/instances/pl-prod-1/environments/prod"},
		{"empty segment", "spiffe://pipelock.test/orgs//fleets/prod/instances/pl-prod-1/environments/prod"},
		{"leading dash", "spiffe://pipelock.test/orgs/-org/fleets/prod/instances/pl-prod-1/environments/prod"},
	}
	for _, c := range rejections {
		t.Run(c.name, func(t *testing.T) {
			uri, err := url.Parse(c.raw)
			if err != nil {
				t.Fatalf("Parse(%q): %v", c.raw, err)
			}
			if _, err := ParseFollowerIdentityURI(uri, "pipelock.test"); !errors.Is(err, ErrFollowerRequired) {
				t.Fatalf("ParseFollowerIdentityURI(%q) error = %v, want ErrFollowerRequired", c.raw, err)
			}
		})
	}
}

func TestMTLSFollowerIdentityResolverRequiresVerifiedClientCertificate(t *testing.T) {
	resolver, err := MTLSFollowerIdentityResolver("pipelock.test")
	if err != nil {
		t.Fatalf("MTLSFollowerIdentityResolver() error = %v", err)
	}
	if _, err := resolver(httptestRequestWithTLS(nil)); !errors.Is(err, ErrFollowerRequired) {
		t.Fatalf("resolver(no TLS) error = %v, want ErrFollowerRequired", err)
	}

	uri, err := url.Parse("spiffe://pipelock.test/orgs/org-main/fleets/prod/instances/pl-prod-1/environments/prod")
	if err != nil {
		t.Fatalf("Parse URL: %v", err)
	}
	req := httptestRequestWithTLS(&tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{uri}}},
		VerifiedChains:   [][]*x509.Certificate{{&x509.Certificate{}}},
	})
	identity, err := resolver(req)
	if err != nil {
		t.Fatalf("resolver(valid TLS) error = %v", err)
	}
	if identity.InstanceID != "pl-prod-1" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestBearerPublisherAuthorizer(t *testing.T) {
	if _, err := BearerPublisherAuthorizer(""); !errors.Is(err, ErrPublisherForbidden) {
		t.Fatalf("BearerPublisherAuthorizer(empty) error = %v, want ErrPublisherForbidden", err)
	}
	authz, err := BearerPublisherAuthorizer("secret-token")
	if err != nil {
		t.Fatalf("BearerPublisherAuthorizer() error = %v", err)
	}
	cases := []struct {
		name      string
		header    string
		setHeader bool
		wantErr   bool
	}{
		{name: "no header", wantErr: true},
		{name: "wrong scheme", setHeader: true, header: "Basic secret-token", wantErr: true},
		{name: "wrong token", setHeader: true, header: "Bearer wrong", wantErr: true},
		{name: "lowercase scheme", setHeader: true, header: "bearer secret-token"},
		{name: "empty token", setHeader: true, header: "Bearer ", wantErr: true},
		{name: "valid", setHeader: true, header: "Bearer secret-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, PublishPolicyBundlePath, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if c.setHeader {
				req.Header.Set("Authorization", c.header)
			}
			err = authz(req)
			if c.wantErr && !errors.Is(err, ErrPublisherForbidden) {
				t.Fatalf("authz() error = %v, want ErrPublisherForbidden", err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("authz() error = %v, want nil", err)
			}
		})
	}
}

func TestStaticAuditKeyResolverHonorsIdentityBinding(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	resolver, err := StaticAuditKeyResolver([]StaticAuditKey{{
		KeyID: "audit-key-1",
		Key: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		OrgID: "org-main",
	}})
	if err != nil {
		t.Fatalf("StaticAuditKeyResolver() error = %v", err)
	}
	key, err := resolver(FollowerIdentity{OrgID: "org-main"}, "audit-key-1")
	if err != nil {
		t.Fatalf("resolver(valid) error = %v", err)
	}
	if len(key.PublicKey) == 0 {
		t.Fatal("resolver returned empty public key")
	}
	if _, err := resolver(FollowerIdentity{OrgID: "other"}, "audit-key-1"); !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("resolver(wrong org) error = %v, want ErrSignatureVerification", err)
	}
	if _, err := resolver(FollowerIdentity{OrgID: "org-main"}, "unknown-key"); !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("resolver(unknown keyID) error = %v, want ErrSignatureVerification", err)
	}
}

func TestStaticAuditKeyResolverRejectsCrossOrgKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key := conductor.SignatureKey{PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning}
	cases := []struct {
		name    string
		keys    []StaticAuditKey
		wantSub string
	}{
		{
			name:    "empty org id",
			keys:    []StaticAuditKey{{KeyID: "k1", Key: key}},
			wantSub: "org_id required",
		},
		{
			name:    "whitespace org id",
			keys:    []StaticAuditKey{{KeyID: "k1", Key: key, OrgID: "   "}},
			wantSub: "org_id required",
		},
		{
			name:    "missing key id",
			keys:    []StaticAuditKey{{Key: key, OrgID: "org-main"}},
			wantSub: "key_id",
		},
		{
			name:    "missing public key",
			keys:    []StaticAuditKey{{KeyID: "k1", OrgID: "org-main"}},
			wantSub: "public_key",
		},
		{
			name:    "short public key",
			keys:    []StaticAuditKey{{KeyID: "k1", Key: conductor.SignatureKey{PublicKey: ed25519.PublicKey("short"), KeyPurpose: signing.PurposeAuditBatchSigning}, OrgID: "org-main"}},
			wantSub: "public_key",
		},
		{
			name:    "wrong purpose",
			keys:    []StaticAuditKey{{KeyID: "k1", Key: conductor.SignatureKey{PublicKey: pub, KeyPurpose: signing.PurposePolicyBundleSigning}, OrgID: "org-main"}},
			wantSub: "key_purpose",
		},
		{
			name:    "invalid key id",
			keys:    []StaticAuditKey{{KeyID: "-k1", Key: key, OrgID: "org-main"}},
			wantSub: "key_id",
		},
		{
			name:    "invalid org id",
			keys:    []StaticAuditKey{{KeyID: "k1", Key: key, OrgID: "-org"}},
			wantSub: "org_id",
		},
		{
			name:    "invalid fleet id",
			keys:    []StaticAuditKey{{KeyID: "k1", Key: key, OrgID: "org-main", FleetID: "fleet/prod"}},
			wantSub: "fleet_id",
		},
		{
			name:    "invalid instance id",
			keys:    []StaticAuditKey{{KeyID: "k1", Key: key, OrgID: "org-main", InstanceID: "pl prod"}},
			wantSub: "instance_id",
		},
		{
			name: "duplicate key id",
			keys: []StaticAuditKey{
				{KeyID: "dup", Key: key, OrgID: "org-main"},
				{KeyID: "dup", Key: key, OrgID: "org-main"},
			},
			wantSub: "duplicate key_id",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := StaticAuditKeyResolver(c.keys)
			if !errors.Is(err, ErrAuditKeyRequired) {
				t.Fatalf("StaticAuditKeyResolver() error = %v, want ErrAuditKeyRequired", err)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("StaticAuditKeyResolver() error = %v, want substring %q", err, c.wantSub)
			}
		})
	}
}

func httptestRequestWithTLS(state *tls.ConnectionState) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil)
	if state != nil {
		req.TLS = state
	}
	return req
}
