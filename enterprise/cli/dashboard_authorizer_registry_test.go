//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

const (
	dashboardRegistryMetadataToken = "registry-metadata-token"
	dashboardRegistryRawToken      = "registry-raw-token"
)

type dashboardRegistryRequestCase string

const (
	requestNone     dashboardRegistryRequestCase = "no authorization"
	requestMetadata dashboardRegistryRequestCase = "metadata"
	requestRaw      dashboardRegistryRequestCase = "raw"
	requestTokenBad dashboardRegistryRequestCase = "invalid static"
	requestMTLS     dashboardRegistryRequestCase = "mapped mTLS"
	requestMTLSBad  dashboardRegistryRequestCase = "unmapped mTLS"
	requestOIDC     dashboardRegistryRequestCase = "verified OIDC"
	requestOIDCBad  dashboardRegistryRequestCase = "invalid OIDC"
)

type dashboardCompositionTestResult struct {
	metaAuthorized      func(*http.Request) bool
	authorizePermission func(*http.Request, dashboard.Permission) error
	rawAuthorized       func(*http.Request) bool
	authAuditInfo       func(*http.Request) dashboard.AuthAuditInfo
	failedAuthMode      func(*http.Request) string
	wrap                func(http.Handler) http.Handler
}

// TestDashboardAuthorizerCompositionTruthTable records the pre-registry
// decision contract. mTLS is deliberately exclusive: when configured, a
// valid token or OIDC principal without a verified mapped certificate denies.
func TestDashboardAuthorizerCompositionTruthTable(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	oidcProvider := newOIDCTestProvider(t)
	oidcAuthenticator := newOIDCTestAuthenticator(t, oidcProvider, now)

	pki := newDashboardMTLSTestPKI(t)
	_, mappedLeaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 301, commonName: "mapped operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	_, unmappedLeaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 302, commonName: "unmapped operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	mappedFingerprint := sha256.Sum256(mappedLeaf.RawSubjectPublicKeyInfo)
	mappedHex := dashboardClientCertSPKIFingerprint(mappedLeaf)
	unmappedHex := dashboardClientCertSPKIFingerprint(unmappedLeaf)
	clientCertAuth := &dashboardClientCertAuthorizer{principals: map[[sha256.Size]byte]dashboardClientCertPrincipal{
		mappedFingerprint: {
			role: "evidence-reader",
			permissions: map[dashboard.Permission]struct{}{
				dashboard.PermissionEvidenceRead: {},
			},
		},
	}}

	type expectation struct {
		requestCase dashboardRegistryRequestCase
		meta        bool
		evidence    bool
		raw         bool
		modeSet     bool
		mode        string
	}
	type testCase struct {
		name   string
		token  bool
		mtls   bool
		oidc   bool
		expect []expectation
	}

	tests := []testCase{
		{
			name: "token only", token: true,
			expect: []expectation{
				{requestCase: requestMetadata, meta: true, evidence: true, modeSet: true, mode: "operator_token"},
				{requestCase: requestRaw, meta: true, evidence: true, raw: true, modeSet: true, mode: "operator_token"},
				{requestCase: requestTokenBad, modeSet: true, mode: "operator_token"},
			},
		},
		{
			name: "mTLS only", mtls: true,
			expect: []expectation{
				{requestCase: requestMTLS, meta: true, evidence: true},
				{requestCase: requestMTLSBad},
			},
		},
		{
			name: "OIDC only", oidc: true,
			expect: []expectation{
				{requestCase: requestOIDC, meta: true, evidence: true, modeSet: true, mode: "operator_token"},
				{requestCase: requestOIDCBad, modeSet: true, mode: "oidc"},
			},
		},
		{
			name: "token and mTLS", token: true, mtls: true,
			expect: []expectation{
				{requestCase: requestMetadata},
				{requestCase: requestRaw},
				{requestCase: requestMTLS, meta: true, evidence: true},
				{requestCase: requestMTLSBad},
			},
		},
		{
			name: "token and OIDC", token: true, oidc: true,
			expect: []expectation{
				{requestCase: requestMetadata, meta: true, evidence: true, modeSet: true, mode: "operator_token"},
				{requestCase: requestRaw, meta: true, evidence: true, raw: true, modeSet: true, mode: "operator_token"},
				{requestCase: requestOIDC, meta: true, evidence: true, modeSet: true, mode: "operator_token"},
				{requestCase: requestTokenBad, modeSet: true, mode: "operator_token"},
				{requestCase: requestOIDCBad, modeSet: true, mode: "oidc"},
			},
		},
		{
			name: "mTLS and OIDC", mtls: true, oidc: true,
			expect: []expectation{
				{requestCase: requestMTLS, meta: true, evidence: true},
				{requestCase: requestOIDC},
				{requestCase: requestMTLSBad},
				{requestCase: requestOIDCBad},
			},
		},
		{
			name: "token mTLS and OIDC", token: true, mtls: true, oidc: true,
			expect: []expectation{
				{requestCase: requestMetadata},
				{requestCase: requestRaw},
				{requestCase: requestMTLS, meta: true, evidence: true},
				{requestCase: requestOIDC},
				{requestCase: requestTokenBad},
				{requestCase: requestMTLSBad},
				{requestCase: requestOIDCBad},
			},
		},
		{
			name: "none",
			expect: []expectation{
				{requestCase: requestNone, modeSet: true, mode: "none"},
				{requestCase: requestTokenBad, modeSet: true, mode: "operator_token"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var configuredClientCertAuth *dashboardClientCertAuthorizer
			if tc.mtls {
				configuredClientCertAuth = clientCertAuth
			}
			var configuredOIDC *dashboardOIDCAuthenticator
			if tc.oidc {
				configuredOIDC = oidcAuthenticator
			}
			composition := currentDashboardAuthorizerComposition(tc.token, configuredClientCertAuth, configuredOIDC)
			if composition.authAuditInfo == nil {
				t.Fatal("auth audit callback is not configured")
			}

			for _, want := range tc.expect {
				want := want
				t.Run(string(want.requestCase), func(t *testing.T) {
					req := dashboardRegistryRequest(t, want.requestCase, mappedLeaf, unmappedLeaf, composition.wrap, oidcProvider, now)
					if got := composition.metaAuthorized(req); got != want.meta {
						t.Fatalf("metaAuthorized = %v, want %v", got, want.meta)
					}
					if got := composition.authorizePermission(req, dashboard.PermissionEvidenceRead) == nil; got != want.evidence {
						t.Fatalf("evidence permission = %v, want %v", got, want.evidence)
					}
					if got := composition.rawAuthorized(req); got != want.raw {
						t.Fatalf("rawAuthorized = %v, want %v", got, want.raw)
					}
					if got := composition.failedAuthMode != nil; got != want.modeSet {
						t.Fatalf("failedAuthMode configured = %v, want %v", got, want.modeSet)
					}
					if want.modeSet {
						if got := composition.failedAuthMode(req); got != want.mode {
							t.Fatalf("failedAuthMode = %q, want %q", got, want.mode)
						}
					}
					// Invoke the composed audit attribution and compare every identity
					// field exactly, so a wrong fingerprint, subject, role or reason
					// fails here rather than only a missing callback.
					got := composition.authAuditInfo(req)
					want := dashboardRegistryExpectedAudit(tc.mtls, want.requestCase, mappedHex, unmappedHex)
					if got.Method != want.Method || got.Subject != want.Subject ||
						got.MTLSSPKISHA256 != want.MTLSSPKISHA256 || got.FailureReason != want.FailureReason ||
						!slices.Equal(got.Roles, want.Roles) {
						t.Fatalf("authAuditInfo = %+v, want %+v", got, want)
					}
				})
			}
		})
	}
}

// dashboardRegistryExpectedAudit is the exact audit attribution the composed
// callback must report. mTLS is exclusive and attributes every request through
// the certificate authorizer; otherwise attribution follows the credential the
// request presented.
func dashboardRegistryExpectedAudit(mtlsConfigured bool, requestCase dashboardRegistryRequestCase, mappedHex, unmappedHex string) dashboard.AuthAuditInfo {
	if mtlsConfigured {
		switch requestCase {
		case requestMTLS:
			return dashboard.AuthAuditInfo{Method: "mtls", MTLSSPKISHA256: mappedHex, Roles: []string{"evidence-reader"}}
		case requestMTLSBad:
			return dashboard.AuthAuditInfo{Method: "mtls", MTLSSPKISHA256: unmappedHex, FailureReason: "unmapped_client_certificate"}
		default:
			return dashboard.AuthAuditInfo{Method: "mtls", FailureReason: "missing_client_certificate"}
		}
	}
	switch requestCase {
	case requestMetadata:
		return dashboard.AuthAuditInfo{Method: "token", Roles: []string{"metadata"}}
	case requestRaw:
		return dashboard.AuthAuditInfo{Method: "raw-access-token", Roles: []string{"raw"}}
	case requestTokenBad:
		return dashboard.AuthAuditInfo{Method: "token", FailureReason: "unknown_principal"}
	case requestOIDC:
		return dashboard.AuthAuditInfo{Method: "oidc", Subject: "operator-a", Roles: []string{"evidence-reader"}}
	case requestOIDCBad:
		return dashboard.AuthAuditInfo{Method: "oidc", FailureReason: "invalid_token"}
	default:
		return dashboard.AuthAuditInfo{Method: "none", FailureReason: "missing_token"}
	}
}

func currentDashboardAuthorizerComposition(
	tokenConfigured bool,
	clientCertAuth *dashboardClientCertAuthorizer,
	oidcAuthenticator *dashboardOIDCAuthenticator,
) dashboardCompositionTestResult {
	metadataToken, rawToken := "", ""
	if tokenConfigured {
		metadataToken, rawToken = dashboardRegistryMetadataToken, dashboardRegistryRawToken
	}
	registry := newDashboardAuthorizerRegistry()
	if tokenConfigured {
		registry.registerStaticTokens(metadataToken, rawToken)
	}
	if clientCertAuth != nil {
		registry.registerClientCertificate(clientCertAuth)
	}
	if oidcAuthenticator != nil {
		registry.registerOIDC(oidcAuthenticator)
	}
	composition := registry.compose()
	return dashboardCompositionTestResult{
		metaAuthorized:      composition.metaAuthorized,
		authorizePermission: composition.authorizePermission,
		rawAuthorized:       composition.rawAuthorized,
		authAuditInfo:       composition.authAuditInfo,
		failedAuthMode:      composition.failedAuthMode,
		wrap:                composition.wrap,
	}
}

func dashboardRegistryRequest(
	t *testing.T,
	requestCase dashboardRegistryRequestCase,
	mappedLeaf, unmappedLeaf *x509.Certificate,
	wrap func(http.Handler) http.Handler,
	oidcProvider *oidcTestProvider,
	now time.Time,
) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://dashboard.example/", nil)
	switch requestCase {
	case requestMetadata:
		req.Header.Set("Authorization", "Bearer "+dashboardRegistryMetadataToken)
	case requestRaw:
		req.Header.Set("Authorization", "Bearer "+dashboardRegistryRawToken)
	case requestTokenBad:
		req.Header.Set("Authorization", "Bearer wrong-token")
	case requestMTLS:
		req = dashboardMTLSTestRequest(t, mappedLeaf, true)
	case requestMTLSBad:
		req = dashboardMTLSTestRequest(t, unmappedLeaf, true)
	case requestOIDC:
		req = requestWithBearer(t, oidcProvider.token(t, oidcProvider.validClaims(now)))
	case requestOIDCBad:
		req = requestWithBearer(t, "not-a-valid-jwt")
	}
	if requestCase != requestOIDC && requestCase != requestOIDCBad {
		return req
	}
	var forwarded *http.Request
	wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		forwarded = r
	})).ServeHTTP(httptest.NewRecorder(), req)
	if forwarded == nil {
		t.Fatal("OIDC middleware did not forward the request")
	}
	return forwarded
}
