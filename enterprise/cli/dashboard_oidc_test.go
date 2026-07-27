//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

const (
	oidcTestAudience = "pipelock-dashboard"
	oidcTestKeyID    = "test-signing-key"
)

func TestDashboardOIDCFailureCategory(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "-"},
		{"missing bearer", errors.New("bearer token is missing"), "missing_token"},
		{"missing issuer claim is invalid token", errors.New("OIDC issuer claim is missing or does not match"), "invalid_token"},
		{"missing audience claim is invalid token", errors.New("OIDC audience claim is missing or does not match"), "invalid_token"},
		{"missing subject claim is invalid token", errors.New("OIDC subject claim is missing or invalid"), "invalid_token"},
		{"signature", errors.New("token signature is invalid"), "invalid_signature"},
		{"expired", errors.New("token has expired"), "expired"},
		{"unmapped role", errors.New("role claim has no mapped value"), "permission_denied"},
		{"unknown signing key", dashboardOIDCSigningKeyNotFound("kid-a"), "unknown_principal"},
		{"unknown signing key kid cannot steer expired category", dashboardOIDCSigningKeyNotFound("expired"), "unknown_principal"},
		{"unknown signing key kid cannot steer signature category", dashboardOIDCSigningKeyNotFound("bad signature"), "unknown_principal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := dashboardOIDCFailureCategory(tc.err); got != tc.want {
				t.Fatalf("dashboardOIDCFailureCategory(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

type oidcTestProvider struct {
	server    *httptest.Server
	private   *rsa.PrivateKey
	keyID     string
	mu        sync.Mutex
	jwksFail  bool
	jwksBlock <-chan struct{}
	jwksStart chan<- struct{}
	jwksReads atomic.Int32
}

func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p := &oidcTestProvider{private: private, keyID: oidcTestKeyID}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"authorization_endpoint":%q}`,
				p.server.URL, p.server.URL+"/jwks", p.server.URL+"/authorize")
		case "/jwks":
			p.jwksReads.Add(1)
			if p.jwksShouldFail() {
				http.Error(w, "JWKS unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := p.waitForJWKSBlock(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusGatewayTimeout)
				return
			}
			w.Header().Set("Cache-Control", "max-age=3600")
			keyID, public := p.jwksKey()
			n := base64.RawURLEncoding.EncodeToString(public.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes())
			_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q,"x5c":[]}]}`,
				keyID, n, e)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *oidcTestProvider) jwksKey() (string, rsa.PublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keyID, p.private.PublicKey
}

func (p *oidcTestProvider) signingKey() *rsa.PrivateKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.private
}

func (p *oidcTestProvider) rotateSigningKey(t *testing.T, keyID string) {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(rotated): %v", err)
	}
	p.mu.Lock()
	p.private = private
	p.keyID = keyID
	p.mu.Unlock()
}

func (p *oidcTestProvider) setJWKSFail(fail bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jwksFail = fail
}

func (p *oidcTestProvider) jwksShouldFail() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwksFail
}

func (p *oidcTestProvider) setJWKSBlock(block <-chan struct{}, start chan<- struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jwksBlock = block
	p.jwksStart = start
}

func (p *oidcTestProvider) waitForJWKSBlock(ctx context.Context) error {
	p.mu.Lock()
	block := p.jwksBlock
	start := p.jwksStart
	p.mu.Unlock()
	if block == nil {
		return nil
	}
	if start != nil {
		select {
		case start <- struct{}{}:
		default:
		}
	}
	select {
	case <-block:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *oidcTestProvider) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	keyID, _ := p.jwksKey()
	return p.tokenWithHeader(t, map[string]any{"alg": "RS256", "kid": keyID, "typ": "JWT"}, claims, true)
}

func (p *oidcTestProvider) tokenWithHeader(t *testing.T, header, claims map[string]any, sign bool) string {
	t.Helper()
	encode := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("Marshal JWT: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signingInput := encode(header) + "." + encode(claims)
	if !sign {
		return signingInput + "."
	}
	return p.signInput(t, signingInput)
}

func (p *oidcTestProvider) signInput(t *testing.T, signingInput string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.signingKey(), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (p *oidcTestProvider) validClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":    p.server.URL,
		"sub":    "operator-a",
		"aud":    oidcTestAudience,
		"azp":    oidcTestAudience,
		"exp":    now.Add(5 * time.Minute).Unix(),
		"nbf":    now.Add(-time.Minute).Unix(),
		"groups": []string{"evidence-team"},
	}
}

func oidcTestRoleMap() string {
	return `{"claim_values":{"evidence-team":"evidence-reader","raw-team":"raw-reader"},` +
		`"roles":{"evidence-reader":["dashboard:evidence:read"],` +
		`"raw-reader":["dashboard:evidence:read","dashboard:raw:read"]}}`
}

func oidcTestAuditHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:])
}

func newOIDCTestAuthenticator(t *testing.T, p *oidcTestProvider, now time.Time) *dashboardOIDCAuthenticator {
	t.Helper()
	auth, err := newDashboardOIDCAuthenticator(context.Background(), dashboardOIDCOptions{
		Issuer:       p.server.URL,
		Audience:     oidcTestAudience,
		RoleClaim:    "groups",
		RoleMapJSON:  oidcTestRoleMap(),
		HTTPClient:   p.server.Client(),
		Now:          func() time.Time { return now },
		JWKSCacheTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("newDashboardOIDCAuthenticator: %v", err)
	}
	return auth
}

func requestWithBearer(t *testing.T, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func TestDashboardOIDCAuthenticate_VerifiesTokenAndMapsPermissions(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)

	principal, err := auth.authenticate(requestWithBearer(t, p.token(t, p.validClaims(now))))
	if err != nil {
		t.Fatalf("authenticate valid token: %v", err)
	}
	if principal.Subject != "operator-a" {
		t.Fatalf("Subject = %q, want operator-a", principal.Subject)
	}
	if !principal.hasPermission(dashboard.PermissionEvidenceRead) {
		t.Fatalf("mapped principal missing %s", dashboard.PermissionEvidenceRead)
	}
	if principal.hasPermission(dashboard.PermissionRawRead) {
		t.Fatalf("evidence-only principal unexpectedly has %s", dashboard.PermissionRawRead)
	}
	if got := p.jwksReads.Load(); got != 1 {
		t.Fatalf("JWKS reads = %d, want one cached fetch", got)
	}
}

func TestDecodeDashboardJWTJSONRejectsDuplicateMembers(t *testing.T) {
	tests := []string{
		`{"alg":"none","alg":"RS256"}`,
		`{"claims":{"iss":"first","iss":"second"}}`,
	}
	for _, input := range tests {
		var decoded any
		if err := decodeDashboardJWTJSON([]byte(input), &decoded); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("decodeDashboardJWTJSON(%s) error = %v, want duplicate rejection", input, err)
		}
	}
}

func TestDecodeDashboardJWTJSONRejectsExcessiveNesting(t *testing.T) {
	input := strings.Repeat("[", dashboardOIDCMaxJSONDepth+1) + "0" +
		strings.Repeat("]", dashboardOIDCMaxJSONDepth+1)
	var decoded any
	err := decodeDashboardJWTJSON([]byte(input), &decoded)
	if err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("decodeDashboardJWTJSON excessive nesting error = %v, want depth rejection", err)
	}

	input = strings.Repeat("[", dashboardOIDCMaxJSONDepth) + "0" +
		strings.Repeat("]", dashboardOIDCMaxJSONDepth)
	if err := decodeDashboardJWTJSON([]byte(input), &decoded); err != nil {
		t.Fatalf("decodeDashboardJWTJSON at depth limit: %v", err)
	}
}

func TestDashboardOIDCAuthenticate_FailsClosed(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)

	tests := []struct {
		name  string
		token func(*testing.T) string
	}{
		{
			name: "expired",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["exp"] = now.Add(-time.Minute).Unix()
				return p.token(t, claims)
			},
		},
		{
			name: "missing expiration",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				delete(claims, "exp")
				return p.token(t, claims)
			},
		},
		{
			name: "not yet valid beyond leeway",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["nbf"] = now.Add(time.Minute).Unix()
				return p.token(t, claims)
			},
		},
		{
			name: "invalid not-before type",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["nbf"] = "soon"
				return p.token(t, claims)
			},
		},
		{
			name: "wrong audience",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["aud"] = "different-dashboard"
				return p.token(t, claims)
			},
		},
		{
			name: "wrong issuer",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["iss"] = "https://issuer.example"
				return p.token(t, claims)
			},
		},
		{
			name: "wrong authorized party",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["azp"] = "different-client"
				return p.token(t, claims)
			},
		},
		{
			name: "invalid authorized party type",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["azp"] = []string{oidcTestAudience}
				return p.token(t, claims)
			},
		},
		{
			name: "multiple audiences without authorized party",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["aud"] = []string{oidcTestAudience, "another-service"}
				delete(claims, "azp")
				return p.token(t, claims)
			},
		},
		{
			name: "tampered signature",
			token: func(t *testing.T) string {
				token := p.token(t, p.validClaims(now))
				parts := strings.Split(token, ".")
				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatalf("DecodeString signature: %v", err)
				}
				sig[0] ^= 0xff
				parts[2] = base64.RawURLEncoding.EncodeToString(sig)
				return strings.Join(parts, ".")
			},
		},
		{
			name: "alg none",
			token: func(t *testing.T) string {
				return p.tokenWithHeader(t, map[string]any{"alg": "none", "kid": oidcTestKeyID}, p.validClaims(now), false)
			},
		},
		{
			name: "alg none mixed case",
			token: func(t *testing.T) string {
				return p.tokenWithHeader(t, map[string]any{"alg": "nOnE", "kid": oidcTestKeyID}, p.validClaims(now), true)
			},
		},
		{
			name: "missing algorithm",
			token: func(t *testing.T) string {
				return p.tokenWithHeader(t, map[string]any{"kid": oidcTestKeyID}, p.validClaims(now), true)
			},
		},
		{
			name: "algorithm confusion",
			token: func(t *testing.T) string {
				return p.tokenWithHeader(t, map[string]any{"alg": "HS256", "kid": oidcTestKeyID}, p.validClaims(now), true)
			},
		},
		{
			name: "unmapped role",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["groups"] = []string{"unmapped-team"}
				return p.token(t, claims)
			},
		},
		{
			name: "missing subject",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				delete(claims, "sub")
				return p.token(t, claims)
			},
		},
		{
			name: "empty subject",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["sub"] = ""
				return p.token(t, claims)
			},
		},
		{
			name: "invalid role claim type",
			token: func(t *testing.T) string {
				claims := p.validClaims(now)
				claims["groups"] = map[string]string{"team": "evidence-team"}
				return p.token(t, claims)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if principal, err := auth.authenticate(requestWithBearer(t, tc.token(t))); err == nil || principal != nil {
				t.Fatalf("authenticate = (%+v, %v), want nil principal and error", principal, err)
			}
		})
	}
}

func TestDashboardOIDCAuthenticate_RejectsMalformedJWT(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	validHeader := encode(`{"alg":"RS256","kid":"test-signing-key"}`)
	tests := []struct {
		name  string
		token string
	}{
		{"missing", ""},
		{"overlong", strings.Repeat("a", dashboardOIDCMaxTokenSize+1)},
		{"wrong segment count", "a.b"},
		{"bad header base64", "!.payload.signature"},
		{"bad header JSON", encode("{") + ".payload.signature"},
		{"missing kid", p.tokenWithHeader(t, map[string]any{"alg": "RS256"}, p.validClaims(now), true)},
		{"critical header", p.tokenWithHeader(t, map[string]any{"alg": "RS256", "kid": oidcTestKeyID, "crit": []string{"unknown"}}, p.validClaims(now), true)},
		{"bad signature base64", validHeader + ".payload.!"},
		{"bad payload base64", p.signInput(t, validHeader+".!")},
		{"bad payload JSON", p.signInput(t, validHeader+"."+encode("{"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if principal, err := auth.authenticate(requestWithBearer(t, tc.token)); err == nil || principal != nil {
				t.Fatalf("authenticate = (%+v, %v), want denial", principal, err)
			}
		})
	}
}

func TestDashboardOIDC_RoutePermissionsOnly(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	authorization := newDashboardRequestAuthorization("", "", auth)

	inner := dashboard.New(dashboard.Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          func(string) bool { return true },
		Authorize:           dashboardAuthorizeFunc(authorization.metaAuthorized),
		AuthorizePermission: authorization.authorizePermission,
		AuthorizeRaw:        dashboardAuthorizeFunc(authorization.rawAuthorized),
	})
	handler := authorization.wrap(inner, nil)
	token := p.token(t, p.validClaims(now))

	tests := []struct {
		name string
		path string
		want int
	}{
		{"mapped evidence route", "/", http.StatusOK},
		{"unmapped exemptions permission", "/exemptions", http.StatusForbidden},
		{"unmapped fleet permission", "/fleet", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := requestWithBearer(t, token)
			req.URL.Path = tc.path
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func TestDashboardRequestAuthorization_AuthAuditInfoTokenMethodsAndFailures(t *testing.T) {
	authorization := newDashboardRequestAuthorization("metadata-token", "raw-token", nil)

	tests := []struct {
		name       string
		setup      func(*http.Request)
		wantMethod string
		wantRoles  []string
		wantReason string
	}{
		{
			name: "metadata token",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer metadata-token")
			},
			wantMethod: "token",
			wantRoles:  []string{"metadata"},
		},
		{
			name: "raw access token",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer raw-token")
			},
			wantMethod: "raw-access-token",
			wantRoles:  []string{"raw"},
		},
		{
			name: "wrong token attempted",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer wrong-token")
			},
			wantMethod: "token",
			wantReason: "unknown_principal",
		},
		{
			name:       "no credential",
			setup:      func(*http.Request) {},
			wantMethod: "none",
			wantReason: "missing_token",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://dashboard.example/", nil)
			tc.setup(req)
			got := authorization.authAuditInfo(req)
			if got.Method != tc.wantMethod {
				t.Fatalf("Method = %q, want %q", got.Method, tc.wantMethod)
			}
			if strings.Join(got.Roles, ",") != strings.Join(tc.wantRoles, ",") {
				t.Fatalf("Roles = %v, want %v", got.Roles, tc.wantRoles)
			}
			if got.FailureReason != tc.wantReason {
				t.Fatalf("FailureReason = %q, want %q", got.FailureReason, tc.wantReason)
			}
		})
	}
}

func TestDashboardCredentialAttemptedNilRequest(t *testing.T) {
	if dashboardCredentialAttempted(nil) {
		t.Fatal("nil request reported a credential attempt")
	}
}

func TestDashboardOIDC_OIDCOnlyModeRejectsEmptyCredentials(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	// OIDC-only deployment: all static operator tokens are empty, so every
	// optional-token match must fail at the call site before comparing request
	// credentials. Missing, empty, or malformed credentials must never
	// authorize; only a verified OIDC bearer may.
	authorization := newDashboardRequestAuthorization("", "", auth)
	inner := dashboard.New(dashboard.Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          func(string) bool { return true },
		Authorize:           dashboardAuthorizeFunc(authorization.metaAuthorized),
		AuthorizePermission: authorization.authorizePermission,
		AuthorizeRaw:        dashboardAuthorizeFunc(authorization.rawAuthorized),
	})
	handler := authorization.wrap(inner, nil)

	newReq := func(mutate func(*http.Request)) *http.Request {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if mutate != nil {
			mutate(req)
		}
		return req
	}

	tests := []struct {
		name    string
		request *http.Request
	}{
		{"no authorization header", newReq(nil)},
		{"empty bearer", newReq(func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") })},
		{"basic empty password", newReq(func(r *http.Request) { r.SetBasicAuth("operator", "") })},
		{"basic empty user and password", newReq(func(r *http.Request) { r.SetBasicAuth("", "") })},
		{"malformed bearer", newReq(func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-jwt") })},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, tc.request)
			if rr.Code == http.StatusOK {
				t.Fatalf("OIDC-only mode authorized %s (status %d); empty configured tokens must fail closed", tc.name, rr.Code)
			}
		})
	}
}

func TestDashboardOIDC_AuditRecordsPrincipalAndDeniedOIDCFailure(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	authorization := newDashboardRequestAuthorization("", "", auth)
	var audit strings.Builder
	inner := dashboard.New(dashboard.Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          func(string) bool { return true },
		Authorize:           dashboardAuthorizeFunc(authorization.metaAuthorized),
		AuthorizePermission: authorization.authorizePermission,
		AuthorizeRaw:        dashboardAuthorizeFunc(authorization.rawAuthorized),
		AuditWriter:         &audit,
	})
	handler := authorization.wrap(inner, &audit)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestWithBearer(t, p.token(t, p.validClaims(now))))
	if rr.Code != http.StatusOK {
		t.Fatalf("valid OIDC request status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	log := audit.String()
	for _, want := range []string{
		"pipelock-dashboard access",
		"permission=\"dashboard:evidence:read\"",
		"auth_method=oidc",
		fmt.Sprintf("auth_subject_sha256=%q", oidcTestAuditHash("operator-a")),
		`mtls_spki_sha256="-"`,
		"auth_roles=\"evidence-reader\"",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("audit log missing %q: %s", want, log)
		}
	}
	if strings.Contains(log, p.token(t, p.validClaims(now))) {
		t.Fatalf("audit log leaked bearer token: %s", log)
	}
	if strings.Contains(log, "auth_subject=\"operator-a\"") {
		t.Fatalf("audit log leaked raw OIDC subject: %s", log)
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, requestWithBearer(t, "not-a-jwt"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("malformed OIDC request status = %d, want 401", rr.Code)
	}
	log = audit.String()
	for _, want := range []string{
		"pipelock-dashboard denied",
		"auth_method=oidc",
		`auth_subject_sha256="-"`,
		"reason=invalid_token",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("denied audit log missing %q: %s", want, log)
		}
	}
}

func TestDashboardOIDC_RawPermission(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	authorization := newDashboardRequestAuthorization("", "", auth)

	claims := p.validClaims(now)
	claims["groups"] = []string{"raw-team"}
	req := requestWithBearer(t, p.token(t, claims))
	rr := httptest.NewRecorder()
	authorization.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorization.rawAuthorized(r) {
			t.Error("raw-mapped OIDC principal was denied raw authorization")
		}
		if err := authorization.authorizePermission(r, dashboard.PermissionRawRead); err != nil {
			t.Errorf("raw-mapped OIDC principal denied raw permission: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}), nil).ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestDashboardOIDC_JWKSCacheRefreshesAfterExpiry(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	token := p.token(t, p.validClaims(now))

	if _, err := auth.authenticate(requestWithBearer(t, token)); err != nil {
		t.Fatalf("first authenticate: %v", err)
	}
	auth.keys.mu.Lock()
	auth.keys.expiresAt = now.Add(-time.Second)
	auth.keys.mu.Unlock()
	if _, err := auth.authenticate(requestWithBearer(t, token)); err != nil {
		t.Fatalf("authenticate after cache expiry: %v", err)
	}
	if got := p.jwksReads.Load(); got != 2 {
		t.Fatalf("JWKS reads = %d, want initial fetch plus expiry refresh", got)
	}
}

func TestDashboardOIDC_UnknownKeyRefreshIsRateLimited(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	p.setJWKSFail(true)
	auth.keys.mu.Lock()
	auth.keys.expiresAt = now.Add(-time.Second)
	auth.keys.mu.Unlock()

	for _, kid := range []string{"unknown-key-a", "unknown-key-b", "unknown-key-c"} {
		token := p.tokenWithHeader(t, map[string]any{"alg": "RS256", "kid": kid}, p.validClaims(now), true)
		if principal, err := auth.authenticate(requestWithBearer(t, token)); err == nil || principal != nil {
			t.Fatalf("unknown signing key authenticate = (%+v, %v), want denial", principal, err)
		}
	}
	if got := p.jwksReads.Load(); got != 2 {
		t.Fatalf("JWKS reads = %d, want initial fetch plus one gated unknown-kid refresh", got)
	}
}

func TestDashboardOIDC_UnknownKeyRefreshCanFindRotatedKey(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)

	auth.keys.mu.Lock()
	auth.keys.keys = map[string]*rsa.PublicKey{}
	auth.keys.expiresAt = now.Add(time.Hour)
	auth.keys.mu.Unlock()

	if _, err := auth.authenticate(requestWithBearer(t, p.token(t, p.validClaims(now)))); err != nil {
		t.Fatalf("authenticate after refresh restored key: %v", err)
	}
	if got := p.jwksReads.Load(); got != 2 {
		t.Fatalf("JWKS reads = %d, want initial fetch plus rotation refresh", got)
	}
}

func TestDashboardOIDC_UnknownKidAttackerCannotPersistentlyStarveRotatedKey(t *testing.T) {
	currentNow := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth, err := newDashboardOIDCAuthenticator(context.Background(), dashboardOIDCOptions{
		Issuer:       p.server.URL,
		Audience:     oidcTestAudience,
		RoleClaim:    "groups",
		RoleMapJSON:  oidcTestRoleMap(),
		HTTPClient:   p.server.Client(),
		Now:          func() time.Time { return currentNow },
		JWKSCacheTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("newDashboardOIDCAuthenticator: %v", err)
	}

	attackerToken := p.tokenWithHeader(t, map[string]any{"alg": "RS256", "kid": "attacker-bogus-a"}, p.validClaims(currentNow), true)
	if principal, err := auth.authenticate(requestWithBearer(t, attackerToken)); err == nil || principal != nil {
		t.Fatalf("attacker unknown kid authenticate = (%+v, %v), want denial", principal, err)
	}
	if got := p.jwksReads.Load(); got != 2 {
		t.Fatalf("JWKS reads after attacker miss = %d, want initial fetch plus attacker-triggered refresh", got)
	}

	p.rotateSigningKey(t, "rotated-legitimate-key")
	legitimateToken := p.token(t, p.validClaims(currentNow))
	if principal, err := auth.authenticate(requestWithBearer(t, legitimateToken)); err == nil || principal != nil {
		t.Fatalf("legitimate rotated kid inside attacker window = (%+v, %v), want bounded denial", principal, err)
	}
	if got := p.jwksReads.Load(); got != 2 {
		t.Fatalf("JWKS reads inside attacker miss window = %d, want no throttled refresh", got)
	}

	currentNow = currentNow.Add(dashboardOIDCMinKeyRefresh)
	nextAttackerToken := p.tokenWithHeader(t, map[string]any{"alg": "RS256", "kid": "attacker-bogus-b"}, p.validClaims(currentNow), true)
	if principal, err := auth.authenticate(requestWithBearer(t, nextAttackerToken)); err == nil || principal != nil {
		t.Fatalf("next attacker unknown kid authenticate = (%+v, %v), want denial", principal, err)
	}
	if got := p.jwksReads.Load(); got != 3 {
		t.Fatalf("JWKS reads after next attacker window = %d, want another bounded refresh", got)
	}

	if _, err := auth.authenticate(requestWithBearer(t, p.token(t, p.validClaims(currentNow)))); err != nil {
		t.Fatalf("legitimate rotated kid after attacker-triggered refresh: %v", err)
	}
}

func TestDashboardOIDC_ExpiredJWKSRefreshIgnoresPriorUnknownKeyThrottle(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)

	auth.keys.mu.Lock()
	auth.keys.keys = map[string]*rsa.PublicKey{}
	auth.keys.expiresAt = now.Add(-time.Second)
	auth.keys.lastMiss = now.Add(-2 * time.Second)
	auth.keys.mu.Unlock()

	if _, err := auth.authenticate(requestWithBearer(t, p.token(t, p.validClaims(now)))); err != nil {
		t.Fatalf("authenticate after expired cache refresh with prior unknown-kid miss: %v", err)
	}
	if got := p.jwksReads.Load(); got != 2 {
		t.Fatalf("JWKS reads = %d, want initial fetch plus expired-cache refresh", got)
	}
}

func TestDashboardOIDC_JWKSCacheMissingKeyAfterInitialRefreshFailsClosed(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	cache := &dashboardJWKSCache{
		uri:    p.server.URL + "/jwks",
		client: p.server.Client(),
		now:    func() time.Time { return now },
		ttl:    time.Hour,
	}
	if key, err := cache.key(context.Background(), "missing-key"); err == nil || key != nil {
		t.Fatalf("cache.key missing key = (%v, %v), want fail-closed miss", key, err)
	}
	if got := p.jwksReads.Load(); got != 1 {
		t.Fatalf("JWKS reads = %d, want one initial refresh", got)
	}
}

func TestDashboardOIDC_JWKSCacheCoalescesConcurrentRefresh(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	token := p.token(t, p.validClaims(now))
	block := make(chan struct{})
	start := make(chan struct{}, 1)
	p.setJWKSBlock(block, start)
	defer p.setJWKSBlock(nil, nil)

	auth.keys.mu.Lock()
	auth.keys.expiresAt = now.Add(-time.Second)
	auth.keys.mu.Unlock()

	const requests = 8
	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := auth.authenticate(requestWithBearer(t, token))
			errs <- err
		}()
	}
	select {
	case <-start:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for JWKS refresh to start")
	}
	close(block)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("authenticate during coalesced refresh: %v", err)
		}
	}
	if got := p.jwksReads.Load(); got != 2 {
		t.Fatalf("JWKS reads = %d, want initial fetch plus one coalesced refresh", got)
	}
}

func TestDashboardOIDC_StaticTokenRemainsAdditive(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	authorization := newDashboardRequestAuthorization(dashTestToken, "", auth)

	rr := httptest.NewRecorder()
	authorization.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorization.metaAuthorized(r) {
			t.Error("existing static token was denied when OIDC was also configured")
		}
		w.WriteHeader(http.StatusNoContent)
	}), nil).ServeHTTP(rr, requestWithBearer(t, dashTestToken))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestParseDashboardOIDCRoleMap_FailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"empty", "", "role map"},
		{"malformed JSON", "{", "--oidc-role-map"},
		{"empty maps", `{"claim_values":{},"roles":{}}`, "claim_values"},
		{"unknown role", `{"claim_values":{"team":"missing"},"roles":{"reader":["dashboard:evidence:read"]}}`, "missing"},
		{"empty permissions", `{"claim_values":{"team":"reader"},"roles":{"reader":[]}}`, "permission"},
		{"unknown permission", `{"claim_values":{"team":"reader"},"roles":{"reader":["dashboard:unknown"]}}`, "dashboard:unknown"},
		{"unknown field", `{"claim_values":{"team":"reader"},"roles":{"reader":["dashboard:evidence:read"]},"extra":true}`, "unknown field"},
		{"trailing JSON", oidcTestRoleMap() + `{}`, "trailing"},
		{"empty role name", `{"claim_values":{"team":""},"roles":{"": ["dashboard:evidence:read"]}}`, "role name"},
		{"empty claim value", `{"claim_values":{"":"reader"},"roles":{"reader":["dashboard:evidence:read"]}}`, "claim value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDashboardOIDCRoleMap(tc.value); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parseDashboardOIDCRoleMap error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestDashboardOIDCConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    dashboardServeOptions
		wantErr string
	}{
		{"token only", dashboardServeOptions{authTokenFile: "token"}, ""},
		{"OIDC only", dashboardServeOptions{oidcIssuer: "https://issuer.example", oidcAudience: oidcTestAudience, oidcRoleClaim: "groups", oidcRoleMap: oidcTestRoleMap()}, ""},
		// A verified client certificate is a complete sole authenticator: the
		// mapped cert role supplies route + raw permissions and an absent/wrong/
		// unmapped cert is denied. Rejecting cert-only contradicts the flag help.
		{"client cert only", dashboardServeOptions{requireClientCert: true}, ""},
		{"no authenticator lists cert mode", dashboardServeOptions{}, "require-client-cert"},
		{"no authenticator", dashboardServeOptions{}, "auth-token-file"},
		{"OIDC missing audience", dashboardServeOptions{oidcIssuer: "https://issuer.example", oidcRoleClaim: "groups", oidcRoleMap: oidcTestRoleMap()}, "audience"},
		{"OIDC missing role claim", dashboardServeOptions{oidcIssuer: "https://issuer.example", oidcAudience: oidcTestAudience, oidcRoleMap: oidcTestRoleMap()}, "role-claim"},
		{"OIDC empty role map", dashboardServeOptions{oidcIssuer: "https://issuer.example", oidcAudience: oidcTestAudience, oidcRoleClaim: "groups"}, "role-map"},
		{"OIDC option without issuer", dashboardServeOptions{authTokenFile: "token", oidcAudience: oidcTestAudience}, "oidc-issuer"},
		{"raw token without metadata token", dashboardServeOptions{rawTokenFile: "raw", oidcIssuer: "https://issuer.example", oidcAudience: oidcTestAudience, oidcRoleClaim: "groups", oidcRoleMap: oidcTestRoleMap()}, "raw-token-file"},
		{"conflicting audience aliases", dashboardServeOptions{oidcIssuer: "https://issuer.example", oidcAudience: "aud-a", oidcClientID: "aud-b", oidcRoleClaim: "groups", oidcRoleMap: oidcTestRoleMap()}, "must match"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDashboardAuthenticatorConfig(tc.opts)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("validateDashboardAuthenticatorConfig: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestDashboardOIDCURLValidation(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"HTTPS", "https://issuer.example/tenant", false},
		{"loopback HTTP v4", "http://127.0.0.1:8080", false},
		{"loopback HTTP v6", "http://[::1]:8080", false},
		{"public HTTP", "http://issuer.example", true},
		{"credentials", "https://operator@issuer.example", true},
		{"query", "https://issuer.example?tenant=a", true},
		{"relative", "/issuer", true},
		{"malformed", "://", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDashboardOIDCURL("issuer", tc.value)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateDashboardOIDCURL(%q) = %v, wantErr %v", tc.value, err, tc.wantErr)
			}
		})
	}
}

func TestParseDashboardRSAJWK(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	encodeInt := func(value *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(value.Bytes())
	}
	valid := dashboardJWK{
		KeyType: "RSA", KeyID: "key-a", Use: "sig", Alg: "RS256",
		N: encodeInt(private.N), E: encodeInt(big.NewInt(int64(private.E))),
	}
	tests := []struct {
		name    string
		mutate  func(*dashboardJWK)
		wantKey bool
		wantErr bool
	}{
		{"valid", func(*dashboardJWK) {}, true, false},
		{"wrong key type ignored", func(j *dashboardJWK) { j.KeyType = "EC" }, false, false},
		{"wrong use ignored", func(j *dashboardJWK) { j.Use = "enc" }, false, false},
		{"wrong algorithm ignored", func(j *dashboardJWK) { j.Alg = "RS512" }, false, false},
		{"key ops without verify ignored", func(j *dashboardJWK) { j.KeyOps = []string{"sign"} }, false, false},
		{"empty key id", func(j *dashboardJWK) { j.KeyID = "" }, false, true},
		{"bad modulus encoding", func(j *dashboardJWK) { j.N = "!" }, false, true},
		{"bad exponent encoding", func(j *dashboardJWK) { j.E = "!" }, false, true},
		{"weak modulus", func(j *dashboardJWK) { j.N = encodeInt(big.NewInt(17)) }, false, true},
		{"maximum modulus", func(j *dashboardJWK) { j.N = encodeInt(new(big.Int).Lsh(big.NewInt(1), dashboardOIDCRSAMaxBits-1)) }, true, false},
		{"oversize modulus", func(j *dashboardJWK) { j.N = encodeInt(new(big.Int).Lsh(big.NewInt(1), dashboardOIDCRSAMaxBits)) }, false, true},
		{"even exponent", func(j *dashboardJWK) { j.E = encodeInt(big.NewInt(4)) }, false, true},
		{"huge exponent", func(j *dashboardJWK) { j.E = encodeInt(new(big.Int).Lsh(big.NewInt(1), 80)) }, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jwk := valid
			tc.mutate(&jwk)
			key, included, err := parseDashboardRSAJWK(jwk)
			if (err != nil) != tc.wantErr || included != tc.wantKey || (key != nil) != tc.wantKey {
				t.Fatalf("parseDashboardRSAJWK = (key=%v, included=%v, err=%v), wantKey %v wantErr %v",
					key != nil, included, err, tc.wantKey, tc.wantErr)
			}
		})
	}
}

func TestDashboardOIDCClaimParsers(t *testing.T) {
	t.Run("audience forms", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			raw     string
			wantErr bool
		}{
			{"string", `"dashboard"`, false},
			{"array", `["dashboard","other"]`, false},
			{"empty string", `""`, true},
			{"empty array", `[]`, true},
			{"wrong type", `{}`, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := audienceClaim(json.RawMessage(tc.raw))
				if (err != nil) != tc.wantErr {
					t.Fatalf("audienceClaim = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})
	t.Run("numeric dates", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			claims   map[string]json.RawMessage
			required bool
			wantErr  bool
		}{
			{"valid", map[string]json.RawMessage{"exp": json.RawMessage(`2000000000`)}, true, false},
			{"optional missing", nil, false, false},
			{"required missing", nil, true, true},
			{"string rejected", map[string]json.RawMessage{"exp": json.RawMessage(`"2000000000"`)}, true, true},
			{"fraction rejected", map[string]json.RawMessage{"exp": json.RawMessage(`1.5`)}, true, true},
			{"negative rejected", map[string]json.RawMessage{"exp": json.RawMessage(`-1`)}, true, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := numericDateClaim(tc.claims, "exp", tc.required)
				if (err != nil) != tc.wantErr {
					t.Fatalf("numericDateClaim = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})
	t.Run("role forms", func(t *testing.T) {
		for _, tc := range []struct {
			raw     string
			wantErr bool
		}{
			{`"team"`, false}, {`["team","other"]`, false}, {`""`, true}, {`[]`, true}, {`{}`, true},
		} {
			_, err := roleClaimValues(json.RawMessage(tc.raw))
			if (err != nil) != tc.wantErr {
				t.Fatalf("roleClaimValues(%s) = %v, wantErr %v", tc.raw, err, tc.wantErr)
			}
		}
	})
}

func TestDashboardOIDCAuthenticatorRejectsBadDiscovery(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		wantErr string
	}{
		{"HTTP error", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusBadGateway) }), "HTTP 502"},
		{"malformed JSON", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) }), "unexpected EOF"},
		{"trailing JSON", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{} {}`)) }), "trailing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			_, err := newDashboardOIDCAuthenticator(context.Background(), dashboardOIDCOptions{
				Issuer: server.URL, Audience: oidcTestAudience, RoleClaim: "groups",
				RoleMapJSON: oidcTestRoleMap(), HTTPClient: server.Client(),
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("newDashboardOIDCAuthenticator error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestDashboardOIDCAuthenticatorRejectsBadConfiguration(t *testing.T) {
	tests := []struct {
		name string
		opts dashboardOIDCOptions
	}{
		{"insecure issuer", dashboardOIDCOptions{Issuer: "http://issuer.example", Audience: oidcTestAudience, RoleClaim: "groups", RoleMapJSON: oidcTestRoleMap()}},
		{"missing audience", dashboardOIDCOptions{Issuer: "https://issuer.example", RoleClaim: "groups", RoleMapJSON: oidcTestRoleMap()}},
		{"missing role claim", dashboardOIDCOptions{Issuer: "https://issuer.example", Audience: oidcTestAudience, RoleMapJSON: oidcTestRoleMap()}},
		{"bad role map", dashboardOIDCOptions{Issuer: "https://issuer.example", Audience: oidcTestAudience, RoleClaim: "groups", RoleMapJSON: "{}"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if auth, err := newDashboardOIDCAuthenticator(context.Background(), tc.opts); err == nil || auth != nil {
				t.Fatalf("newDashboardOIDCAuthenticator = (%v, %v), want error", auth, err)
			}
		})
	}
}

func TestDashboardOIDCAuthenticator_DefaultHTTPClient(t *testing.T) {
	p := newOIDCTestProvider(t)
	if _, err := newDashboardOIDCAuthenticator(context.Background(), dashboardOIDCOptions{
		Issuer: p.server.URL, Audience: oidcTestAudience, RoleClaim: "groups",
		RoleMapJSON: oidcTestRoleMap(),
	}); err != nil {
		t.Fatalf("newDashboardOIDCAuthenticator with default client: %v", err)
	}
}

func TestDashboardOIDCAuthenticator_RejectsRedirects(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	n := base64.RawURLEncoding.EncodeToString(private.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(private.PublicKey.E)).Bytes())

	for _, endpoint := range []string{"discovery", "JWKS"} {
		t.Run(endpoint, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					if endpoint == "discovery" {
						http.Redirect(w, r, "/redirected-discovery", http.StatusFound)
						return
					}
					_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, server.URL, server.URL+"/jwks")
				case "/redirected-discovery":
					_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, server.URL, server.URL+"/jwks")
				case "/jwks":
					if endpoint == "JWKS" {
						http.Redirect(w, r, "/redirected-jwks", http.StatusFound)
						return
					}
					_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`,
						oidcTestKeyID, n, e)
				case "/redirected-jwks":
					_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`,
						oidcTestKeyID, n, e)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			for _, clientMode := range []string{"default client", "injected client"} {
				t.Run(clientMode, func(t *testing.T) {
					var client *http.Client
					if clientMode == "injected client" {
						client = server.Client()
					}
					if auth, err := newDashboardOIDCAuthenticator(context.Background(), dashboardOIDCOptions{
						Issuer: server.URL, Audience: oidcTestAudience, RoleClaim: "groups",
						RoleMapJSON: oidcTestRoleMap(), HTTPClient: client,
					}); err == nil || auth != nil {
						t.Fatalf("redirecting %s endpoint accepted: auth=%v err=%v", endpoint, auth, err)
					}
				})
			}
		})
	}
}

func TestDashboardOIDCAuthenticatorValidatesDiscoveryMetadata(t *testing.T) {
	for _, mode := range []string{"issuer mismatch", "insecure JWKS", "cross scheme JWKS", "cross host JWKS", "cross port JWKS", "empty JWKS"} {
		t.Run(mode, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/jwks" {
					_, _ = w.Write([]byte(`{"keys":[]}`))
					return
				}
				issuer, jwksURI := server.URL, server.URL+"/jwks"
				if mode == "issuer mismatch" {
					issuer = "https://issuer.example"
				}
				if mode == "insecure JWKS" {
					jwksURI = "http://issuer.example/jwks"
				}
				if mode == "cross scheme JWKS" {
					u, err := url.Parse(server.URL)
					if err != nil {
						t.Fatalf("parse server URL: %v", err)
					}
					jwksURI = "https://" + u.Host + "/jwks"
				}
				if mode == "cross host JWKS" {
					jwksURI = "https://issuer.example/jwks"
				}
				if mode == "cross port JWKS" {
					u, err := url.Parse(server.URL)
					if err != nil {
						t.Fatalf("parse server URL: %v", err)
					}
					jwksURI = u.Scheme + "://" + u.Hostname() + ":1/jwks"
				}
				_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, jwksURI)
			}))
			defer server.Close()
			if auth, err := newDashboardOIDCAuthenticator(context.Background(), dashboardOIDCOptions{
				Issuer: server.URL, Audience: oidcTestAudience, RoleClaim: "groups",
				RoleMapJSON: oidcTestRoleMap(), HTTPClient: server.Client(),
			}); err == nil || auth != nil {
				t.Fatalf("newDashboardOIDCAuthenticator = (%v, %v), want error", auth, err)
			}
		})
	}
}

func TestDashboardOIDCAudienceAlias(t *testing.T) {
	if got := dashboardOIDCAudience(dashboardServeOptions{oidcAudience: " audience ", oidcClientID: "client"}); got != "audience" {
		t.Fatalf("audience precedence = %q", got)
	}
	if got := dashboardOIDCAudience(dashboardServeOptions{oidcClientID: " client "}); got != "client" {
		t.Fatalf("client-id alias = %q", got)
	}
}

// TestDashboardOIDC_RunServeCompositionUsesMappedRoutePermissions guards the
// serve-path composition: an OIDC principal must receive exactly the permissions
// its mapped role grants. Deriving the permission authorizer from the
// metadata/raw booleans alone granted every metadata-tier permission to any
// authenticated principal, ignoring the role map entirely.
func TestDashboardOIDC_RunServeCompositionUsesMappedRoutePermissions(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	p := newOIDCTestProvider(t)
	auth := newOIDCTestAuthenticator(t, p, now)
	authorization := newDashboardRequestAuthorization("", "", auth)
	// Drive the same helper the serve path installs, so a regression in WHICH
	// authorization callbacks reach the composer fails here instead of passing
	// because the test rebuilt the wiring itself.
	metaAuthorized, authorizePermission, rawAuthorized := dashboardServeAuthorizers(nil, authorization)
	var audit strings.Builder
	inner := dashboard.New(dashboard.Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          func(string) bool { return true },
		Authorize:           dashboardAuthorizeFunc(metaAuthorized),
		AuthorizePermission: authorizePermission,
		AuthorizeRaw:        dashboardAuthorizeFunc(rawAuthorized),
		AuditWriter:         &audit,
	})
	handler := auth.middleware(dashboardAuthHandler(metaAuthorized, authorization.authAuditInfo, &audit, inner))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestWithBearer(t, p.token(t, p.validClaims(now))))
	if rr.Code != http.StatusOK {
		t.Fatalf("mapped evidence status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if strings.Contains(audit.String(), "permission=\"dashboard:exemptions:read\"") {
		t.Fatalf("evidence route unexpectedly audited exemptions permission: %s", audit.String())
	}

	req := requestWithBearer(t, p.token(t, p.validClaims(now)))
	req.URL.Path = "/exemptions"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unmapped exemptions status = %d, want %d; body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	log := audit.String()
	for _, want := range []string{
		"pipelock-dashboard denied",
		"permission=\"dashboard:exemptions:read\"",
		"auth_method=oidc",
		// The subject is recorded hashed rather than in the clear. Derive the
		// expected digest from the subject so this still pins WHICH principal
		// was denied, not merely that some digest was written.
		fmt.Sprintf("auth_subject_sha256=%q", fmt.Sprintf("%x", sha256.Sum256([]byte("operator-a")))),
		"auth_roles=\"evidence-reader\"",
		"reason=permission_denied",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("permission-denied audit missing %q: %s", want, log)
		}
	}
	if rawAuthorized(req) {
		t.Fatal("mapped OIDC principal unexpectedly received raw permission")
	}
}
