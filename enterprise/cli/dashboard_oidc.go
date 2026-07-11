//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

const (
	dashboardOIDCAlgorithm       = "RS256"
	dashboardOIDCClockLeeway     = 30 * time.Second
	dashboardOIDCDefaultCacheTTL = 5 * time.Minute
	dashboardOIDCHTTPTimeout     = 5 * time.Second
	dashboardOIDCMaxDocumentSize = 1 << 20
	dashboardOIDCMaxTokenSize    = 16 << 10
	dashboardOIDCMaxRoleValues   = 64
	dashboardOIDCMaxRoleLength   = 256
	dashboardOIDCMinKeyRefresh   = 30 * time.Second
)

type dashboardOIDCOptions struct {
	Issuer       string
	Audience     string
	RoleClaim    string
	RoleMapJSON  string
	HTTPClient   *http.Client
	Now          func() time.Time
	JWKSCacheTTL time.Duration
}

func validateDashboardAuthenticatorConfig(opts dashboardServeOptions) error {
	issuerConfigured := strings.TrimSpace(opts.oidcIssuer) != ""
	anyOIDCOption := issuerConfigured || strings.TrimSpace(opts.oidcAudience) != "" ||
		strings.TrimSpace(opts.oidcClientID) != "" || strings.TrimSpace(opts.oidcRoleClaim) != "" ||
		strings.TrimSpace(opts.oidcRoleMap) != ""
	if anyOIDCOption && !issuerConfigured {
		return errors.New("--oidc-issuer is required when any OIDC option is set")
	}
	if strings.TrimSpace(opts.authTokenFile) == "" && !issuerConfigured {
		return errors.New("one authenticator is required: set --auth-token-file or --oidc-issuer")
	}
	if strings.TrimSpace(opts.rawTokenFile) != "" && strings.TrimSpace(opts.authTokenFile) == "" {
		return errors.New("--raw-token-file requires --auth-token-file")
	}
	if !issuerConfigured {
		return nil
	}
	if strings.TrimSpace(opts.oidcAudience) == "" && strings.TrimSpace(opts.oidcClientID) == "" {
		return errors.New("--oidc-audience or --oidc-client-id is required with --oidc-issuer")
	}
	if strings.TrimSpace(opts.oidcAudience) != "" && strings.TrimSpace(opts.oidcClientID) != "" &&
		strings.TrimSpace(opts.oidcAudience) != strings.TrimSpace(opts.oidcClientID) {
		return errors.New("--oidc-audience and --oidc-client-id must match when both are set")
	}
	if strings.TrimSpace(opts.oidcRoleClaim) == "" {
		return errors.New("--oidc-role-claim is required with --oidc-issuer")
	}
	if strings.TrimSpace(opts.oidcRoleMap) == "" {
		return errors.New("--oidc-role-map must not be empty when OIDC is enabled")
	}
	return nil
}

func dashboardOIDCAudience(opts dashboardServeOptions) string {
	if strings.TrimSpace(opts.oidcAudience) != "" {
		return strings.TrimSpace(opts.oidcAudience)
	}
	return strings.TrimSpace(opts.oidcClientID)
}

type dashboardOIDCAuthenticator struct {
	issuer    string
	audience  string
	roleClaim string
	roleMap   dashboardOIDCRoleMap
	keys      *dashboardJWKSCache
	now       func() time.Time
}

type dashboardOIDCPrincipal struct {
	Subject     string
	Roles       []string
	permissions map[dashboard.Permission]struct{}
}

func (p *dashboardOIDCPrincipal) hasPermission(permission dashboard.Permission) bool {
	if p == nil {
		return false
	}
	_, ok := p.permissions[permission]
	return ok
}

type dashboardOIDCRoleMap struct {
	claimValues map[string]string
	roles       map[string]map[dashboard.Permission]struct{}
}

type dashboardOIDCRoleMapDocument struct {
	ClaimValues map[string]string   `json:"claim_values"`
	Roles       map[string][]string `json:"roles"`
}

func parseDashboardOIDCRoleMap(value string) (dashboardOIDCRoleMap, error) {
	if strings.TrimSpace(value) == "" {
		return dashboardOIDCRoleMap{}, errors.New("--oidc-role-map must contain a JSON role map")
	}
	if len(value) > dashboardOIDCMaxDocumentSize {
		return dashboardOIDCRoleMap{}, errors.New("--oidc-role-map exceeds the 1 MiB limit")
	}
	var document dashboardOIDCRoleMapDocument
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return dashboardOIDCRoleMap{}, fmt.Errorf("parse --oidc-role-map: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return dashboardOIDCRoleMap{}, fmt.Errorf("parse --oidc-role-map: %w", err)
	}
	if len(document.ClaimValues) == 0 {
		return dashboardOIDCRoleMap{}, errors.New("--oidc-role-map claim_values must not be empty")
	}
	if len(document.Roles) == 0 {
		return dashboardOIDCRoleMap{}, errors.New("--oidc-role-map roles must not be empty")
	}

	knownPermissions := make(map[dashboard.Permission]struct{})
	for _, permission := range dashboard.AllPermissions() {
		knownPermissions[permission] = struct{}{}
	}
	roles := make(map[string]map[dashboard.Permission]struct{}, len(document.Roles))
	for role, configuredPermissions := range document.Roles {
		if strings.TrimSpace(role) == "" || len(role) > dashboardOIDCMaxRoleLength {
			return dashboardOIDCRoleMap{}, errors.New("--oidc-role-map contains an empty or overlong role name")
		}
		if len(configuredPermissions) == 0 {
			return dashboardOIDCRoleMap{}, fmt.Errorf("--oidc-role-map role %q must grant at least one permission", role)
		}
		permissions := make(map[dashboard.Permission]struct{}, len(configuredPermissions))
		for _, configured := range configuredPermissions {
			permission := dashboard.Permission(configured)
			if _, ok := knownPermissions[permission]; !ok {
				return dashboardOIDCRoleMap{}, fmt.Errorf("--oidc-role-map role %q has unknown permission %q", role, configured)
			}
			permissions[permission] = struct{}{}
		}
		roles[role] = permissions
	}
	for claimValue, role := range document.ClaimValues {
		if strings.TrimSpace(claimValue) == "" || len(claimValue) > dashboardOIDCMaxRoleLength {
			return dashboardOIDCRoleMap{}, errors.New("--oidc-role-map contains an empty or overlong claim value")
		}
		if _, ok := roles[role]; !ok {
			return dashboardOIDCRoleMap{}, fmt.Errorf("--oidc-role-map claim value %q references unknown role %q", claimValue, role)
		}
	}
	return dashboardOIDCRoleMap{claimValues: document.ClaimValues, roles: roles}, nil
}

type dashboardOIDCDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func newDashboardOIDCAuthenticator(ctx context.Context, opts dashboardOIDCOptions) (*dashboardOIDCAuthenticator, error) {
	issuer := strings.TrimSpace(opts.Issuer)
	if err := validateDashboardOIDCURL("--oidc-issuer", issuer); err != nil {
		return nil, err
	}
	audience := strings.TrimSpace(opts.Audience)
	if audience == "" {
		return nil, errors.New("--oidc-audience or --oidc-client-id is required with --oidc-issuer")
	}
	roleClaim := strings.TrimSpace(opts.RoleClaim)
	if roleClaim == "" || len(roleClaim) > dashboardOIDCMaxRoleLength {
		return nil, errors.New("--oidc-role-claim must be non-empty and at most 256 bytes")
	}
	roleMap, err := parseDashboardOIDCRoleMap(opts.RoleMapJSON)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	cacheTTL := opts.JWKSCacheTTL
	if cacheTTL <= 0 {
		cacheTTL = dashboardOIDCDefaultCacheTTL
	}
	client := &http.Client{Timeout: dashboardOIDCHTTPTimeout}
	if opts.HTTPClient != nil {
		client = new(http.Client)
		*client = *opts.HTTPClient
	}
	// Discovery and JWKS endpoints are fixed trust anchors. Following even a
	// same-origin redirect makes their effective destination mutable and can
	// turn provider metadata into an SSRF or downgrade hop. Clone injected
	// clients above so this policy cannot be weakened by their redirect hook.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	var discovery dashboardOIDCDiscovery
	if err := fetchDashboardOIDCJSON(ctx, client, discoveryURL, &discovery); err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	if discovery.Issuer != issuer {
		return nil, fmt.Errorf("OIDC discovery issuer %q does not match configured issuer %q", discovery.Issuer, issuer)
	}
	if err := validateDashboardOIDCURL("OIDC jwks_uri", discovery.JWKSURI); err != nil {
		return nil, err
	}
	if err := validateDashboardOIDCJWKSOrigin(issuer, discovery.JWKSURI); err != nil {
		return nil, err
	}
	keys := &dashboardJWKSCache{
		uri:    discovery.JWKSURI,
		client: client,
		now:    now,
		ttl:    cacheTTL,
	}
	if err := keys.refresh(ctx); err != nil {
		return nil, fmt.Errorf("load OIDC JWKS: %w", err)
	}
	return &dashboardOIDCAuthenticator{
		issuer: issuer, audience: audience, roleClaim: roleClaim,
		roleMap: roleMap, keys: keys, now: now,
	}, nil
}

func validateDashboardOIDCURL(label, value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute URL without credentials, query, or fragment", label)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%s must use HTTPS (HTTP is allowed only for a loopback test issuer)", label)
}

func validateDashboardOIDCJWKSOrigin(issuer, jwksURI string) error {
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("--oidc-issuer: %w", err)
	}
	jwksURL, err := url.Parse(jwksURI)
	if err != nil {
		return fmt.Errorf("OIDC jwks_uri: %w", err)
	}
	if !sameDashboardOIDCOrigin(issuerURL, jwksURL) {
		return fmt.Errorf("OIDC jwks_uri origin %q does not match configured issuer origin %q", jwksURL.Scheme+"://"+jwksURL.Host, issuerURL.Scheme+"://"+issuerURL.Host)
	}
	return nil
}

func sameDashboardOIDCOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		dashboardOIDCPort(a) == dashboardOIDCPort(b)
}

func dashboardOIDCPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func fetchDashboardOIDCJSON(ctx context.Context, client *http.Client, endpoint string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, dashboardOIDCMaxDocumentSize+1))
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

type dashboardJWKSCache struct {
	mu         sync.Mutex
	uri        string
	client     *http.Client
	now        func() time.Time
	ttl        time.Duration
	keys       map[string]*rsa.PublicKey
	expiresAt  time.Time
	lastMiss   time.Time
	refreshCh  chan struct{}
	refreshErr error
}

type dashboardJWKS struct {
	Keys []dashboardJWK `json:"keys"`
}

type dashboardJWK struct {
	KeyType string   `json:"kty"`
	KeyID   string   `json:"kid"`
	Use     string   `json:"use"`
	Alg     string   `json:"alg"`
	KeyOps  []string `json:"key_ops"`
	N       string   `json:"n"`
	E       string   `json:"e"`
}

func (c *dashboardJWKSCache) key(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	if c.keys == nil || !c.now().Before(c.expiresAt) {
		c.mu.Unlock()
		if err := c.refresh(ctx); err != nil {
			return nil, err
		}
		c.mu.Lock()
	}
	if key := c.keys[keyID]; key != nil {
		c.mu.Unlock()
		return key, nil
	}
	// An unknown kid commonly means the provider rotated keys before this
	// cache entry expired. Refresh at a bounded rate; attacker-chosen kids must
	// not turn the dashboard into a JWKS request amplifier.
	if !c.lastMiss.IsZero() && c.now().Before(c.lastMiss.Add(dashboardOIDCMinKeyRefresh)) {
		c.mu.Unlock()
		return nil, fmt.Errorf("OIDC signing key %q not found", keyID)
	}
	c.lastMiss = c.now()
	c.mu.Unlock()
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	key := c.keys[keyID]
	c.mu.Unlock()
	if key == nil {
		return nil, fmt.Errorf("OIDC signing key %q not found", keyID)
	}
	return key, nil
}

func (c *dashboardJWKSCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	if c.refreshCh != nil {
		refreshCh := c.refreshCh
		c.mu.Unlock()
		select {
		case <-refreshCh:
			c.mu.Lock()
			err := c.refreshErr
			c.mu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	refreshCh := make(chan struct{})
	c.refreshCh = refreshCh
	c.mu.Unlock()

	err := c.fetchAndStore(ctx)

	c.mu.Lock()
	c.refreshErr = err
	close(refreshCh)
	c.refreshCh = nil
	c.mu.Unlock()
	return err
}

func (c *dashboardJWKSCache) fetchAndStore(ctx context.Context) error {
	var set dashboardJWKS
	if err := fetchDashboardOIDCJSON(ctx, c.client, c.uri, &set); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range set.Keys {
		key, include, err := parseDashboardRSAJWK(jwk)
		if err != nil {
			return err
		}
		if !include {
			continue
		}
		if _, duplicate := keys[jwk.KeyID]; duplicate {
			return fmt.Errorf("OIDC JWKS contains duplicate kid %q", jwk.KeyID)
		}
		keys[jwk.KeyID] = key
	}
	if len(keys) == 0 {
		return errors.New("OIDC JWKS contains no usable RS256 signing keys")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = keys
	c.expiresAt = c.now().Add(c.ttl)
	return nil
}

func parseDashboardRSAJWK(jwk dashboardJWK) (*rsa.PublicKey, bool, error) {
	if jwk.KeyType != "RSA" || (jwk.Use != "" && jwk.Use != "sig") || (jwk.Alg != "" && jwk.Alg != dashboardOIDCAlgorithm) {
		return nil, false, nil
	}
	if jwk.KeyID == "" || len(jwk.KeyID) > dashboardOIDCMaxRoleLength {
		return nil, false, errors.New("OIDC JWKS has a usable RSA key with an empty or overlong kid")
	}
	if len(jwk.KeyOps) > 0 && !containsString(jwk.KeyOps, "verify") {
		return nil, false, nil
	}
	nBytes, err := base64.RawURLEncoding.Strict().DecodeString(jwk.N)
	if err != nil {
		return nil, false, fmt.Errorf("decode OIDC JWK %q modulus: %w", jwk.KeyID, err)
	}
	eBytes, err := base64.RawURLEncoding.Strict().DecodeString(jwk.E)
	if err != nil {
		return nil, false, fmt.Errorf("decode OIDC JWK %q exponent: %w", jwk.KeyID, err)
	}
	n := new(big.Int).SetBytes(nBytes)
	eBig := new(big.Int).SetBytes(eBytes)
	if n.BitLen() < 2048 {
		return nil, false, fmt.Errorf("OIDC JWK %q RSA modulus is smaller than 2048 bits", jwk.KeyID)
	}
	if !eBig.IsInt64() {
		return nil, false, fmt.Errorf("OIDC JWK %q exponent is out of range", jwk.KeyID)
	}
	e := eBig.Int64()
	if e < 3 || e > int64(^uint(0)>>1) || e%2 == 0 {
		return nil, false, fmt.Errorf("OIDC JWK %q exponent is invalid", jwk.KeyID)
	}
	return &rsa.PublicKey{N: n, E: int(e)}, true, nil
}

type dashboardJWTHeader struct {
	Algorithm string   `json:"alg"`
	KeyID     string   `json:"kid"`
	Critical  []string `json:"crit"`
}

func (a *dashboardOIDCAuthenticator) authenticate(r *http.Request) (*dashboardOIDCPrincipal, error) {
	token, err := dashboardBearerToken(r)
	if err != nil {
		return nil, err
	}
	if len(token) > dashboardOIDCMaxTokenSize {
		return nil, errors.New("OIDC bearer token is too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errors.New("OIDC bearer token must be a signed compact JWT")
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode OIDC JWT header: %w", err)
	}
	var header dashboardJWTHeader
	if err := decodeDashboardJWTJSON(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("decode OIDC JWT header: %w", err)
	}
	if header.Algorithm != dashboardOIDCAlgorithm {
		return nil, fmt.Errorf("OIDC JWT algorithm %q is not allowed; expected RS256", header.Algorithm)
	}
	if header.KeyID == "" || len(header.KeyID) > dashboardOIDCMaxRoleLength {
		return nil, errors.New("OIDC JWT kid is empty or overlong")
	}
	if len(header.Critical) != 0 {
		return nil, errors.New("OIDC JWT uses unsupported critical headers")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode OIDC JWT signature: %w", err)
	}
	key, err := a.keys.key(r.Context(), header.KeyID)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("OIDC JWT signature verification failed")
	}

	// Claims are decoded only after the signature succeeds; no identity or
	// authorization decision is ever made from an unverified payload.
	claimsBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode verified OIDC claims: %w", err)
	}
	var claims map[string]json.RawMessage
	if err := decodeDashboardJWTJSON(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("decode verified OIDC claims: %w", err)
	}
	return a.principalFromClaims(claims)
}

func decodeDashboardJWTJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func dashboardBearerToken(r *http.Request) (string, error) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", errors.New("OIDC bearer token is missing")
	}
	return parts[1], nil
}

func (a *dashboardOIDCAuthenticator) principalFromClaims(claims map[string]json.RawMessage) (*dashboardOIDCPrincipal, error) {
	issuer, err := requiredStringClaim(claims, "iss")
	if err != nil || issuer != a.issuer {
		return nil, errors.New("OIDC issuer claim is missing or does not match")
	}
	subject, err := requiredStringClaim(claims, "sub")
	if err != nil {
		return nil, errors.New("OIDC subject claim is missing or invalid")
	}
	audiences, err := audienceClaim(claims["aud"])
	if err != nil || !containsString(audiences, a.audience) {
		return nil, errors.New("OIDC audience claim is missing or does not match")
	}
	if rawAZP, present := claims["azp"]; present {
		var azp string
		if err := json.Unmarshal(rawAZP, &azp); err != nil || azp != a.audience {
			return nil, errors.New("OIDC authorized-party claim does not match the expected audience")
		}
	} else if len(audiences) > 1 {
		return nil, errors.New("OIDC token with multiple audiences is missing azp")
	}

	now := a.now()
	expiresAt, err := numericDateClaim(claims, "exp", true)
	if err != nil || !now.Before(expiresAt.Add(dashboardOIDCClockLeeway)) {
		return nil, errors.New("OIDC token is expired or has an invalid exp claim")
	}
	if notBefore, err := numericDateClaim(claims, "nbf", false); err != nil {
		return nil, errors.New("OIDC token has an invalid nbf claim")
	} else if !notBefore.IsZero() && now.Add(dashboardOIDCClockLeeway).Before(notBefore) {
		return nil, errors.New("OIDC token is not yet valid")
	}

	claimValues, err := roleClaimValues(claims[a.roleClaim])
	if err != nil {
		return nil, err
	}
	principal := &dashboardOIDCPrincipal{
		Subject: subject, permissions: make(map[dashboard.Permission]struct{}),
	}
	seenRoles := make(map[string]struct{})
	for _, claimValue := range claimValues {
		role, mapped := a.roleMap.claimValues[claimValue]
		if !mapped {
			continue
		}
		if _, seen := seenRoles[role]; seen {
			continue
		}
		seenRoles[role] = struct{}{}
		principal.Roles = append(principal.Roles, role)
		for permission := range a.roleMap.roles[role] {
			principal.permissions[permission] = struct{}{}
		}
	}
	if len(principal.Roles) == 0 {
		return nil, errors.New("OIDC role claim has no mapped value")
	}
	return principal, nil
}

func requiredStringClaim(claims map[string]json.RawMessage, name string) (string, error) {
	raw, ok := claims[name]
	if !ok {
		return "", errors.New("claim missing")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" || len(value) > dashboardOIDCMaxTokenSize {
		return "", errors.New("claim invalid")
	}
	return value, nil
}

func audienceClaim(raw json.RawMessage) ([]string, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, errors.New("audience is empty")
		}
		return []string{single}, nil
	}
	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err != nil || len(multiple) == 0 || len(multiple) > dashboardOIDCMaxRoleValues {
		return nil, errors.New("audience is invalid")
	}
	for _, audience := range multiple {
		if audience == "" || len(audience) > dashboardOIDCMaxRoleLength {
			return nil, errors.New("audience is invalid")
		}
	}
	return multiple, nil
}

func numericDateClaim(claims map[string]json.RawMessage, name string, required bool) (time.Time, error) {
	raw, ok := claims[name]
	if !ok {
		if required {
			return time.Time{}, errors.New("claim missing")
		}
		return time.Time{}, nil
	}
	text := strings.TrimSpace(string(raw))
	if text == "" || text[0] == '"' {
		return time.Time{}, errors.New("numeric date must be a JSON number")
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return time.Time{}, err
	}
	seconds, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil || seconds < 0 {
		return time.Time{}, errors.New("numeric date is invalid")
	}
	return time.Unix(seconds, 0), nil
}

func roleClaimValues(raw json.RawMessage) ([]string, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" || len(single) > dashboardOIDCMaxRoleLength {
			return nil, errors.New("OIDC role claim is empty or overlong")
		}
		return []string{single}, nil
	}
	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err != nil || len(multiple) == 0 || len(multiple) > dashboardOIDCMaxRoleValues {
		return nil, errors.New("OIDC role claim must be a string or a bounded string array")
	}
	for _, value := range multiple {
		if value == "" || len(value) > dashboardOIDCMaxRoleLength {
			return nil, errors.New("OIDC role claim contains an empty or overlong value")
		}
	}
	return multiple, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type dashboardOIDCPrincipalContextKey struct{}

type dashboardOIDCFailureContextKey struct{}

func dashboardOIDCPrincipalFromRequest(r *http.Request) *dashboardOIDCPrincipal {
	principal, _ := r.Context().Value(dashboardOIDCPrincipalContextKey{}).(*dashboardOIDCPrincipal)
	return principal
}

func dashboardOIDCFailureReasonFromRequest(r *http.Request) string {
	reason, _ := r.Context().Value(dashboardOIDCFailureContextKey{}).(string)
	return reason
}

func (a *dashboardOIDCAuthenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.authenticate(r)
		if err == nil {
			ctx := context.WithValue(r.Context(), dashboardOIDCPrincipalContextKey{}, principal)
			r = r.WithContext(ctx)
		} else if dashboardBearerAttempted(r) {
			ctx := context.WithValue(r.Context(), dashboardOIDCFailureContextKey{}, dashboardOIDCFailureCategory(err))
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func dashboardBearerAttempted(r *http.Request) bool {
	parts := strings.Fields(r.Header.Get("Authorization"))
	return len(parts) > 0 && strings.EqualFold(parts[0], "Bearer")
}

func dashboardOIDCFailureCategory(err error) string {
	if err == nil {
		return "-"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "bearer token is missing"):
		return "missing_token"
	case strings.Contains(msg, "signature"):
		return "invalid_signature"
	case strings.Contains(msg, "expired"):
		return "expired"
	case strings.Contains(msg, "role claim has no mapped value"):
		return "permission_denied"
	default:
		return "invalid_token"
	}
}

type dashboardRequestAuthorization struct {
	metadataToken   string
	rawToken        string
	complianceToken string
	oidc            *dashboardOIDCAuthenticator
	legacy          func(*http.Request, dashboard.Permission) error
}

func newDashboardRequestAuthorization(metadataToken, rawToken, complianceToken string, oidc *dashboardOIDCAuthenticator) *dashboardRequestAuthorization {
	return &dashboardRequestAuthorization{
		metadataToken:   metadataToken,
		rawToken:        rawToken,
		complianceToken: complianceToken,
		oidc:            oidc,
		legacy: dashboardAuthorizePermissionFunc(
			func(req *http.Request) bool {
				return dashboardConfiguredTokenMatches(req, metadataToken) || dashboardConfiguredTokenMatches(req, rawToken)
			},
			func(req *http.Request) bool { return dashboardConfiguredTokenMatches(req, rawToken) },
			func(req *http.Request) bool {
				return dashboardConfiguredTokenMatches(req, complianceToken)
			},
		),
	}
}

func dashboardConfiguredTokenMatches(r *http.Request, token string) bool {
	return token != "" && dashboardTokenMatches(r, token)
}

func (a *dashboardRequestAuthorization) metaAuthorized(r *http.Request) bool {
	return dashboardConfiguredTokenMatches(r, a.metadataToken) ||
		dashboardConfiguredTokenMatches(r, a.rawToken) ||
		dashboardOIDCPrincipalFromRequest(r) != nil
}

// complianceAuthorized recognizes the optional auditor token, which is scoped to
// the compliance path by authenticated/dashboardGlobalAuthorized.
func (a *dashboardRequestAuthorization) complianceAuthorized(r *http.Request) bool {
	return dashboardConfiguredTokenMatches(r, a.complianceToken)
}

// authenticated is the global gate: any operator/OIDC identity, or the
// compliance token restricted to the compliance path.
func (a *dashboardRequestAuthorization) authenticated(r *http.Request) bool {
	if a.metaAuthorized(r) {
		return true
	}
	return r.URL.Path == dashboard.CompliancePath && a.complianceAuthorized(r)
}

func (a *dashboardRequestAuthorization) rawAuthorized(r *http.Request) bool {
	return dashboardConfiguredTokenMatches(r, a.rawToken) ||
		dashboardOIDCPrincipalFromRequest(r).hasPermission(dashboard.PermissionRawRead)
}

func (a *dashboardRequestAuthorization) authorizePermission(r *http.Request, permission dashboard.Permission) error {
	if dashboardOIDCPrincipalFromRequest(r).hasPermission(permission) {
		return nil
	}
	if err := a.legacy(r, permission); err == nil {
		return nil
	}
	return fmt.Errorf("dashboard permission %q denied", permission)
}

func (a *dashboardRequestAuthorization) authAuditInfo(r *http.Request) dashboard.AuthAuditInfo {
	if principal := dashboardOIDCPrincipalFromRequest(r); principal != nil {
		return dashboard.AuthAuditInfo{Method: "oidc", Subject: principal.Subject, Roles: principal.Roles}
	}
	switch {
	case dashboardConfiguredTokenMatches(r, a.rawToken):
		return dashboard.AuthAuditInfo{Method: "static-raw-token"}
	case dashboardConfiguredTokenMatches(r, a.metadataToken):
		return dashboard.AuthAuditInfo{Method: "static-metadata-token"}
	case dashboardConfiguredTokenMatches(r, a.complianceToken):
		return dashboard.AuthAuditInfo{Method: "static-compliance-token"}
	case dashboardOIDCFailureReasonFromRequest(r) != "":
		return dashboard.AuthAuditInfo{Method: "oidc", FailureReason: dashboardOIDCFailureReasonFromRequest(r)}
	default:
		return dashboard.AuthAuditInfo{Method: "none", FailureReason: "missing_token"}
	}
}

func (a *dashboardRequestAuthorization) wrap(next http.Handler, auditWriter io.Writer) http.Handler {
	handler := dashboardAuthHandler(a.authenticated, a.authAuditInfo, auditWriter, next)
	if a.oidc != nil {
		return a.oidc.middleware(handler)
	}
	return handler
}
