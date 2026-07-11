//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

type dashboardMTLSTestPKI struct {
	caCert     *x509.Certificate
	caKey      ed25519.PrivateKey
	caFile     string
	serverCert tls.Certificate
	serverPool *x509.CertPool
}

func newDashboardMTLSTestPKI(t *testing.T) dashboardMTLSTestPKI {
	t.Helper()
	now := time.Now()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(CA): %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "dashboard test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(CA): %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile := filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(CA): %v", err)
	}

	serverCert, serverLeaf := issueDashboardMTLSTestCert(t, caCert, caKey, dashboardMTLSTestCertOptions{
		serial:     101,
		commonName: "dashboard server",
		server:     true,
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(time.Hour),
	})
	serverPool := x509.NewCertPool()
	serverPool.AddCert(serverLeaf)
	return dashboardMTLSTestPKI{
		caCert:     caCert,
		caKey:      caKey,
		caFile:     caFile,
		serverCert: serverCert,
		serverPool: serverPool,
	}
}

type dashboardMTLSTestCertOptions struct {
	serial     int64
	commonName string
	server     bool
	notBefore  time.Time
	notAfter   time.Time
}

func issueDashboardMTLSTestCert(
	t *testing.T,
	caCert *x509.Certificate,
	caKey ed25519.PrivateKey,
	opts dashboardMTLSTestCertOptions,
) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", opts.commonName, err)
	}
	extUsage := x509.ExtKeyUsageClientAuth
	if opts.server {
		extUsage = x509.ExtKeyUsageServerAuth
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(opts.serial),
		Subject:      pkix.Name{CommonName: opts.commonName},
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{extUsage},
	}
	if opts.server {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", opts.commonName, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", opts.commonName, err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

func writeDashboardMTLSRoleMap(t *testing.T, entries map[string]string, roles string) string {
	t.Helper()
	var body strings.Builder
	body.WriteString("version: 1\nroles:\n")
	body.WriteString(roles)
	body.WriteString("certificates:\n")
	for fingerprint, role := range entries {
		body.WriteString("  ")
		body.WriteString(fingerprint)
		body.WriteString(": ")
		body.WriteString(role)
		body.WriteByte('\n')
	}
	path := filepath.Join(t.TempDir(), "client-cert-roles.yaml")
	if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
		t.Fatalf("WriteFile(role map): %v", err)
	}
	return path
}

func dashboardMTLSTestRequest(t *testing.T, leaf *x509.Certificate, verified bool) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://dashboard.example/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if verified {
		req.TLS.VerifiedChains = [][]*x509.Certificate{{leaf}}
	}
	return req
}

func TestLoadDashboardClientCertRoleMap(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	_, leaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 102, commonName: "mapped operator", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour),
	})
	fingerprint := dashboardClientCertSPKIFingerprint(leaf)
	validRoles := "  metadata:\n    permissions:\n      - dashboard:evidence:read\n"

	t.Run("valid", func(t *testing.T) {
		path := writeDashboardMTLSRoleMap(t, map[string]string{fingerprint: "metadata"}, validRoles)
		authorizer, err := loadDashboardClientCertRoleMap(path)
		if err != nil {
			t.Fatalf("load role map: %v", err)
		}
		req := dashboardMTLSTestRequest(t, leaf, true)
		if !authorizer.authorized(req) {
			t.Fatal("mapped verified certificate was not authenticated")
		}
		if err := authorizer.authorizePermission(req, dashboard.PermissionEvidenceRead); err != nil {
			t.Fatalf("mapped permission denied: %v", err)
		}
		if err := authorizer.authorizePermission(req, dashboard.PermissionRawRead); err == nil {
			t.Fatal("permission absent from role was allowed")
		}
	})

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"empty file", "", "empty"},
		{"unknown field", "version: 1\nroles: {}\ncertificates: {}\nsurprise: true\n", "field surprise"},
		{"unknown role field", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\n    surprise: true\ncertificates:\n  " + fingerprint + ": metadata\n", "field surprise"},
		{"duplicate version key", "version: 1\nversion: 1\nroles: {}\ncertificates: {}\n", "already defined"},
		{"duplicate role key", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\n  metadata:\n    permissions:\n      - dashboard:raw:read\ncertificates:\n  " + fingerprint + ": metadata\n", "already defined"},
		{"duplicate permissions key", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\n    permissions:\n      - dashboard:raw:read\ncertificates:\n  " + fingerprint + ": metadata\n", "already defined"},
		{"duplicate certificate key", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\ncertificates:\n  " + fingerprint + ": metadata\n  " + fingerprint + ": metadata\n", "already defined"},
		{"wrong version", "version: 2\nroles: {}\ncertificates: {}\n", "version"},
		{"empty certificates", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\ncertificates: {}\n", "at least one certificate"},
		{"unknown permission", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:unknown\ncertificates:\n  " + fingerprint + ": metadata\n", "unknown permission"},
		{"duplicate permission", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\n      - dashboard:evidence:read\ncertificates:\n  " + fingerprint + ": metadata\n", "duplicate permission"},
		{"bad fingerprint", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\ncertificates:\n  not-a-fingerprint: metadata\n", "fingerprint"},
		{"duplicate normalized fingerprint", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\ncertificates:\n  " + fingerprint + ": metadata\n  sha256:" + fingerprint + ": metadata\n", "duplicate normalized fingerprint"},
		{"unknown role", "version: 1\nroles:\n  metadata:\n    permissions:\n      - dashboard:evidence:read\ncertificates:\n  " + fingerprint + ": missing\n", "unknown role"},
		{"whitespace role name", "version: 1\nroles:\n  ' metadata ':\n    permissions:\n      - dashboard:evidence:read\ncertificates:\n  " + fingerprint + ": ' metadata '\n", "invalid role name"},
		{"empty role permissions", "version: 1\nroles:\n  metadata:\n    permissions: []\ncertificates:\n  " + fingerprint + ": metadata\n", "at least one permission"},
		{"multiple documents", "version: 1\nroles: {}\ncertificates: {}\n---\nversion: 1\n", "one YAML document"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "roles.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := loadDashboardClientCertRoleMap(path); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestLoadDashboardClientCertRoleMap_RejectsOversizeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.yaml")
	data := strings.Repeat(" ", dashboardClientCertRoleMapMaxBytes+1)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadDashboardClientCertRoleMap(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize role map: want size error, got %v", err)
	}
}

func TestParseDashboardClientCertFingerprint(t *testing.T) {
	plain := strings.Repeat("a1", sha256.Size)
	colonSeparated := strings.TrimSuffix(strings.Repeat("A1:", sha256.Size), ":")
	want, err := parseDashboardClientCertFingerprint(plain)
	if err != nil {
		t.Fatalf("parse plain fingerprint: %v", err)
	}
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"plain hex", plain},
		{"sha256 prefix with colons and padding", "  SHA256:" + colonSeparated + "  "},
	} {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			got, err := parseDashboardClientCertFingerprint(tc.value)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.value, err)
			}
			if got != want {
				t.Fatalf("parse %q normalized to %x, want %x", tc.value, got, want)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"too short", strings.Repeat("a1", sha256.Size-1)},
		{"too long", strings.Repeat("a1", sha256.Size+1)},
		{"non-hex", strings.Repeat("zz", sha256.Size)},
		{"double prefix", "sha256:sha256:" + plain},
	} {
		t.Run("malformed/"+tc.name, func(t *testing.T) {
			if _, err := parseDashboardClientCertFingerprint(tc.value); err == nil {
				t.Fatalf("parse malformed fingerprint %q: want error", tc.value)
			}
		})
	}
}

func TestLoadDashboardClientCAs(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	validPEM, err := os.ReadFile(pki.caFile)
	if err != nil {
		t.Fatalf("read CA file: %v", err)
	}

	t.Run("valid bundle loads", func(t *testing.T) {
		if _, err := loadDashboardClientCAs(pki.caFile); err != nil {
			t.Fatalf("valid CA bundle rejected: %v", err)
		}
	})

	t.Run("mixed valid and malformed bundle is rejected", func(t *testing.T) {
		malformed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a DER certificate")})
		bundle := append(append([]byte{}, validPEM...), malformed...)
		path := filepath.Join(t.TempDir(), "mixed-ca.pem")
		if err := os.WriteFile(path, bundle, 0o600); err != nil {
			t.Fatalf("write mixed bundle: %v", err)
		}
		if _, err := loadDashboardClientCAs(path); err == nil {
			t.Fatal("mixed valid/malformed CA bundle accepted; a malformed certificate must fail loud")
		}
	})

	t.Run("empty path rejected", func(t *testing.T) {
		if _, err := loadDashboardClientCAs("  "); err == nil {
			t.Fatal("empty --client-ca-file path accepted")
		}
	})
}

func TestDashboardClientCertAuthAuditInfo(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	now := time.Now()
	_, mappedLeaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 103, commonName: "mapped operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	_, unmappedLeaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 104, commonName: "unmapped operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	roleMap := writeDashboardMTLSRoleMap(t, map[string]string{
		dashboardClientCertSPKIFingerprint(mappedLeaf): "metadata",
	}, "  metadata:\n    permissions:\n      - dashboard:evidence:read\n")
	authorizer, err := loadDashboardClientCertRoleMap(roleMap)
	if err != nil {
		t.Fatalf("load role map: %v", err)
	}

	tests := []struct {
		name        string
		req         *http.Request
		wantReason  string
		wantSubject string
		wantRoles   []string
	}{
		{
			name:       "missing certificate",
			req:        httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://dashboard.example/", nil),
			wantReason: "missing_client_certificate",
		},
		{
			name:        "unverified certificate",
			req:         dashboardMTLSTestRequest(t, mappedLeaf, false),
			wantReason:  "unverified_client_certificate",
			wantSubject: dashboardClientCertSPKIFingerprint(mappedLeaf),
		},
		{
			name:        "verified unmapped certificate",
			req:         dashboardMTLSTestRequest(t, unmappedLeaf, true),
			wantReason:  "unmapped_client_certificate",
			wantSubject: dashboardClientCertSPKIFingerprint(unmappedLeaf),
		},
		{
			name:        "verified mapped certificate",
			req:         dashboardMTLSTestRequest(t, mappedLeaf, true),
			wantSubject: dashboardClientCertSPKIFingerprint(mappedLeaf),
			wantRoles:   []string{"metadata"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dashboardClientCertAuthAuditInfo(authorizer, tc.req)
			if got.Method != "mtls" {
				t.Fatalf("Method = %q, want mtls", got.Method)
			}
			if got.FailureReason != tc.wantReason {
				t.Fatalf("FailureReason = %q, want %q", got.FailureReason, tc.wantReason)
			}
			if got.Subject != tc.wantSubject {
				t.Fatalf("Subject = %q, want %q", got.Subject, tc.wantSubject)
			}
			if strings.Join(got.Roles, ",") != strings.Join(tc.wantRoles, ",") {
				t.Fatalf("Roles = %v, want %v", got.Roles, tc.wantRoles)
			}
		})
	}
}

func TestDashboardClientCertRoleMap_DocumentedExampleParses(t *testing.T) {
	const docPath = "../../docs/cli/dashboard.md"
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", docPath, err)
	}
	const start = "<!-- dashboard-mtls-role-map-start -->\n```yaml\n"
	const end = "\n```\n<!-- dashboard-mtls-role-map-end -->"
	startIndex := strings.Index(string(doc), start)
	if startIndex < 0 {
		t.Fatalf("documented role map start marker %q not found", start)
	}
	after := string(doc[startIndex+len(start):])
	example, _, ok := strings.Cut(after, end)
	if !ok {
		t.Fatalf("documented role map end marker %q not found", end)
	}
	path := filepath.Join(t.TempDir(), "documented-role-map.yaml")
	if err := os.WriteFile(path, []byte(example), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadDashboardClientCertRoleMap(path); err != nil {
		t.Fatalf("documented role map does not parse: %v", err)
	}
}

func TestDashboardClientCertAuthorizer_FailsClosed(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	now := time.Now()
	_, mapped := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 103, commonName: "mapped operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	_, unmapped := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 104, commonName: "unmapped operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	path := writeDashboardMTLSRoleMap(t, map[string]string{
		dashboardClientCertSPKIFingerprint(mapped): "metadata",
	}, "  metadata:\n    permissions:\n      - dashboard:evidence:read\n")
	authorizer, err := loadDashboardClientCertRoleMap(path)
	if err != nil {
		t.Fatalf("load role map: %v", err)
	}

	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"verified mapped", dashboardMTLSTestRequest(t, mapped, true), true},
		{"unverified mapped", dashboardMTLSTestRequest(t, mapped, false), false},
		{"verified unmapped", dashboardMTLSTestRequest(t, unmapped, true), false},
		{"no TLS", httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://dashboard.example/", nil), false},
		{"TLS without client certificate", func() *http.Request {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://dashboard.example/", nil)
			r.TLS = &tls.ConnectionState{}
			return r
		}(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizer.authorized(tc.req); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDashboardClientCertAuthorizers_VerifiedChainCannotFallThroughToRawToken(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	_, leaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 110, commonName: "metadata operator", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour),
	})
	fingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	authorizer := &dashboardClientCertAuthorizer{principals: map[[sha256.Size]byte]dashboardClientCertPrincipal{
		fingerprint: {
			role: "metadata",
			permissions: map[dashboard.Permission]struct{}{
				dashboard.PermissionEvidenceRead: {},
			},
		},
	}}
	_, authorizePermission, rawAuthorized := dashboardClientCertAuthorizers(
		authorizer,
		func(*http.Request) bool { return true },
		func(*http.Request) bool { return true },
		func(*http.Request) bool { return false },
	)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://dashboard.example/", nil)
	// Construct the divergent state explicitly: the verified leaf is present,
	// but PeerCertificates is empty. The verified identity must remain
	// authoritative instead of falling through to the broader token tier.
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}

	if rawAuthorized(req) {
		t.Fatal("verified metadata certificate fell through to raw-token authorization")
	}
	if err := authorizePermission(req, dashboard.PermissionExemptionsRead); err == nil {
		t.Fatal("verified metadata certificate fell through to token route permissions")
	}
}

func TestDashboardClientCertAuthorizers_NoTokenFallbackWhenMTLSEnabled(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	_, leaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 111, commonName: "metadata operator", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour),
	})
	fingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	authorizer := &dashboardClientCertAuthorizer{principals: map[[sha256.Size]byte]dashboardClientCertPrincipal{
		fingerprint: {
			role:        "metadata",
			permissions: map[dashboard.Permission]struct{}{dashboard.PermissionEvidenceRead: {}},
		},
	}}
	// Token callbacks that would authorize everything. With mTLS enabled the
	// verified certificate is authoritative, so these must never be consulted.
	metaAuthorized, authorizePermission, rawAuthorized := dashboardClientCertAuthorizers(
		authorizer,
		func(*http.Request) bool { return true },
		func(*http.Request) bool { return true },
		func(*http.Request) bool { return false },
	)
	// A request carrying a matching operator token but NO client certificate:
	// the TLS layer would normally reject this, but the application layer must
	// also fail closed rather than fall back to the token.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://dashboard.example/", nil)
	req.Header.Set("Authorization", "Bearer "+dashTestToken)

	if metaAuthorized(req) {
		t.Fatal("mTLS mode authorized a certificate-less request via token fallback")
	}
	if rawAuthorized(req) {
		t.Fatal("mTLS mode granted raw access to a certificate-less request via token fallback")
	}
	if err := authorizePermission(req, dashboard.PermissionEvidenceRead); err == nil {
		t.Fatal("mTLS mode granted route permission to a certificate-less request via token fallback")
	}
}

func TestDashboardMTLS_RoutePermissionsAndRaw(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	now := time.Now()
	metadataCert, metadataLeaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 105, commonName: "metadata operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	rawCert, rawLeaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 106, commonName: "raw operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	unmappedCert, _ := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 107, commonName: "unmapped operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	roleMap := writeDashboardMTLSRoleMap(t, map[string]string{
		dashboardClientCertSPKIFingerprint(metadataLeaf): "metadata",
		dashboardClientCertSPKIFingerprint(rawLeaf):      "raw",
	}, "  metadata:\n    permissions:\n      - dashboard:evidence:read\n"+
		"  raw:\n    permissions:\n      - dashboard:evidence:read\n      - dashboard:exemptions:read\n      - dashboard:raw:read\n")
	authorizer, err := loadDashboardClientCertRoleMap(roleMap)
	if err != nil {
		t.Fatalf("load role map: %v", err)
	}

	tokenMetaAuthorized := func(r *http.Request) bool { return dashboardTokenMatches(r, dashTestToken) }
	tokenRawAuthorized := func(r *http.Request) bool { return dashboardTokenMatches(r, "raw-token") }
	metaAuthorized, authorizePermission, rawAuthorized := dashboardClientCertAuthorizers(
		authorizer, tokenMetaAuthorized, tokenRawAuthorized,
		func(*http.Request) bool { return false },
	)
	inner := dashboard.New(dashboard.Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          func(string) bool { return true },
		Authorize:           dashboardAuthorizeFunc(metaAuthorized),
		AuthorizePermission: authorizePermission,
		AuthorizeRaw:        dashboardAuthorizeFunc(rawAuthorized),
	})
	server := httptest.NewUnstartedServer(dashboardAuthHandler(metaAuthorized, nil, nil, inner))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
		MinVersion:   tls.VersionTLS12,
	}
	server.TLS.ClientCAs.AddCert(pki.caCert)
	server.StartTLS()
	defer server.Close()

	requestStatus := func(t *testing.T, certs []tls.Certificate, path, token string) (int, error) {
		t.Helper()
		transport := &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pki.serverPool,
			Certificates: certs,
			MinVersion:   tls.VersionTLS12,
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, nil
	}

	tests := []struct {
		name       string
		cert       tls.Certificate
		path       string
		token      string
		wantStatus int
	}{
		{"metadata evidence allowed", metadataCert, "/", "", http.StatusOK},
		{"metadata exemptions denied", metadataCert, "/exemptions", "", http.StatusForbidden},
		{"metadata raw token cannot elevate", metadataCert, "/exemptions", "raw-token", http.StatusForbidden},
		{"raw role reaches additional route", rawCert, "/exemptions", "", http.StatusOK},
		{"unmapped verified cert denied", unmappedCert, "/", dashTestToken, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, err := requestStatus(t, []tls.Certificate{tc.cert}, tc.path, tc.token)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", status, tc.wantStatus)
			}
		})
	}

	t.Run("raw role receives raw permission", func(t *testing.T) {
		req := dashboardMTLSTestRequest(t, rawLeaf, true)
		if !rawAuthorized(req) {
			t.Fatal("raw role was denied raw authorization")
		}
		if err := authorizePermission(req, dashboard.PermissionRawRead); err != nil {
			t.Fatalf("raw role was denied raw permission: %v", err)
		}
	})

	t.Run("no client certificate rejected by handshake", func(t *testing.T) {
		if _, err := requestStatus(t, nil, "/", dashTestToken); err == nil {
			t.Fatal("request without client certificate unexpectedly completed")
		}
	})
}

func TestDashboardMTLS_ExpiredAndWrongCARejected(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	otherPKI := newDashboardMTLSTestPKI(t)
	now := time.Now()
	expiredCert, expiredLeaf := issueDashboardMTLSTestCert(t, pki.caCert, pki.caKey, dashboardMTLSTestCertOptions{
		serial: 108, commonName: "expired operator", notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour),
	})
	wrongCert, wrongLeaf := issueDashboardMTLSTestCert(t, otherPKI.caCert, otherPKI.caKey, dashboardMTLSTestCertOptions{
		serial: 109, commonName: "wrong CA operator", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
	roleMap := writeDashboardMTLSRoleMap(t, map[string]string{
		dashboardClientCertSPKIFingerprint(expiredLeaf): "metadata",
		dashboardClientCertSPKIFingerprint(wrongLeaf):   "metadata",
	}, "  metadata:\n    permissions:\n      - dashboard:evidence:read\n")
	authorizer, err := loadDashboardClientCertRoleMap(roleMap)
	if err != nil {
		t.Fatalf("load role map: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorizer.authorized(r) {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
		MinVersion:   tls.VersionTLS12,
	}
	server.TLS.ClientCAs.AddCert(pki.caCert)
	server.StartTLS()
	defer server.Close()

	for _, tc := range []struct {
		name string
		cert tls.Certificate
	}{
		{"expired", expiredCert},
		{"wrong CA", wrongCert},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := tc.cert
			var presented bool
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{TLSClientConfig: &tls.Config{
					RootCAs: pki.serverPool,
					// GetClientCertificate forces the test certificate to be
					// presented even when its issuer is absent from the server's
					// AcceptableCAs. Default selection would silently drop the
					// wrong-CA certificate, collapsing this case into the
					// no-client-certificate path instead of exercising the
					// certificate-verification rejection under test.
					GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
						presented = true
						return &cert, nil
					},
					MinVersion: tls.VersionTLS12,
				}},
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("%s certificate unexpectedly completed TLS with status %d", tc.name, resp.StatusCode)
			}
			if !presented {
				t.Fatalf("%s certificate was never presented; test did not exercise certificate verification", tc.name)
			}
		})
	}
}

func TestDashboardTLSConfig_ClientCertificates(t *testing.T) {
	pki := newDashboardMTLSTestPKI(t)
	certFile, keyFile, _ := writeDashTLSCert(t)
	opts := dashboardServeOptions{
		tlsCert:           certFile,
		tlsKey:            keyFile,
		requireClientCert: true,
		clientCAFile:      pki.caFile,
		clientCertRoleMap: "roles.yaml",
	}
	config, err := dashboardTLSConfig(opts)
	if err != nil {
		t.Fatalf("dashboardTLSConfig: %v", err)
	}
	if config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", config.ClientAuth)
	}
	if config.ClientCAs == nil {
		t.Fatal("ClientCAs is empty")
	}
}

func TestValidateDashboardListen_ClientCertificateFlags(t *testing.T) {
	tests := []struct {
		name    string
		opts    dashboardServeOptions
		wantErr string
	}{
		{"complete", dashboardServeOptions{listen: "127.0.0.1:8896", tlsCert: "server.pem", tlsKey: "server.key", requireClientCert: true, clientCAFile: "ca.pem", clientCertRoleMap: "roles.yaml"}, ""},
		{"requires server TLS", dashboardServeOptions{listen: "127.0.0.1:8896", requireClientCert: true, clientCAFile: "ca.pem", clientCertRoleMap: "roles.yaml"}, "--tls-cert"},
		{"requires CA", dashboardServeOptions{listen: "127.0.0.1:8896", tlsCert: "server.pem", tlsKey: "server.key", requireClientCert: true, clientCertRoleMap: "roles.yaml"}, "--client-ca-file"},
		{"requires role map", dashboardServeOptions{listen: "127.0.0.1:8896", tlsCert: "server.pem", tlsKey: "server.key", requireClientCert: true, clientCAFile: "ca.pem"}, "--client-cert-role-map"},
		{"CA without enable refused", dashboardServeOptions{listen: "127.0.0.1:8896", tlsCert: "server.pem", tlsKey: "server.key", clientCAFile: "ca.pem"}, "--require-client-cert"},
		{"role map without enable refused", dashboardServeOptions{listen: "127.0.0.1:8896", tlsCert: "server.pem", tlsKey: "server.key", clientCertRoleMap: "roles.yaml"}, "--require-client-cert"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDashboardListen(tc.opts)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDashboardMTLSAuthorizer_AllPermissionValuesAreRecognized(t *testing.T) {
	known := dashboardPermissionSet()
	for _, permission := range dashboard.AllPermissions() {
		if _, ok := known[permission]; !ok {
			t.Errorf("permission %q missing from mTLS role-map validator", permission)
		}
	}
	if _, ok := known[dashboard.Permission("dashboard:unknown")]; ok {
		t.Fatal("unknown permission unexpectedly recognized")
	}
}

func TestDashboardMTLS_DoesNotChangeLicenseEntitlement(t *testing.T) {
	inner := dashboard.New(dashboard.Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          func(string) bool { return false },
		Authorize:           func(*http.Request) error { return nil },
		AuthorizePermission: func(*http.Request, dashboard.Permission) error { return nil },
		AuthorizeRaw:        func(*http.Request) error { return nil },
	})
	recorder := httptest.NewRecorder()
	inner.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://dashboard.example/", nil))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), license.FeatureAgents) {
		t.Fatalf("status/body = %d %q, want entitlement denial", recorder.Code, recorder.Body.String())
	}
}
