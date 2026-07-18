//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
)

// selfSignedTLS produces a self-signed leaf certificate for 127.0.0.1 plus its
// PEM-encoded cert and key. Because it is self-signed, the cert PEM doubles as
// the CA bundle the client trusts.
func selfSignedTLS(t *testing.T) (tls.Certificate, []byte, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"127.0.0.1"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert, certPEM, keyPEM
}

// newTestClientServer starts an httptest TLS server running handler and returns
// a clientOptions wired to trust it with a generated operator client cert. The
// server is closed via t.Cleanup, so callers receive only the wired options.
func newTestClientServer(t *testing.T, token string, handler http.Handler) clientOptions {
	t.Helper()
	serverCert, caPEM, _ := selfSignedTLS(t)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	_, clientCertPEM, clientKeyPEM := selfSignedTLS(t)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	tokenPath := filepath.Join(dir, "token")
	writeClientFile(t, caPath, caPEM)
	writeClientFile(t, certPath, clientCertPEM)
	writeClientFile(t, keyPath, clientKeyPEM)
	writeClientFile(t, tokenPath, []byte(token+"\n"))

	return clientOptions{
		server:         srv.URL,
		caFile:         caPath,
		clientCertFile: certPath,
		clientKeyFile:  keyPath,
		tokenFile:      tokenPath,
		serverName:     "127.0.0.1",
	}
}

func writeClientFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func TestNewConductorClientValidatesFlags(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "f")
	writeClientFile(t, good, []byte("x"))
	base := clientOptions{
		server:         "https://127.0.0.1:8895",
		caFile:         good,
		clientCertFile: good,
		clientKeyFile:  good,
		tokenFile:      good,
	}
	cases := []struct {
		name string
		mut  func(*clientOptions)
		want string
	}{
		{"empty server", func(o *clientOptions) { o.server = "" }, "--server is required"},
		{"non-https", func(o *clientOptions) { o.server = "http://x" }, "scheme must be https"},
		{"missing host", func(o *clientOptions) { o.server = "https://" }, "missing host"},
		{"server userinfo", func(o *clientOptions) { o.server = "https://operator:token@127.0.0.1:8895" }, "must not include userinfo"},
		{"server path", func(o *clientOptions) { o.server = "https://127.0.0.1:8895/conductor" }, "must not include userinfo"},
		{"server query", func(o *clientOptions) { o.server = "https://127.0.0.1:8895?path=/other" }, "must not include userinfo"},
		{"server fragment", func(o *clientOptions) { o.server = "https://127.0.0.1:8895#followers" }, "must not include userinfo"},
		{"missing ca", func(o *clientOptions) { o.caFile = "" }, "--ca-file is required"},
		{"missing cert", func(o *clientOptions) { o.clientCertFile = "" }, "--client-cert is required"},
		{"missing key", func(o *clientOptions) { o.clientKeyFile = "" }, "--client-key is required"},
		{"missing token", func(o *clientOptions) { o.tokenFile = "" }, "--token-file is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.mut(&opts)
			_, err := newConductorClient(opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("newConductorClient() error = %v, want contains %q", err, tc.want)
			}
		})
	}
}

func TestNewConductorClientRejectsEmptyTokenFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "f")
	emptyToken := filepath.Join(dir, "empty-token")
	writeClientFile(t, good, []byte("x"))
	writeClientFile(t, emptyToken, []byte(" \n"))
	_, err := newConductorClient(clientOptions{
		server:         "https://127.0.0.1:8895",
		caFile:         good,
		clientCertFile: good,
		clientKeyFile:  good,
		tokenFile:      emptyToken,
	})
	if err == nil || !strings.Contains(err.Error(), "--token-file is empty") {
		t.Fatalf("newConductorClient() error = %v, want empty token error", err)
	}
}

func TestNewConductorClientTLSConfigRequiresTLS13AndVerification(t *testing.T) {
	opts := newTestClientServer(t, "operator-token", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	client, err := newConductorClient(opts)
	if err != nil {
		t.Fatalf("newConductorClient() error = %v", err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatalf("transport TLS config missing: %#v", client.httpClient.Transport)
	}
	tlsConfig := transport.TLSClientConfig
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", tlsConfig.MinVersion)
	}
	if tlsConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify enabled")
	}
	if tlsConfig.RootCAs == nil {
		t.Fatal("RootCAs not configured")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("client certificates = %d, want 1", len(tlsConfig.Certificates))
	}
}

func TestConductorClientGetJSONSendsBearerAndReturnsBody(t *testing.T) {
	var gotAuth, gotPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	opts := newTestClientServer(t, "operator-token", handler)
	client, err := newConductorClient(opts)
	if err != nil {
		t.Fatalf("newConductorClient() error = %v", err)
	}
	body, err := client.getJSON(context.Background(), "/api/v1/conductor/followers?org_id=org-main")
	if err != nil {
		t.Fatalf("getJSON() error = %v", err)
	}
	if string(bytes.TrimSpace(body)) != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
	if gotAuth != "Bearer operator-token" {
		t.Fatalf("Authorization = %q, want Bearer operator-token", gotAuth)
	}
	if gotPath != "/api/v1/conductor/followers?org_id=org-main" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestConductorClientGetJSONPropagatesStatusErrors(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("{\"error\":\"conductor follower list authorization failed\"}\nAuthorization: Bearer operator-token\r\n"))
	})
	opts := newTestClientServer(t, "operator-token", handler)
	client, err := newConductorClient(opts)
	if err != nil {
		t.Fatalf("newConductorClient() error = %v", err)
	}
	_, err = client.getJSON(context.Background(), "/api/v1/conductor/followers?org_id=org-main")
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("getJSON() error = %v, want status 403", err)
	}
	if strings.Contains(err.Error(), "\n") || strings.Contains(err.Error(), "\r") {
		t.Fatalf("getJSON() error kept response control bytes: %q", err.Error())
	}
	if strings.Contains(err.Error(), "operator-token") {
		t.Fatalf("getJSON() error leaked bearer token: %q", err.Error())
	}
}

func TestConductorReadClientListFollowersUsesGETAndBoundsBody(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var client *ReadClient
		_, err := client.ListFollowers(context.Background(), "org-main", "prod", 1)
		if err == nil || !strings.Contains(err.Error(), "nil") {
			t.Fatalf("ListFollowers() error = %v, want nil receiver error", err)
		}
	})

	var gotMethod, gotPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"followers":[],"count":0}`))
	})
	opts := newTestClientServer(t, "operator-token", handler)
	client, err := NewReadClient(ReadClientOptions{
		Server:         opts.server,
		CAFile:         opts.caFile,
		ClientCertFile: opts.clientCertFile,
		ClientKeyFile:  opts.clientKeyFile,
		TokenFile:      opts.tokenFile,
		ServerName:     opts.serverName,
	})
	if err != nil {
		t.Fatalf("NewReadClient() error = %v", err)
	}
	body, err := client.ListFollowers(context.Background(), "org-main", "prod", 25)
	if err != nil {
		t.Fatalf("ListFollowers() error = %v", err)
	}
	if !bytes.Contains(body, []byte(`"followers"`)) {
		t.Fatalf("ListFollowers() body = %q", body)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/api/v1/conductor/followers?fleet_id=prod&limit=25&org_id=org-main" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestConductorReadClientListFollowersRejectsUnboundedLimits(t *testing.T) {
	client := &ReadClient{client: &conductorClient{}}
	tests := []struct {
		name    string
		limit   int
		wantErr string
	}{
		{name: "zero", limit: 0, wantErr: "positive"},
		{name: "negative", limit: -1, wantErr: "positive"},
		{name: "too high", limit: ReadClientFollowerLimitMax + 1, wantErr: "exceeds maximum"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.ListFollowers(context.Background(), "org-main", "prod", tc.limit)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ListFollowers() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestConductorReadClientListFollowersRejectsInvalidScope(t *testing.T) {
	client := &ReadClient{client: &conductorClient{}}
	tests := []struct {
		name    string
		orgID   string
		fleetID string
		wantErr string
	}{
		{name: "empty org", fleetID: "prod", wantErr: "required"},
		{name: "empty fleet", orgID: "org-main", wantErr: "required"},
		{name: "blank org", orgID: " \t", fleetID: "prod", wantErr: "required"},
		{name: "org control", orgID: "org\nmain", fleetID: "prod", wantErr: "control characters"},
		{name: "fleet control", orgID: "org-main", fleetID: "prod\rwest", wantErr: "control characters"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.ListFollowers(context.Background(), tc.orgID, tc.fleetID, 1)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ListFollowers() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestConductorClientGetJSONRefusesRedirects(t *testing.T) {
	redirectTargetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectTargetHit = true
	}))
	t.Cleanup(target.Close)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", r.Method)
		}
		http.Redirect(w, r, target.URL+"/internal-metadata", http.StatusTemporaryRedirect)
	})
	opts := newTestClientServer(t, "operator-token", handler)
	client, err := newConductorClient(opts)
	if err != nil {
		t.Fatalf("newConductorClient() error = %v", err)
	}
	_, err = client.getJSON(context.Background(), "/api/v1/conductor/followers?org_id=org-main")
	if err == nil || !strings.Contains(err.Error(), "redirects are not allowed") {
		t.Fatalf("getJSON() error = %v, want redirect refusal", err)
	}
	if redirectTargetHit {
		t.Fatal("redirect target was reached")
	}
}

func TestConductorClientGetJSONRejectsOversizedBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("x"), clientMaxBodyBytes+1))
	})
	opts := newTestClientServer(t, "operator-token", handler)
	client, err := newConductorClient(opts)
	if err != nil {
		t.Fatalf("newConductorClient() error = %v", err)
	}
	_, err = client.getJSON(context.Background(), "/api/v1/conductor/followers?org_id=org-main")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("getJSON() error = %v, want response limit", err)
	}
}

func TestEncodeQueryOmitsEmptyAndSorts(t *testing.T) {
	got := encodeQuery(map[string]string{"org_id": "org-main", "fleet_id": "", "instance_id": "i-1"})
	if got != "?instance_id=i-1&org_id=org-main" {
		t.Fatalf("encodeQuery() = %q", got)
	}
	if encodeQuery(map[string]string{"a": "", "b": " "}) != "" {
		t.Fatalf("encodeQuery(all empty) = %q, want empty", encodeQuery(map[string]string{"a": ""}))
	}
}
