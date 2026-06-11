//go:build enterprise

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

func TestEncodeQueryOmitsEmptyAndSorts(t *testing.T) {
	got := encodeQuery(map[string]string{"org_id": "org-main", "fleet_id": "", "instance_id": "i-1"})
	if got != "?instance_id=i-1&org_id=org-main" {
		t.Fatalf("encodeQuery() = %q", got)
	}
	if encodeQuery(map[string]string{"a": "", "b": " "}) != "" {
		t.Fatalf("encodeQuery(all empty) = %q, want empty", encodeQuery(map[string]string{"a": ""}))
	}
}
