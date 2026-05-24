// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestNewConductorMTLSClientConfiguresClientCertificate(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	trustPath := filepath.Join(dir, "trust-roster.json")
	caPath := filepath.Join(dir, "boss-ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, trustPath, []byte(`{"keys":[]}`))
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	client, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    "https://conductor.example",
		TrustRosterPath: trustPath,
		ServerCAFile:    caPath,
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
	})
	if err != nil {
		t.Fatalf("newConductorMTLSClient() error = %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig = nil, want mTLS config")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %d, want TLS 1.3", transport.TLSClientConfig.MinVersion)
	}
	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(transport.TLSClientConfig.Certificates))
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("RootCAs = nil; mTLS client must pin Boss server cert against roster, not system trust")
	}
	if transport.TLSClientConfig.ServerName != "conductor.example" {
		t.Fatalf("ServerName = %q, want pinned host conductor.example", transport.TLSClientConfig.ServerName)
	}
	if transport.TLSHandshakeTimeout == 0 {
		t.Fatal("TLSHandshakeTimeout = 0, want bounded handshake timeout")
	}
	if transport.ResponseHeaderTimeout == 0 {
		t.Fatal("ResponseHeaderTimeout = 0, want bounded response header timeout")
	}
	if transport.MaxResponseHeaderBytes == 0 {
		t.Fatal("MaxResponseHeaderBytes = 0, want explicit cap")
	}
}

func TestNewConductorMTLSClientRejectsMissingClientCertificate(t *testing.T) {
	dir := t.TempDir()
	certPEM, _ := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	writePrivateTestFile(t, caPath, certPEM)

	_, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    "https://conductor.example",
		TrustRosterPath: filepath.Join(t.TempDir(), "trust.json"),
		ServerCAFile:    caPath,
		ClientCertPath:  filepath.Join(t.TempDir(), "missing.crt"),
		ClientKeyPath:   filepath.Join(t.TempDir(), "missing.key"),
	})
	if err == nil || !strings.Contains(err.Error(), "mTLS client certificate") {
		t.Fatalf("newConductorMTLSClient() = %v, want certificate load error", err)
	}
}

func TestNewConductorMTLSClientRejectsMissingServerCABundle(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	_, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    "https://conductor.example",
		TrustRosterPath: filepath.Join(t.TempDir(), "trust.json"),
		ServerCAFile:    filepath.Join(t.TempDir(), "missing.pem"),
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "server CA bundle") {
		t.Fatalf("newConductorMTLSClient() = %v, want server CA bundle load error", err)
	}
}

func TestNewConductorMTLSClientRejectsNonPEMServerCABundle(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	writePrivateTestFile(t, caPath, []byte("not a PEM bundle"))
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	_, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    "https://conductor.example",
		TrustRosterPath: filepath.Join(t.TempDir(), "trust.json"),
		ServerCAFile:    caPath,
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "PEM-encoded certificates") {
		t.Fatalf("newConductorMTLSClient() = %v, want PEM parse error", err)
	}
}

// TestNewConductorMTLSClient_VerifiesAgainstPinnedRosterOnly is the "proves
// the pin" test. Two test CAs sign two server certs. The follower's mTLS
// client gets only one CA in its roster. A request to the matching server
// succeeds; a request to the off-roster server is rejected at TLS verification
// even though both certs are valid X.509 leaves with healthy chains.
func TestNewConductorMTLSClient_VerifiesAgainstPinnedRosterOnly(t *testing.T) {
	dir := t.TempDir()
	pinnedCAPEM, pinnedServer := newTestTLSServer(t)
	_, offRosterServer := newTestTLSServer(t)
	defer pinnedServer.Close()
	defer offRosterServer.Close()

	caPath := filepath.Join(dir, "boss-ca.pem")
	writePrivateTestFile(t, caPath, pinnedCAPEM)
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	client, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    pinnedServer.URL,
		TrustRosterPath: filepath.Join(t.TempDir(), "trust.json"),
		ServerCAFile:    caPath,
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
	})
	if err != nil {
		t.Fatalf("newConductorMTLSClient() error = %v", err)
	}

	// Override ServerName because httptest servers bind 127.0.0.1 and the
	// pinned-cert SAN below is also 127.0.0.1. The production code derives
	// ServerName from the configured URL, so this test mirrors that path.
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.ServerName = mustHostname(t, pinnedServer.URL)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pinnedServer.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest(pinned) error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do(pinned) error = %v; pinned-CA chain must validate", err)
	}
	_ = resp.Body.Close()

	transport.TLSClientConfig.ServerName = mustHostname(t, offRosterServer.URL)
	transport.CloseIdleConnections()
	offReq, err := http.NewRequestWithContext(ctx, http.MethodGet, offRosterServer.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest(off-roster) error = %v", err)
	}
	offResp, err := client.Do(offReq)
	if err == nil {
		_ = offResp.Body.Close()
		t.Fatal("Do(off-roster) error = nil; off-roster CA must NOT be accepted")
	}
	if !strings.Contains(err.Error(), "unknown authority") &&
		!strings.Contains(err.Error(), "x509") &&
		!strings.Contains(err.Error(), "certificate") {
		t.Fatalf("Do(off-roster) error = %v; want TLS verification error", err)
	}
}

func TestConductorServerNameStripsPort(t *testing.T) {
	got, err := conductorServerName("https://boss.example:8443")
	if err != nil {
		t.Fatalf("conductorServerName() error = %v", err)
	}
	if got != "boss.example" {
		t.Fatalf("conductorServerName() = %q, want boss.example", got)
	}
}

func TestConductorRuntimeChanged(t *testing.T) {
	oldCfg := config.Defaults()
	newCfg := oldCfg.Clone()
	if conductorRuntimeChanged(oldCfg, newCfg) {
		t.Fatal("conductorRuntimeChanged(equal) = true, want false")
	}
	newCfg.Conductor.Enabled = true
	if !conductorRuntimeChanged(oldCfg, newCfg) {
		t.Fatal("conductorRuntimeChanged(changed) = false, want true")
	}
}

func mustHostname(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%s) error = %v", raw, err)
	}
	host := u.Hostname()
	if host == "" {
		t.Fatalf("url %s has no host", raw)
	}
	return host
}

// newTestTLSServer builds a single-leaf CA + server cert, starts an httptest
// server, and returns the CA PEM bundle plus the server. The CA is unique per
// call so two servers can't reuse the same chain.
func newTestTLSServer(t *testing.T) ([]byte, *httptest.Server) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(ca) error = %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: "pipelock-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(ca) error = %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(ca) error = %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(leaf) error = %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: mustSerial(t),
		Subject:      pkix.Name{CommonName: "pipelock-test-boss"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf) error = %v", err)
	}
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyBytes, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyBytes})
	leafCert, err := tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair(leaf) error = %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leafCert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	return caPEM, srv
}

// testTLSClientCert returns a self-signed client cert + key PEM pair. The cert
// uses ECDSA P-256 to keep test setup cheap and reproducible.
func testTLSClientCert(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: mustSerial(t),
		Subject:      pkix.Name{CommonName: "pipelock-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}
	return serial
}

func writePrivateTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
