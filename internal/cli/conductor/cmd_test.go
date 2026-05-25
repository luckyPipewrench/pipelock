// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conductor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	conductorcore "github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestBuildServeHandlerWiresControlPlane(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "publisher-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}

	handler, tlsConfig, err := buildServeHandler(context.Background(), serveOptions{
		listen:              defaultListen,
		storageDir:          filepath.Join(dir, "store"),
		conductorID:         "conductor-test",
		followerTrustDomain: defaultTrustDomain,
		publisherTokenFile:  tokenPath,
		trustedAuditKeys: []string{
			"id=audit-key-1,inline=" + signing.EncodePublicKey(pub) + ",org=org-main",
		},
		tlsCert:  filepath.Join(dir, "server.pem"),
		tlsKey:   filepath.Join(dir, "server.key"),
		clientCA: caPath,
	})
	if err != nil {
		t.Fatalf("buildServeHandler() error = %v", err)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS config = %+v", tlsConfig)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, conductorcore.CapabilitiesPath, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d body=%s, want 200", w.Code, w.Body.String())
	}
}

func TestBuildServeHandlerRequiresAuthInputs(t *testing.T) {
	_, _, err := buildServeHandler(context.Background(), serveOptions{
		storageDir: "/tmp/store",
		tlsCert:    "server.pem",
		tlsKey:     "server.key",
	})
	if err == nil || err.Error() != "--client-ca is required" {
		t.Fatalf("buildServeHandler() error = %v, want --client-ca required", err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	tokenPath := filepath.Join(dir, "publisher-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	_, _, err = buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
	})
	if !errors.Is(err, controlplane.ErrAuditKeyRequired) {
		t.Fatalf("buildServeHandler() error = %v, want ErrAuditKeyRequired", err)
	}
}

func TestRunServeReturnsTLSLoadError(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "publisher-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	cmd := serveCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	err = runServe(cmd, serveOptions{
		listen:              "127.0.0.1:0",
		storageDir:          filepath.Join(dir, "store"),
		conductorID:         "conductor-test",
		followerTrustDomain: defaultTrustDomain,
		publisherTokenFile:  tokenPath,
		trustedAuditKeys: []string{
			"id=audit-key-1,inline=" + signing.EncodePublicKey(pub) + ",org=org-main",
		},
		tlsCert:  filepath.Join(dir, "missing-server.pem"),
		tlsKey:   filepath.Join(dir, "missing-server.key"),
		clientCA: caPath,
	})
	if err == nil || !strings.Contains(err.Error(), "missing-server.pem") {
		t.Fatalf("runServe() error = %v, want missing TLS cert error", err)
	}
	if !strings.Contains(out.String(), "pipelock: conductor listening on 127.0.0.1:0") {
		t.Fatalf("runServe() output = %q, want listening line", out.String())
	}
}

func TestParseAuditKeySpec(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		spec, err := parseAuditKeySpec("id=k1,inline=abc,org=o,fleet=f,instance=i")
		if err != nil {
			t.Fatalf("parseAuditKeySpec() error = %v", err)
		}
		if spec.id != "k1" || spec.inline != "abc" || spec.orgID != "o" || spec.fleetID != "f" || spec.instanceID != "i" {
			t.Fatalf("spec = %+v", spec)
		}
	})

	rejections := []struct {
		name   string
		input  string
		errSub string
	}{
		{"missing id", "inline=abc,org=o", "id= required"},
		{"missing org", "id=k1,inline=abc", "org= required"},
		{"missing material", "id=k1,org=o", "exactly one of inline= or file="},
		{"both inline and file", "id=k1,inline=abc,file=/tmp/x,org=o", "exactly one of inline= or file="},
		{"duplicate field", "id=k1,id=k2,inline=abc,org=o", "duplicate key"},
		{"unknown field", "id=k1,inline=abc,org=o,bogus=x", "unknown field"},
		{"empty input", "", "empty"},
		{"no equals", "id-k1,inline=abc", "expected k=v pairs"},
	}
	for _, c := range rejections {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseAuditKeySpec(c.input)
			if err == nil {
				t.Fatalf("parseAuditKeySpec(%q) error = nil, want %q", c.input, c.errSub)
			}
			if !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("parseAuditKeySpec(%q) error = %v, want substring %q", c.input, err, c.errSub)
			}
		})
	}
}

func TestLoadTokenFileRejectsMissingAndEmpty(t *testing.T) {
	if _, err := loadTokenFile(""); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("loadTokenFile(empty path) error = %v, want required", err)
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n\t"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadTokenFile(empty); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("loadTokenFile(whitespace) error = %v, want empty", err)
	}
	tok := filepath.Join(dir, "tok")
	if err := os.WriteFile(tok, []byte("  hello-token  \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := loadTokenFile(tok)
	if err != nil {
		t.Fatalf("loadTokenFile() error = %v", err)
	}
	if got != "hello-token" {
		t.Fatalf("loadTokenFile() = %q, want trimmed token", got)
	}
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(CA): %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
