// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tlsfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadX509KeyPairSecurityBoundary(t *testing.T) {
	certPEM, keyPEM := testPair(t)
	write := func(dir, name string, data []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("0600 pair", func(t *testing.T) {
		dir := t.TempDir()
		cert := write(dir, "tls.crt", certPEM, 0o644)
		key := write(dir, "tls.key", keyPEM, 0o600)
		if _, err := LoadX509KeyPair(cert, key); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("0440 Kubernetes secret symlink", func(t *testing.T) {
		dir := t.TempDir()
		version := filepath.Join(dir, "..2026_07_14")
		if err := os.Mkdir(version, 0o750); err != nil {
			t.Fatal(err)
		}
		write(version, "tls.crt", certPEM, 0o440)
		write(version, "tls.key", keyPEM, 0o440)
		cert := filepath.Join(dir, "tls.crt")
		key := filepath.Join(dir, "tls.key")
		if err := os.Symlink(filepath.Join(filepath.Base(version), "tls.crt"), cert); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(filepath.Base(version), "tls.key"), key); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadX509KeyPair(cert, key); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("world readable private key", func(t *testing.T) {
		dir := t.TempDir()
		cert := write(dir, "tls.crt", certPEM, 0o644)
		key := write(dir, "tls.key", keyPEM, 0o644)
		if _, err := LoadX509KeyPair(cert, key); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("error = %v, want permissions rejection", err)
		}
	})
	t.Run("escaping key symlink", func(t *testing.T) {
		dir := t.TempDir()
		cert := write(dir, "tls.crt", certPEM, 0o644)
		outside := t.TempDir()
		target := write(outside, "tls.key", keyPEM, 0o600)
		key := filepath.Join(dir, "tls.key")
		if err := os.Symlink(target, key); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadX509KeyPair(cert, key); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("error = %v, want symlink escape rejection", err)
		}
	})
	t.Run("oversized certificate", func(t *testing.T) {
		dir := t.TempDir()
		cert := write(dir, "tls.crt", []byte(strings.Repeat("x", maxPEMBytes+1)), 0o644)
		key := write(dir, "tls.key", keyPEM, 0o600)
		if _, err := LoadX509KeyPair(cert, key); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("error = %v, want size rejection", err)
		}
	})
}

func testPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tlsfile.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
