// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package certgen

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testOrg         = "Test"
	testHost        = "example.com"
	testCertFile    = "ca.pem"
	testKeyFile     = "ca-key.pem"
	testCertPath    = "/tmp/ca.pem"
	testValidityDay = 24 * time.Hour
)

func TestGenerateCA(t *testing.T) {
	cert, key, pemBytes, err := GenerateCA("Test Org", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if cert == nil || key == nil || len(pemBytes) == 0 {
		t.Fatal("GenerateCA returned nil values")
	}
	if !cert.IsCA {
		t.Error("cert is not CA")
	}
	if cert.Subject.Organization[0] != "Test Org" {
		t.Errorf("org = %q, want %q", cert.Subject.Organization[0], "Test Org")
	}
	if cert.Subject.CommonName != "Pipelock CA" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "Pipelock CA")
	}
	if key == nil {
		t.Error("key is nil")
	}
}

func TestGenerateLeaf_Hostname(t *testing.T) {
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := GenerateLeaf(ca, caKey, "api.example.com", time.Hour)
	if err != nil {
		t.Fatalf("GenerateLeaf: %v", err)
	}
	if leaf == nil {
		t.Fatal("leaf is nil")
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "api.example.com" {
		t.Errorf("DNSNames = %v, want [api.example.com]", parsed.DNSNames)
	}
	if len(parsed.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want empty", parsed.IPAddresses)
	}
	// Verify cert chains to CA.
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("cert does not chain to CA: %v", err)
	}
}

func TestGenerateLeaf_IPv4(t *testing.T) {
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := GenerateLeaf(ca, caKey, "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.IPAddresses) != 1 {
		t.Fatalf("IPAddresses = %v, want [127.0.0.1]", parsed.IPAddresses)
	}
	if parsed.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IP = %v, want 127.0.0.1", parsed.IPAddresses[0])
	}
}

func TestGenerateLeaf_IPv6(t *testing.T) {
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := GenerateLeaf(ca, caKey, "::1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.IPAddresses) != 1 {
		t.Fatalf("IPAddresses = %v, want [::1]", parsed.IPAddresses)
	}
}

func TestCertCache_GetGeneratesOnMiss(t *testing.T) {
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, time.Hour, 100)
	cert, err := cache.Get("example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
	if cache.Size() != 1 {
		t.Errorf("size = %d, want 1", cache.Size())
	}
}

func TestCertCache_GetReturnsCached(t *testing.T) {
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, time.Hour, 100)
	cert1, _ := cache.Get("example.com")
	cert2, _ := cache.Get("example.com")
	// Same pointer means cache hit.
	if cert1 != cert2 {
		t.Error("second Get returned different cert (cache miss)")
	}
}

func TestCertCache_EvictsWhenFull(t *testing.T) {
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, time.Hour, 3) // cap at 3
	for i := range 5 {
		_, err := cache.Get(fmt.Sprintf("host%d.example.com", i))
		if err != nil {
			t.Fatal(err)
		}
	}
	if cache.Size() > 3 {
		t.Errorf("size = %d, want <= 3", cache.Size())
	}
}

func TestCertCache_RegeneratesExpired(t *testing.T) {
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, 2*time.Second, 100)
	cert1, _ := cache.Get("example.com")

	// Manually expire the cached entry.
	cache.mu.Lock()
	cache.certs["example.com"].expiresAt = time.Now().Add(-1 * time.Second)
	cache.mu.Unlock()

	cert2, _ := cache.Get("example.com")
	if cert1 == cert2 {
		t.Error("expired cert was not regenerated")
	}
}

func TestCertCache_ConcurrentAccess(t *testing.T) {
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, time.Hour, 1000)
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := cache.Get(fmt.Sprintf("host%d.example.com", i))
			if err != nil {
				t.Errorf("Get(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestSaveAndLoadCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca, key, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCA(certPath, keyPath, ca, key); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	loadedCert, loadedKey, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if loadedCert.Subject.CommonName != ca.Subject.CommonName {
		t.Errorf("CN = %q, want %q", loadedCert.Subject.CommonName, ca.Subject.CommonName)
	}
	if loadedKey == nil {
		t.Error("loaded key is nil")
	}
}

func TestSaveCA_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca, key, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCA(certPath, keyPath, ca, key); err != nil {
		t.Fatal(err)
	}
	// Second save should fail (no overwrite).
	err = SaveCA(certPath, keyPath, ca, key)
	if err == nil {
		t.Error("expected error on overwrite, got nil")
	}
}

func TestSaveCA_ForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca, key, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCA(certPath, keyPath, ca, key); err != nil {
		t.Fatal(err)
	}
	if err := SaveCAForce(certPath, keyPath, ca, key); err != nil {
		t.Fatalf("SaveCAForce: %v", err)
	}
}

func TestLoadCA_MissingFiles(t *testing.T) {
	_, _, err := LoadCA("/nonexistent/ca.pem", "/nonexistent/ca-key.pem")
	if err == nil {
		t.Error("expected error for missing files")
	}
}

func TestLoadCA_InvalidCertPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(certPath, []byte("not a PEM block"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for invalid cert PEM")
	}
}

func TestLoadCA_InvalidKeyPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "bad-key.pem")

	ca, key, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCAForce(certPath, keyPath, ca, key); err != nil {
		t.Fatal(err)
	}
	// Overwrite key with invalid PEM.
	if err := os.WriteFile(keyPath, []byte("not a PEM block"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for invalid key PEM")
	}
}

func TestLoadCA_MissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca, key, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCAForce(certPath, keyPath, ca, key); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(keyPath)
	_, _, err = LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

func TestLoadCA_RejectsNonCA(t *testing.T) {
	// Generate a CA and then create a non-CA leaf cert.
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, time.Hour, 100)
	// Get a leaf cert (not a CA).
	leafCert, err := cache.Get("example.com")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "leaf.pem")
	keyPath := filepath.Join(dir, "leaf-key.pem")

	// Write the leaf cert PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Certificate[0]})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Write the CA key PEM (mismatched with leaf cert).
	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err = LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for non-CA certificate")
	}
}

func TestLoadCA_RejectsMissingCertSign(t *testing.T) {
	// Create a cert with IsCA=true but without KeyUsageCertSign.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature, // no CertSign
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err = LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for CA without KeyUsageCertSign")
	}
}

func TestLoadCA_RejectsMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	// Generate two CAs.
	ca1, _, _, err := GenerateCA("CA1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, key2, _, err := GenerateCA("CA2", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Save cert from CA1 with key from CA2.
	if err := SaveCAForce(certPath, keyPath, ca1, key2); err != nil {
		t.Fatal(err)
	}
	_, _, err = LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for mismatched key")
	}
}

func TestInstallCA_PrintsInstructions(t *testing.T) {
	var buf bytes.Buffer
	if err := InstallCA(&buf, "/tmp/ca.pem"); err != nil {
		t.Fatalf("InstallCA: %v", err)
	}
	output := buf.String()
	if len(output) == 0 {
		t.Error("InstallCA produced no output")
	}
	// Should contain the cert path in the output.
	if !bytes.Contains(buf.Bytes(), []byte("/tmp/ca.pem")) {
		t.Error("output does not contain cert path")
	}
}

func TestWriteCAFiles_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(roDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Write cert to writable dir, key to read-only dir.
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(roDir, "subdir", "ca-key.pem")

	ca, key, _, err := GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Make roDir read-only so MkdirAll for keyPath fails.
	if err := os.Chmod(roDir, 0o444); err != nil { //nolint:gosec // test: intentionally restrictive perms
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o750) }) //nolint:gosec // test: restore dir permissions for cleanup

	err = writeCAFiles(certPath, keyPath, ca, key)
	if err == nil {
		t.Error("expected error for read-only key directory")
	}
}

func TestNewCertCache_PanicsOnNilCA(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil CA")
		}
	}()
	NewCertCache(nil, nil, time.Hour, 100)
}

func TestNewCertCache_PanicsOnZeroMaxSize(t *testing.T) {
	ca, caKey, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for zero maxSize")
		}
	}()
	NewCertCache(ca, caKey, time.Hour, 0)
}

func TestNewCertCache_PanicsOnNegativeMaxSize(t *testing.T) {
	ca, caKey, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for negative maxSize")
		}
	}()
	NewCertCache(ca, caKey, time.Hour, -1)
}

func TestSaveCA_RefusesOverwrite_KeyExists(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, testCertFile)
	keyPath := filepath.Join(dir, testKeyFile)

	ca, key, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCA(certPath, keyPath, ca, key); err != nil {
		t.Fatal(err)
	}

	// Remove cert but leave key, then try to save again.
	_ = os.Remove(certPath)
	err = SaveCA(certPath, keyPath, ca, key)
	if err == nil {
		t.Error("expected error when key already exists")
	}
	if !strings.Contains(err.Error(), "CA key already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWriteCAFiles_CertDirCreateFails(t *testing.T) {
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(roDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Both cert and key paths under read-only directory.
	certPath := filepath.Join(roDir, "subdir", testCertFile)
	keyPath := filepath.Join(dir, testKeyFile)

	ca, key, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}

	// Make roDir read-only so MkdirAll for certPath fails.
	if err := os.Chmod(roDir, 0o444); err != nil { //nolint:gosec // test: intentionally restrictive perms
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o750) }) //nolint:gosec // test: restore dir permissions for cleanup

	err = writeCAFiles(certPath, keyPath, ca, key)
	if err == nil {
		t.Error("expected error for read-only cert directory")
	}
	if !strings.Contains(err.Error(), "create cert directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWriteCAFiles_WriteCertFails(t *testing.T) {
	dir := t.TempDir()
	// Create a directory where the cert file should go, making the write fail.
	certPath := filepath.Join(dir, testCertFile)
	keyPath := filepath.Join(dir, testKeyFile)

	ca, key, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}

	// Create a directory at certPath so WriteFile fails (can't write to a directory).
	if err := os.MkdirAll(certPath, 0o750); err != nil {
		t.Fatal(err)
	}

	err = writeCAFiles(certPath, keyPath, ca, key)
	if err == nil {
		t.Error("expected error when cert path is a directory")
	}
	if !strings.Contains(err.Error(), "write CA cert") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWriteCAFiles_WriteKeyFails(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, testCertFile)
	keyPath := filepath.Join(dir, testKeyFile)

	ca, key, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}

	// Create a directory at keyPath so WriteFile fails.
	if err := os.MkdirAll(keyPath, 0o750); err != nil {
		t.Fatal(err)
	}

	err = writeCAFiles(certPath, keyPath, ca, key)
	if err == nil {
		t.Error("expected error when key path is a directory")
	}
	if !strings.Contains(err.Error(), "write CA key") {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify cleanup removed the cert file.
	if _, statErr := os.Stat(certPath); statErr == nil {
		t.Error("cert file should have been cleaned up after key write failure")
	}
}

func TestLoadCA_InvalidECKeyBytes(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, testCertFile)
	keyPath := filepath.Join(dir, testKeyFile)

	ca, key, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCAForce(certPath, keyPath, ca, key); err != nil {
		t.Fatal(err)
	}

	// Overwrite key file with a valid PEM block containing garbage EC key bytes.
	badKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not valid DER")})
	if err := os.WriteFile(keyPath, badKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err = LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for invalid EC key DER bytes")
	}
	if !strings.Contains(err.Error(), "parse CA key") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadCA_InvalidCertDER(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, testCertFile)
	keyPath := filepath.Join(dir, testKeyFile)

	// Write a valid PEM block with garbage certificate DER bytes.
	badCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not valid DER")})
	if err := os.WriteFile(certPath, badCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Key file doesn't matter; cert parse should fail first.
	if err := os.WriteFile(keyPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for invalid cert DER bytes")
	}
	if !strings.Contains(err.Error(), "parse CA cert") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadCA_NonECDSAPublicKey(t *testing.T) {
	// Create a CA cert with Ed25519 key, then try to load with an ECDSA key file.
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(testValidityDay),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, edKey.Public(), edKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, testCertFile)
	keyPath := filepath.Join(dir, testKeyFile)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Write a valid ECDSA key (LoadCA will get past key parsing but fail on type assertion).
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err = LoadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error for non-ECDSA public key in CA cert")
	}
	if !strings.Contains(err.Error(), "not ECDSA") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInstallCA_CurrentPlatformOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := InstallCA(&buf, testCertPath); err != nil {
		t.Fatalf("InstallCA: %v", err)
	}
	output := buf.String()

	// Verify platform-specific content based on runtime.GOOS.
	switch runtime.GOOS {
	case "linux":
		if !strings.Contains(output, "Linux") {
			t.Error("linux output should mention Linux")
		}
		if !strings.Contains(output, "update-ca-certificates") {
			t.Error("linux output should mention update-ca-certificates")
		}
		if !strings.Contains(output, "update-ca-trust") {
			t.Error("linux output should mention update-ca-trust")
		}
		if !strings.Contains(output, testCertPath) {
			t.Error("linux output should contain the cert path")
		}
	case "darwin":
		if !strings.Contains(output, "macOS") {
			t.Error("darwin output should mention macOS")
		}
		if !strings.Contains(output, "security add-trusted-cert") {
			t.Error("darwin output should mention security command")
		}
	case "windows":
		if !strings.Contains(output, "Windows") {
			t.Error("windows output should mention Windows")
		}
		if !strings.Contains(output, "certutil") {
			t.Error("windows output should mention certutil")
		}
	default:
		if !strings.Contains(output, "Unsupported OS") {
			t.Error("unsupported OS output should mention Unsupported OS")
		}
	}
}

func TestInstallCAForOS_AllPlatforms(t *testing.T) {
	tests := []struct {
		goos     string
		contains []string
	}{
		{
			goos:     "linux",
			contains: []string{"Linux", "update-ca-certificates", "update-ca-trust", testCertPath},
		},
		{
			goos:     "darwin",
			contains: []string{"macOS", "security add-trusted-cert", testCertPath},
		},
		{
			goos:     "windows",
			contains: []string{"Windows", "certutil", testCertPath},
		},
		{
			goos:     "freebsd",
			contains: []string{"Unsupported OS: freebsd", testCertPath},
		},
	}

	for _, tc := range tests {
		t.Run(tc.goos, func(t *testing.T) {
			var buf bytes.Buffer
			if err := installCAForOS(&buf, testCertPath, tc.goos); err != nil {
				t.Fatalf("installCAForOS(%q): %v", tc.goos, err)
			}
			output := buf.String()
			for _, want := range tc.contains {
				if !strings.Contains(output, want) {
					t.Errorf("output for %q should contain %q", tc.goos, want)
				}
			}
		})
	}
}

func TestCertCache_GetReturnsErrorOnBadCA(t *testing.T) {
	// Create a valid CA but use an Ed25519 key as the signing key.
	// This makes GenerateLeaf fail because x509.CreateCertificate will reject
	// the mismatch between the CA cert and signing key.
	ca, _, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}

	// Use an Ed25519 key instead of the ECDSA CA key.
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cache := NewCertCache(ca, edKey, time.Hour, 100)
	_, err = cache.Get(testHost)
	if err == nil {
		t.Error("expected error when CA key is wrong type for signing")
	}
}

func TestCertCache_EvictsExpiredFirst(t *testing.T) {
	ca, caKey, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, time.Hour, 2) // cap at 2

	// Insert two entries.
	if _, err := cache.Get("a.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get("b.example.com"); err != nil {
		t.Fatal(err)
	}

	// Expire one entry.
	cache.mu.Lock()
	cache.certs["a.example.com"].expiresAt = time.Now().Add(-time.Second)
	cache.mu.Unlock()

	// Adding a third should evict the expired one, keeping size at 2.
	if _, err := cache.Get("c.example.com"); err != nil {
		t.Fatal(err)
	}

	if cache.Size() > 2 {
		t.Errorf("size = %d, want <= 2", cache.Size())
	}

	// Verify expired entry was evicted, not a live one.
	cache.mu.RLock()
	_, hasA := cache.certs["a.example.com"]
	_, hasB := cache.certs["b.example.com"]
	_, hasC := cache.certs["c.example.com"]
	cache.mu.RUnlock()

	if hasA {
		t.Error("expired entry 'a' should have been evicted")
	}
	if !hasB || !hasC {
		t.Error("live entries 'b' and 'c' should be present")
	}
}

func TestCertCache_EvictsOldestWhenNoneExpired(t *testing.T) {
	ca, caKey, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, time.Hour, 2) // cap at 2

	// Insert two entries with controlled expiration times.
	if _, err := cache.Get("first.example.com"); err != nil {
		t.Fatal(err)
	}

	// Make the first entry expire sooner (but still valid).
	cache.mu.Lock()
	cache.certs["first.example.com"].expiresAt = time.Now().Add(10 * time.Minute) // 10 min from now: earliest
	cache.mu.Unlock()

	if _, err := cache.Get("second.example.com"); err != nil {
		t.Fatal(err)
	}

	// Insert a third, forcing eviction. Since none are expired, oldest-expiring should be evicted.
	if _, err := cache.Get("third.example.com"); err != nil {
		t.Fatal(err)
	}

	if cache.Size() > 2 {
		t.Errorf("size = %d, want <= 2", cache.Size())
	}

	cache.mu.RLock()
	_, hasFirst := cache.certs["first.example.com"]
	cache.mu.RUnlock()

	if hasFirst {
		t.Error("earliest-expiring entry 'first' should have been evicted")
	}
}

func TestCertCache_DoubleCheckAfterWriteLock(t *testing.T) {
	ca, caKey, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCertCache(ca, caKey, time.Hour, 100)

	// To exercise the double-check path (line 275-276), we need a scenario where
	// the entry exists and is valid when the write lock is acquired but was
	// missing during the read lock check. We simulate this by manually injecting
	// an entry between the two lock acquisitions.
	//
	// Since we can't intercept the lock in production code, we exercise it
	// indirectly: pre-populate the cache, then have many goroutines race to
	// re-get the same expired host. Some will hit the double-check.
	const host = "race.example.com"

	// Populate cache with an entry that's about to expire.
	if _, err := cache.Get(host); err != nil {
		t.Fatal(err)
	}

	// Expire it so the RLock check misses.
	cache.mu.Lock()
	cache.certs[host].expiresAt = time.Now().Add(-time.Millisecond)
	cache.mu.Unlock()

	// 50 goroutines: 50 goroutines all see expired, race to regenerate.
	// Only one generates; the rest hit the double-check path.
	var wg sync.WaitGroup
	const goroutines = 50
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.Get(host); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()

	// Cache should have exactly 1 entry for this host.
	if cache.Size() != 1 {
		t.Errorf("size = %d, want 1", cache.Size())
	}
}

func TestGenerateCA_CertProperties(t *testing.T) {
	validity := 48 * time.Hour
	cert, key, pemBytes, err := GenerateCA("Custom Org", validity)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Verify PEM decodes back to the same cert.
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("PEM decode returned nil block")
	}
	if len(rest) != 0 {
		t.Error("PEM has trailing data")
	}
	parsedFromPEM, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse PEM cert: %v", err)
	}
	if parsedFromPEM.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("PEM cert serial does not match returned cert serial")
	}

	// Verify key matches cert.
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("key does not match cert public key")
	}

	// Verify CA constraints.
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}
	if !cert.MaxPathLenZero {
		t.Error("MaxPathLenZero should be true")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("missing KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("missing KeyUsageCRLSign")
	}

	// Verify validity window: NotBefore should be backdated ~1h.
	if time.Since(cert.NotBefore) < 30*time.Minute {
		t.Error("NotBefore should be backdated by ~1 hour")
	}
}

func TestGenerateLeaf_CertProperties(t *testing.T) {
	ca, caKey, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatal(err)
	}

	ttl := 2 * time.Hour
	leaf, err := GenerateLeaf(ca, caKey, "api.test.com", ttl)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// Verify leaf is NOT a CA.
	if parsed.IsCA {
		t.Error("leaf cert should not be a CA")
	}

	// Verify key usage.
	if parsed.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("missing KeyUsageDigitalSignature")
	}

	// Verify extended key usage.
	if len(parsed.ExtKeyUsage) != 1 || parsed.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", parsed.ExtKeyUsage)
	}

	// Verify CN.
	if parsed.Subject.CommonName != "api.test.com" {
		t.Errorf("CN = %q, want %q", parsed.Subject.CommonName, "api.test.com")
	}

	// Verify private key is present and ECDSA.
	if leaf.PrivateKey == nil {
		t.Fatal("leaf private key is nil")
	}
	if _, ok := leaf.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("private key type = %T, want *ecdsa.PrivateKey", leaf.PrivateKey)
	}
}

func TestGenerateCA_RejectsNonPositiveValidity(t *testing.T) {
	for _, dur := range []time.Duration{0, -time.Hour} {
		_, _, _, err := GenerateCA(testOrg, dur)
		if err == nil {
			t.Errorf("GenerateCA(validity=%v): expected error, got nil", dur)
		}
	}
}

func TestGenerateLeaf_RejectsNonPositiveTTL(t *testing.T) {
	ca, key, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	for _, dur := range []time.Duration{0, -time.Hour} {
		_, err := GenerateLeaf(ca, key, testHost, dur)
		if err == nil {
			t.Errorf("GenerateLeaf(ttl=%v): expected error, got nil", dur)
		}
	}
}
