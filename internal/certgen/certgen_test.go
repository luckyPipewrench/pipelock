package certgen

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
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
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o600) })

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
	ca, caKey, _, err := GenerateCA("Test", 24*time.Hour)
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
