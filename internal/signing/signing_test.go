package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	sig := ed25519.Sign(priv, data)

	if !ed25519.Verify(pub, data, sig) {
		t.Fatal("valid signature rejected")
	}
}

func TestSignVerify_WrongKey(t *testing.T) {
	_, priv1, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()

	data := []byte("hello world")
	sig := ed25519.Sign(priv1, data)

	if ed25519.Verify(pub2, data, sig) {
		t.Fatal("signature verified with wrong key")
	}
}

func TestSignVerify_TamperedData(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()

	data := []byte("original content")
	sig := ed25519.Sign(priv, data)

	tampered := []byte("tampered content")
	if ed25519.Verify(pub, tampered, sig) {
		t.Fatal("signature verified on tampered data")
	}
}

func TestSignFile_RoundTrip(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("file content\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sig, err := SignFile(path, priv)
	if err != nil {
		t.Fatalf("SignFile() error: %v", err)
	}

	sigPath := path + SigExtension
	if err := SaveSignature(sig, sigPath); err != nil {
		t.Fatalf("SaveSignature() error: %v", err)
	}

	if err := VerifyFile(path, sigPath, pub); err != nil {
		t.Fatalf("VerifyFile() error: %v", err)
	}
}

func TestSignFile_DefaultSigPath(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, []byte("binary data"), 0o600); err != nil {
		t.Fatal(err)
	}

	sig, err := SignFile(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSignature(sig, path+SigExtension); err != nil {
		t.Fatal(err)
	}

	// Empty sigPath should default to path + .sig
	if err := VerifyFile(path, "", pub); err != nil {
		t.Fatalf("VerifyFile with default sig path: %v", err)
	}
}

func TestVerifyFile_TamperedFile(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	sig, err := SignFile(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	sigPath := path + SigExtension
	if err := SaveSignature(sig, sigPath); err != nil {
		t.Fatal(err)
	}

	// Tamper with the file
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := VerifyFile(path, sigPath, pub); err == nil {
		t.Fatal("expected verification failure on tampered file")
	}
}

func TestVerifyFile_MissingSig(t *testing.T) {
	pub, _, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := VerifyFile(path, "", pub); err == nil {
		t.Fatal("expected error for missing signature file")
	}
}

func TestSignFile_Nonexistent(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	_, err := SignFile("/nonexistent/file.txt", priv)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSaveLoadSignature_RoundTrip(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	data := []byte("test data")
	sig := ed25519.Sign(priv, data)

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "test.sig")

	if err := SaveSignature(sig, sigPath); err != nil {
		t.Fatalf("SaveSignature() error: %v", err)
	}

	loaded, err := LoadSignature(sigPath)
	if err != nil {
		t.Fatalf("LoadSignature() error: %v", err)
	}

	if !bytes.Equal(sig, loaded) {
		t.Fatal("loaded signature does not match saved signature")
	}
}

func TestSaveSignature_Permissions(t *testing.T) {
	dir := t.TempDir()
	sigPath := filepath.Join(dir, "test.sig")

	if err := SaveSignature([]byte("fake-sig"), sigPath); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("signature permissions = %04o, want 0644", info.Mode().Perm())
	}
}

func TestLoadSignature_InvalidBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.sig")
	if err := os.WriteFile(path, []byte("not-valid-base64!!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSignature(path)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestEncodeDecodePublicKey_RoundTrip(t *testing.T) {
	pub, _, _ := GenerateKeyPair()

	encoded := EncodePublicKey(pub)
	decoded, err := DecodePublicKey(encoded)
	if err != nil {
		t.Fatalf("DecodePublicKey() error: %v", err)
	}

	if !bytes.Equal(pub, decoded) {
		t.Fatal("decoded public key does not match original")
	}
}

func TestEncodeDecodePrivateKey_RoundTrip(t *testing.T) {
	_, priv, _ := GenerateKeyPair()

	encoded := EncodePrivateKey(priv)
	decoded, err := DecodePrivateKey(encoded)
	if err != nil {
		t.Fatalf("DecodePrivateKey() error: %v", err)
	}

	if !bytes.Equal(priv, decoded) {
		t.Fatal("decoded private key does not match original")
	}
}

func TestDecodePublicKey_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"no header", base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{"wrong header", "wrong-header\n" + base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{"bad base64", publicKeyHeader + "\nnot-base64!!!"},
		{"wrong length", publicKeyHeader + "\n" + base64.StdEncoding.EncodeToString(make([]byte, 16))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePublicKey(tt.input)
			if err == nil {
				t.Fatalf("expected error for input %q", tt.name)
			}
		})
	}
}

func TestDecodePrivateKey_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"wrong header", "wrong-header\n" + base64.StdEncoding.EncodeToString(make([]byte, 64))},
		{"bad base64", privateKeyHeader + "\nnot-base64!!!"},
		{"wrong length", privateKeyHeader + "\n" + base64.StdEncoding.EncodeToString(make([]byte, 16))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePrivateKey(tt.input)
			if err == nil {
				t.Fatalf("expected error for input %q", tt.name)
			}
		})
	}
}

func TestSaveLoadPublicKeyFile_RoundTrip(t *testing.T) {
	pub, _, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pub")

	if err := SavePublicKey(pub, path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPublicKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pub, loaded) {
		t.Fatal("loaded key does not match saved key")
	}
}

func TestSaveLoadPrivateKeyFile_RoundTrip(t *testing.T) {
	_, priv, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	if err := SavePrivateKey(priv, path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPrivateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(priv, loaded) {
		t.Fatal("loaded key does not match saved key")
	}
}

func TestSavePrivateKeyFile_Permissions(t *testing.T) {
	_, priv, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	if err := SavePrivateKey(priv, path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestSavePublicKeyFile_Permissions(t *testing.T) {
	pub, _, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pub")

	if err := SavePublicKey(pub, path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("public key permissions = %04o, want 0644", info.Mode().Perm())
	}
}

func TestVerifyFile_MissingFile(t *testing.T) {
	pub, _, _ := GenerateKeyPair()
	err := VerifyFile("/nonexistent/file.txt", "/nonexistent/file.txt.sig", pub)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestAtomicWrite_BadDirectory(t *testing.T) {
	// Writing to a non-existent directory should fail.
	err := atomicWrite("/nonexistent/dir/file.txt", []byte("data"), 0o644)
	if err == nil {
		t.Fatal("expected error for bad directory")
	}
}

func TestAtomicWrite_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	data := []byte("hello atomic write")

	if err := atomicWrite(path, data, 0o644); err != nil {
		t.Fatalf("atomicWrite() error: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("data mismatch: got %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("permissions = %04o, want 0644", info.Mode().Perm())
	}
}

func TestAtomicWrite_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overwrite.txt")

	if err := atomicWrite(path, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("expected 'second', got %q", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestDefaultKeystorePath(t *testing.T) {
	path, err := DefaultKeystorePath()
	if err != nil {
		t.Fatalf("DefaultKeystorePath() error: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}
	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path, got %q", path)
	}
	if filepath.Base(path) != DefaultPipelockDir {
		t.Errorf("expected base %q, got %q", DefaultPipelockDir, filepath.Base(path))
	}
}

func TestLoadSignature_WrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "truncated.sig")

	// Write a valid base64 string but with wrong decoded length (not 64 bytes).
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	if err := os.WriteFile(path, []byte(short), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSignature(path)
	if err == nil {
		t.Fatal("expected error for wrong signature length")
	}
}
