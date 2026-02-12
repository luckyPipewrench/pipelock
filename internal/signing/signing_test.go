package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadPrivateKeyFile_PermissionWarning(t *testing.T) {
	_, priv, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "wide-open.key")

	if err := SavePrivateKey(priv, path); err != nil {
		t.Fatal(err)
	}

	// Make the key readable by group/others (insecure)
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // intentionally insecure for test
		t.Fatal(err)
	}

	// LoadPrivateKeyFile should still succeed but emit a warning to stderr.
	// We can't easily capture stderr, but we verify it loads correctly.
	loaded, err := LoadPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFile should succeed despite bad perms: %v", err)
	}
	if !bytes.Equal(priv, loaded) {
		t.Fatal("loaded key does not match saved key")
	}
}

func TestLoadPrivateKeyFile_GoodPermissions(t *testing.T) {
	_, priv, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "secure.key")

	if err := SavePrivateKey(priv, path); err != nil {
		t.Fatal(err)
	}

	// Verify 0600 permissions (set by SavePrivateKey)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %04o", info.Mode().Perm())
	}

	loaded, err := LoadPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFile error: %v", err)
	}
	if !bytes.Equal(priv, loaded) {
		t.Fatal("loaded key does not match")
	}
}

func TestLoadPrivateKeyFile_NonexistentFile(t *testing.T) {
	_, err := LoadPrivateKeyFile("/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadPublicKeyFile_NonexistentFile(t *testing.T) {
	_, err := LoadPublicKeyFile("/nonexistent/key.pub")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSaveSignature_BadDirectory(t *testing.T) {
	err := SaveSignature([]byte("fake-sig"), "/nonexistent/dir/test.sig")
	if err == nil {
		t.Fatal("expected error for bad directory")
	}
}

func TestLoadPrivateKeyFile_StatOKButUnreadable(t *testing.T) {
	// Save a valid key, then remove read permission.
	// os.Stat succeeds (doesn't need read perm), but os.ReadFile fails.
	_, priv, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "noaccess.key")

	if err := SavePrivateKey(priv, path); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) }) //nolint:errcheck,gosec // best-effort cleanup

	_, err := LoadPrivateKeyFile(path)
	if err == nil {
		t.Fatal("expected error when file is unreadable")
	}
	if !strings.Contains(err.Error(), "reading private key") {
		t.Errorf("expected 'reading private key' error, got: %v", err)
	}
}

func TestAtomicWrite_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Write a file first so we can test overwrite behavior.
	path := filepath.Join(subdir, "file.txt")
	if err := atomicWrite(path, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Make dir read-only so CreateTemp fails.
	if err := os.Chmod(subdir, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(subdir, 0o700) }) //nolint:gosec // restore for cleanup

	err := atomicWrite(path, []byte("second"), 0o644)
	if err == nil {
		t.Fatal("expected error for read-only directory")
	}
	if !strings.Contains(err.Error(), "creating temp file") {
		t.Errorf("expected 'creating temp file' error, got: %v", err)
	}
}

func TestDefaultKeystorePath_ReturnsPath(t *testing.T) {
	path, err := DefaultKeystorePath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(path, DefaultPipelockDir) {
		t.Errorf("expected path ending with %s, got: %s", DefaultPipelockDir, path)
	}
}

func TestSavePublicKey_BadPath(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	err = SavePublicKey(pub, "/nonexistent/dir/key.pub")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

func TestSavePrivateKey_BadPath(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	err = SavePrivateKey(priv, "/nonexistent/dir/key.priv")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

func TestVerifyFile_BadSignature(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(file, []byte("test data"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sign then modify the file to make signature invalid.
	sig, err := SignFile(file, priv)
	if err != nil {
		t.Fatal(err)
	}
	sigPath := file + SigExtension
	if err := SaveSignature(sig, sigPath); err != nil {
		t.Fatal(err)
	}

	// Tamper the file.
	if err := os.WriteFile(file, []byte("tampered data"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = VerifyFile(file, "", pub)
	if err == nil {
		t.Fatal("expected verification failure for tampered file")
	}
}

func TestLoadPublicKeyFile_Missing(t *testing.T) {
	_, err := LoadPublicKeyFile("/nonexistent/key.pub")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPrivateKeyFile_Missing(t *testing.T) {
	_, err := LoadPrivateKeyFile("/nonexistent/key.priv")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestAtomicWrite_RenameError(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory where the file should be written.
	// os.Rename(file, directory) fails with EISDIR.
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}

	err := atomicWrite(target, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error when target is a directory")
	}
	if !strings.Contains(err.Error(), "renaming file") {
		t.Errorf("expected 'renaming file' error, got: %v", err)
	}
}
