// Package signing provides Ed25519 key generation, file signing, and
// signature verification for securing inter-agent communication.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SigExtension is the file extension for detached signature files.
const SigExtension = ".sig"

// Key file header lines identify the format version.
const (
	publicKeyHeader  = "pipelock-ed25519-public-v1"
	privateKeyHeader = "pipelock-ed25519-private-v1"
)

// GenerateKeyPair creates a new Ed25519 key pair using crypto/rand.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// SignFile reads a file and produces a detached Ed25519 signature.
func SignFile(path string, privKey ed25519.PrivateKey) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: caller controls path
	if err != nil {
		return nil, fmt.Errorf("reading file to sign: %w", err)
	}
	return ed25519.Sign(privKey, data), nil
}

// VerifyFile reads a file and its detached signature, verifying against pubKey.
// If sigPath is empty, it defaults to path + SigExtension.
func VerifyFile(path, sigPath string, pubKey ed25519.PublicKey) error {
	if sigPath == "" {
		sigPath = path + SigExtension
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: caller controls path
	if err != nil {
		return fmt.Errorf("reading file to verify: %w", err)
	}

	sig, err := LoadSignature(sigPath)
	if err != nil {
		return err
	}

	if !ed25519.Verify(pubKey, data, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// SaveSignature writes a base64-encoded signature to a .sig file.
// Uses atomic temp+rename to prevent corruption. Permissions are 0o644
// because signatures are public data used for verification.
func SaveSignature(sig []byte, path string) error {
	encoded := base64.StdEncoding.EncodeToString(sig) + "\n"
	return atomicWrite(path, []byte(encoded), 0o644)
}

// LoadSignature reads and decodes a base64-encoded .sig file.
func LoadSignature(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: caller controls path
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// EncodePublicKey serializes a public key with a versioned header.
func EncodePublicKey(key ed25519.PublicKey) string {
	return publicKeyHeader + "\n" + base64.StdEncoding.EncodeToString(key) + "\n"
}

// DecodePublicKey deserializes a public key from the versioned format.
func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	lines := strings.SplitN(strings.TrimSpace(encoded), "\n", 2)
	if len(lines) != 2 || lines[0] != publicKeyHeader {
		return nil, fmt.Errorf("invalid public key format (expected %s header)", publicKeyHeader)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// EncodePrivateKey serializes a private key with a versioned header.
func EncodePrivateKey(key ed25519.PrivateKey) string {
	return privateKeyHeader + "\n" + base64.StdEncoding.EncodeToString(key) + "\n"
}

// DecodePrivateKey deserializes a private key from the versioned format.
func DecodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	lines := strings.SplitN(strings.TrimSpace(encoded), "\n", 2)
	if len(lines) != 2 || lines[0] != privateKeyHeader {
		return nil, fmt.Errorf("invalid private key format (expected %s header)", privateKeyHeader)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: got %d, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// atomicWrite writes data to path via a temporary file and rename.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pipelock-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		tmp.Close()        //nolint:errcheck,gosec // best-effort cleanup
		os.Remove(tmpName) //nolint:errcheck,gosec // best-effort cleanup
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("writing file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:errcheck,gosec // best-effort cleanup
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil { //nolint:gosec // atomic rename in same directory
		os.Remove(tmpName) //nolint:errcheck,gosec // best-effort cleanup
		return fmt.Errorf("renaming file: %w", err)
	}
	return nil
}

// SavePublicKey writes an encoded public key to path with 0o644 permissions.
func SavePublicKey(key ed25519.PublicKey, path string) error {
	return atomicWrite(path, []byte(EncodePublicKey(key)), 0o644)
}

// SavePrivateKey writes an encoded private key to path with 0o600 permissions.
func SavePrivateKey(key ed25519.PrivateKey, path string) error {
	return atomicWrite(path, []byte(EncodePrivateKey(key)), 0o600)
}

// LoadPublicKeyFile reads and decodes a public key from a file.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: caller controls path
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	return DecodePublicKey(string(data))
}

// LoadPrivateKeyFile reads and decodes a private key from a file.
// Warns to stderr if the file is readable by group or others (mode & 0o077 != 0).
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: private key %s has permissions %04o — should be 0600\n", path, info.Mode().Perm())
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: caller controls path
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	return DecodePrivateKey(string(data))
}
