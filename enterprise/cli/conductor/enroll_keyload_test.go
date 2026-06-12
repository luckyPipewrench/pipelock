//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestLoadEnrollmentToken(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		if _, err := loadEnrollmentToken("  "); err == nil || !strings.Contains(err.Error(), "is required") {
			t.Fatalf("loadEnrollmentToken(empty path) error = %v, want required", err)
		}
	})

	t.Run("unreadable path", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		if _, err := loadEnrollmentToken(missing); err == nil || !strings.Contains(err.Error(), "read --enrollment-token-file") {
			t.Fatalf("loadEnrollmentToken(missing) error = %v, want read error", err)
		}
	})

	t.Run("empty contents", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blank")
		if err := os.WriteFile(path, []byte("   \n\t "), 0o600); err != nil {
			t.Fatalf("write blank token: %v", err)
		}
		if _, err := loadEnrollmentToken(path); err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("loadEnrollmentToken(blank) error = %v, want empty", err)
		}
	})

	t.Run("trims and returns", func(t *testing.T) {
		token := "pl_" + "enroll_token"
		path := writeEnrollmentTokenFile(t, token)
		got, err := loadEnrollmentToken(path)
		if err != nil {
			t.Fatalf("loadEnrollmentToken() error = %v", err)
		}
		if got != token {
			t.Fatalf("loadEnrollmentToken() = %q, want %q", got, token)
		}
	})
}

func TestValidateAuditKeyID(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if err := validateAuditKeyID("   "); err == nil || !strings.Contains(err.Error(), "audit key id is required") {
			t.Fatalf("validateAuditKeyID(empty) error = %v, want required", err)
		}
	})

	t.Run("invalid identifier", func(t *testing.T) {
		if err := validateAuditKeyID("bad key!"); err == nil {
			t.Fatal("validateAuditKeyID(invalid) error = nil, want identifier rejection")
		}
	})

	t.Run("valid", func(t *testing.T) {
		if err := validateAuditKeyID("audit-key-1"); err != nil {
			t.Fatalf("validateAuditKeyID(valid) error = %v", err)
		}
	})
}

// writeRawPrivateKeyFile writes an Ed25519 private key in the raw
// pipelock-ed25519-private-v1 encoding (NOT the JSON keypair envelope) so the
// raw-key branch of loadEnrollmentAuditKey is exercised.
func writeRawPrivateKeyFile(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "raw-audit-key")
	if err := os.WriteFile(path, []byte(signing.EncodePrivateKey(priv)), 0o600); err != nil {
		t.Fatalf("write raw key: %v", err)
	}
	return path, pub
}

func TestLoadEnrollmentAuditKey(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		if _, _, err := loadEnrollmentAuditKey("  ", ""); err == nil || !strings.Contains(err.Error(), "is required") {
			t.Fatalf("loadEnrollmentAuditKey(empty) error = %v, want required", err)
		}
	})

	t.Run("json keypair derives id", func(t *testing.T) {
		_, keyFile, pub := writeSigningKeyWithPurpose(t, "audit-key-json", signing.PurposeAuditBatchSigning)
		gotID, gotPub, err := loadEnrollmentAuditKey(keyFile, "")
		if err != nil {
			t.Fatalf("loadEnrollmentAuditKey() error = %v", err)
		}
		if gotID != "audit-key-json" {
			t.Fatalf("loadEnrollmentAuditKey() id=%q, want audit-key-json", gotID)
		}
		if !pub.Equal(gotPub) {
			t.Fatal("loadEnrollmentAuditKey() returned mismatched public key")
		}
	})

	t.Run("json keypair override id wins", func(t *testing.T) {
		_, keyFile, _ := writeSigningKeyWithPurpose(t, "audit-key-json2", signing.PurposeAuditBatchSigning)
		gotID, _, err := loadEnrollmentAuditKey(keyFile, "audit-override")
		if err != nil {
			t.Fatalf("loadEnrollmentAuditKey(override) error = %v", err)
		}
		if gotID != "audit-override" {
			t.Fatalf("loadEnrollmentAuditKey(override) id=%q, want audit-override", gotID)
		}
	})

	t.Run("json keypair invalid override id rejected", func(t *testing.T) {
		_, keyFile, _ := writeSigningKeyWithPurpose(t, "audit-key-json3", signing.PurposeAuditBatchSigning)
		if _, _, err := loadEnrollmentAuditKey(keyFile, "bad id!"); err == nil {
			t.Fatal("loadEnrollmentAuditKey(bad override) error = nil, want identifier rejection")
		}
	})

	t.Run("raw private key requires audit key id", func(t *testing.T) {
		rawFile, _ := writeRawPrivateKeyFile(t)
		if _, _, err := loadEnrollmentAuditKey(rawFile, ""); err == nil ||
			!strings.Contains(err.Error(), "--audit-key-id is required") {
			t.Fatalf("loadEnrollmentAuditKey(raw, no id) error = %v, want id required", err)
		}
	})

	t.Run("raw private key with override id", func(t *testing.T) {
		rawFile, pub := writeRawPrivateKeyFile(t)
		gotID, gotPub, err := loadEnrollmentAuditKey(rawFile, "audit-raw-1")
		if err != nil {
			t.Fatalf("loadEnrollmentAuditKey(raw) error = %v", err)
		}
		if gotID != "audit-raw-1" {
			t.Fatalf("loadEnrollmentAuditKey(raw) id=%q, want audit-raw-1", gotID)
		}
		if !pub.Equal(gotPub) {
			t.Fatal("loadEnrollmentAuditKey(raw) returned mismatched public key")
		}
	})

	t.Run("raw private key invalid override id rejected", func(t *testing.T) {
		rawFile, _ := writeRawPrivateKeyFile(t)
		if _, _, err := loadEnrollmentAuditKey(rawFile, "bad id!"); err == nil {
			t.Fatal("loadEnrollmentAuditKey(raw, bad id) error = nil, want identifier rejection")
		}
	})

	t.Run("unreadable file errors", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent-key")
		if _, _, err := loadEnrollmentAuditKey(missing, "audit-key-1"); err == nil ||
			!strings.Contains(err.Error(), "load audit key file as JSON keypair or raw private key") {
			t.Fatalf("loadEnrollmentAuditKey(missing) error = %v, want combined load error", err)
		}
	})
}
