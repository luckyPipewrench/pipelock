//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func writeRootKey(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "license.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save root key: %v", err)
	}
	return keyPath, pub
}

func runIntermediateIssue(t *testing.T, args ...string) error {
	t.Helper()
	cmd := LicenseCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"intermediate", "issue"}, args...))
	return cmd.Execute()
}

func TestLicenseIntermediateIssue(t *testing.T) {
	rootKey, rootPub := writeRootKey(t)

	t.Run("mints_a_root_verifiable_cert_with_matching_key", func(t *testing.T) {
		outDir := t.TempDir()
		err := runIntermediateIssue(t,
			"--root-key", rootKey, "--serial", "im-2026-001", "--out", outDir, "--validity", "2160h")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		certPath := filepath.Join(outDir, "intermediate.json")
		keyPath := filepath.Join(outDir, "intermediate.key")

		// Cert verifies against the root key.
		certBytes, err := os.ReadFile(filepath.Clean(certPath))
		if err != nil {
			t.Fatalf("read cert: %v", err)
		}
		cert, err := license.ParseAndVerifyIntermediate(certBytes, rootPub, time.Now())
		if err != nil {
			t.Fatalf("minted cert must verify against root: %v", err)
		}
		if cert.Serial() != "im-2026-001" {
			t.Fatalf("serial = %q", cert.Serial())
		}

		// The minted intermediate private key matches the cert's public key:
		// a token signed by the key verifies through the chain.
		intPriv, err := signing.LoadPrivateKeyFile(keyPath)
		if err != nil {
			t.Fatalf("load intermediate key: %v", err)
		}
		tok, err := license.Issue(license.License{
			ID: "lic_x", Email: "ops@example.test", Features: []string{license.FeatureFleet},
		}, intPriv)
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		if _, err := license.VerifyTokenWithOptions(tok, license.VerifyOptions{
			Intermediate: certBytes, RequireIntermediate: false, RootPub: rootPub, Now: time.Now(),
		}); err != nil {
			t.Fatalf("token signed by minted key must verify through chain: %v", err)
		}

		// 0600 perms on both outputs.
		for _, p := range []string{certPath, keyPath} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat %s: %v", p, err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("%s perm = %o, want 0600", p, info.Mode().Perm())
			}
		}
	})

	t.Run("requires_serial", func(t *testing.T) {
		err := runIntermediateIssue(t, "--root-key", rootKey, "--out", t.TempDir())
		if err == nil {
			t.Fatal("missing --serial must error")
		}
	})

	t.Run("rejects_excessive_validity", func(t *testing.T) {
		// Library cap is 400 days; 500 days must be rejected at sign time.
		err := runIntermediateIssue(t,
			"--root-key", rootKey, "--serial", "im-big", "--out", t.TempDir(), "--validity", "12000h")
		if err == nil {
			t.Fatal("validity beyond the library maximum must be rejected")
		}
	})

	t.Run("refuses_to_overwrite_existing_key", func(t *testing.T) {
		outDir := t.TempDir()
		if err := runIntermediateIssue(t, "--root-key", rootKey, "--serial", "im-a", "--out", outDir); err != nil {
			t.Fatalf("first issue: %v", err)
		}
		if err := runIntermediateIssue(t, "--root-key", rootKey, "--serial", "im-b", "--out", outDir); err == nil {
			t.Fatal("second issue into the same dir must refuse to clobber the key")
		}
	})

	t.Run("missing_root_key_errors", func(t *testing.T) {
		err := runIntermediateIssue(t,
			"--root-key", filepath.Join(t.TempDir(), "nope.key"), "--serial", "im-x", "--out", t.TempDir())
		if err == nil {
			t.Fatal("missing root key must error")
		}
	})

	t.Run("non_positive_validity_errors", func(t *testing.T) {
		err := runIntermediateIssue(t,
			"--root-key", rootKey, "--serial", "im-zero", "--out", t.TempDir(), "--validity", "0s")
		if err == nil {
			t.Fatal("--validity 0 must be rejected")
		}
	})
}
