//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestWriteDeploymentKeyFile_RejectsInvalidInputs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey other: %v", err)
	}
	corruptPriv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(corruptPriv, priv)
	for i := ed25519.SeedSize; i < ed25519.PrivateKeySize; i++ {
		corruptPriv[i] ^= 0xFF
	}
	dir := t.TempDir()
	const now = "2026-07-12T00:00:00Z"

	for _, tc := range []struct {
		name    string
		purpose signing.KeyPurpose
		keyID   string
		pub     ed25519.PublicKey
		priv    ed25519.PrivateKey
		wantErr string
	}{
		{"invalid purpose", signing.KeyPurpose("bogus-purpose"), "k1", pub, priv, "purpose"},
		{"empty key id", signing.PurposePolicyBundleSigning, "   ", pub, priv, "key id is empty"},
		{"wrong public key length", signing.PurposePolicyBundleSigning, "k1", ed25519.PublicKey{1, 2, 3}, priv, "public key length"},
		{"public key does not match private", signing.PurposePolicyBundleSigning, "k1", otherPub, priv, "does not match public key"},
		{"corrupt private key", signing.PurposePolicyBundleSigning, "k1", pub, corruptPriv, "seed does not derive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "bad-"+tc.name+".json")
			err := writeDeploymentKeyFile(path, tc.purpose, tc.keyID, tc.pub, tc.priv, now)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("writeDeploymentKeyFile err = %v, want error containing %q", err, tc.wantErr)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatalf("expected no key file on validation error, stat err = %v", statErr)
			}
		})
	}

	// The valid path writes a well-formed 0600 keyfile.
	okPath := filepath.Join(dir, "ok.json")
	if err := writeDeploymentKeyFile(okPath, signing.PurposePolicyBundleSigning, "k-ok", pub, priv, now); err != nil {
		t.Fatalf("writeDeploymentKeyFile(valid) = %v, want nil", err)
	}
	info, err := os.Stat(okPath)
	if err != nil {
		t.Fatalf("stat written keyfile: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("keyfile perm = %o, want 600", perm)
	}
}
