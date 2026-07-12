//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/bootstrap"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type bootstrapKeyFile struct {
	SchemaVersion int    `json:"schema_version"`
	Purpose       string `json:"purpose"`
	KeyID         string `json:"key_id"`
	Public        string `json:"public"`
	Private       string `json:"private"`
	CreatedAt     string `json:"created_at"`
}

func TestBootstrapPolicySigningKeyAppliesAndOffRosterRejects(t *testing.T) {
	dir := privateBootstrapFleetDir(t)
	res, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Dir:         dir,
		OrgID:       "org-1",
		FleetID:     "fleet-1",
		InstanceID:  "instance-1",
		Environment: "prod",
		SkipProof:   true,
		Now:         func() time.Time { return testNow.Add(-time.Minute) },
	})
	if err != nil {
		t.Fatalf("bootstrap Run(SkipProof): %v", err)
	}
	roster, err := signing.LoadRoster(res.Layout.TrustRosterPath, res.RootFingerprint)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}
	resolver := resolverFromLoadedRoster(t, roster)
	policyKey := loadBootstrapPolicyKey(t, res.Layout.PolicySigningKeyPath)

	var reloaded *config.Config
	boundary := Boundary{
		Cache:        openTestCache(t),
		Identity:     testIdentity(),
		Resolver:     resolver,
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload: func(cfg *config.Config) error {
			reloaded = cfg
			return nil
		},
	}
	if _, err := boundary.Apply(signedTestBundle(t, policyKey, "bundle-1", 1, ""), ApplyOptions{}); err != nil {
		t.Fatalf("Apply(on-roster bootstrap policy signer): %v", err)
	}
	if reloaded == nil {
		t.Fatal("on-roster apply did not reload config")
	}

	offRoster := newTestKey(t)
	rejectBoundary := boundary
	rejectBoundary.Cache = openTestCache(t)
	_, err = rejectBoundary.Apply(signedTestBundle(t, offRoster, "bundle-off-roster", 1, ""), ApplyOptions{})
	if !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("Apply(off-roster signer) = %v, want ErrSignatureVerification", err)
	}
	if _, activeErr := rejectBoundary.Cache.Active(); !errors.Is(activeErr, ErrNoValidBundle) {
		t.Fatalf("Active() after rejected off-roster bundle = %v, want ErrNoValidBundle", activeErr)
	}
}

func privateBootstrapFleetDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp(".", ".bootstrap-apply-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	abs, err := filepath.Abs(filepath.Join(base, "fleet"))
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	return abs
}

func loadBootstrapPolicyKey(t *testing.T, path string) testKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read bootstrap policy key: %v", err)
	}
	var kf bootstrapKeyFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kf); err != nil {
		t.Fatalf("decode bootstrap policy key: %v", err)
	}
	if err := dec.Decode(&struct{}{}); err == nil {
		t.Fatal("decode bootstrap policy key: trailing JSON after key object")
	}
	if kf.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", kf.SchemaVersion)
	}
	if kf.Purpose != string(signing.PurposePolicyBundleSigning) {
		t.Fatalf("purpose = %q, want %q", kf.Purpose, signing.PurposePolicyBundleSigning)
	}
	pub, err := hex.DecodeString(kf.Public)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("malformed public key")
	}
	priv, err := hex.DecodeString(kf.Private)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("malformed private key")
	}
	privateKey := ed25519.PrivateKey(priv)
	if err := signing.ValidatePrivateKeyConsistency(privateKey); err != nil {
		t.Fatalf("private key consistency: %v", err)
	}
	derived, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, pub) {
		t.Fatal("private key does not match public key")
	}
	return testKey{
		id:      kf.KeyID,
		purpose: signing.PurposePolicyBundleSigning,
		pub:     ed25519.PublicKey(pub),
		priv:    privateKey,
	}
}

func resolverFromLoadedRoster(t *testing.T, roster *signing.LoadedRoster) conductor.SignatureKeyResolver {
	t.Helper()
	return func(signerKeyID string) (conductor.SignatureKey, error) {
		key, err := roster.ResolveKey(signerKeyID, testNow)
		if err != nil {
			return conductor.SignatureKey{}, fmtSignatureVerification(err)
		}
		pub, err := hex.DecodeString(key.PublicKeyHex)
		if err != nil {
			return conductor.SignatureKey{}, fmtSignatureVerification(err)
		}
		notBefore, err := time.Parse(time.RFC3339, key.ValidFrom)
		if err != nil {
			return conductor.SignatureKey{}, fmtSignatureVerification(err)
		}
		var notAfter time.Time
		if key.ValidUntil != nil {
			notAfter, err = time.Parse(time.RFC3339, *key.ValidUntil)
			if err != nil {
				return conductor.SignatureKey{}, fmtSignatureVerification(err)
			}
		}
		return conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.KeyPurpose(key.KeyPurpose),
			NotBefore:  notBefore,
			NotAfter:   notAfter,
		}, nil
	}
}

func fmtSignatureVerification(err error) error {
	return errors.Join(conductor.ErrSignatureVerification, err)
}
