//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// seedCleanStore publishes one wildcard-audience bundle into a real policy-bundle
// store under <storageDir>/policy-bundles, exercising the same on-disk layout the
// offline commands read. It returns the storage dir to pass via --storage-dir.
func seedCleanStore(t *testing.T) string {
	t.Helper()
	storageDir := t.TempDir()
	pb := filepath.Join(storageDir, "policy-bundles")
	store, err := controlplane.OpenFileBundleStore(pb)
	if err != nil {
		t.Fatalf("OpenFileBundleStore: %v", err)
	}
	bundle := offlineTestBundle(t)
	if _, _, err := store.Publish(t.Context(), bundle, controlplane.PublishOptions{Now: time.Now().UTC()}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return storageDir
}

// offlineTestBundle builds a minimal valid, signed policy bundle.
func offlineTestBundle(t *testing.T) conductorcore.PolicyBundle {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	payload := conductorcore.PolicyBundlePayload{ConfigYAML: "mode: strict\napi_allowlist:\n  - api.example.com\n"}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		t.Fatalf("PayloadHash: %v", err)
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash: %v", err)
	}
	bundle := conductorcore.PolicyBundle{
		SchemaVersion:      conductorcore.SchemaVersion,
		BundleID:           "bundle-offline-cli",
		OrgID:              "org-cli",
		FleetID:            "prod",
		Environment:        "prod",
		Audience:           conductorcore.Audience{InstanceIDs: []string{"*"}},
		Version:            1,
		CreatedAt:          now.Add(-time.Minute),
		NotBefore:          now.Add(-time.Minute),
		ExpiresAt:          now.Add(2 * time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	bundle.Signatures = []conductorcore.SignatureProof{{
		SignerKeyID: "policy-key-1",
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductorcore.SignatureAlgorithmEd25519,
		Signature:   conductorcore.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(priv, preimage)),
	}}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle Validate: %v", err)
	}
	return bundle
}

func TestStoreInspectOfflineCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"store", "inspect-offline", "--storage-dir", t.TempDir()})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("inspect-offline without fleet license: err = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestStoreRepairOfflineCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"store", "repair", "--storage-dir", t.TempDir(), "--confirm"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("repair without fleet license: err = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestRunStoreInspectOffline_MissingStorageDir(t *testing.T) {
	err := runStoreInspectOffline(newCapturingCmd(), storeOfflineOptions{})
	if err == nil || !strings.Contains(err.Error(), "--storage-dir is required") {
		t.Fatalf("missing storage-dir error = %v, want --storage-dir required", err)
	}
}

func TestStoreInspectOfflineCmd_CleanStoreReportsNoOrphans(t *testing.T) {
	setFleetLicenseEnv(t)
	storageDir := seedCleanStore(t)
	var out bytes.Buffer
	cmd := Cmd()
	cmd.SetArgs([]string{"store", "inspect-offline", "--storage-dir", storageDir})
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("inspect-offline: %v", err)
	}
	got := out.String()
	for _, want := range []string{"streams: 1", "orphaned records: none"} {
		if !strings.Contains(got, want) {
			t.Errorf("inspect-offline output missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestStoreRepairOfflineCmd_CleanStoreDryRunNoOp(t *testing.T) {
	setFleetLicenseEnv(t)
	storageDir := seedCleanStore(t)
	var out bytes.Buffer
	cmd := Cmd()
	// No --confirm: dry run.
	cmd.SetArgs([]string{"store", "repair", "--storage-dir", storageDir})
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("repair dry run: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "dry run: no removable orphaned records found") {
		t.Errorf("repair dry-run output = %q, want clean dry-run message", got)
	}
}

func newCapturingCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd
}
