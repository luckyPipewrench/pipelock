//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const rollbackTestPolicyKeyID = "policy-signer-1"

func newRollbackRig(t *testing.T, serverRollbackTTL time.Duration) rollbackOptions {
	t.Helper()
	now := testFixedNow(t)
	id1, f1, pub1 := writeSigningKeyWithPurpose(t, "rollback-signer-1", signing.PurposePolicyBundleRollback)
	id2, f2, pub2 := writeSigningKeyWithPurpose(t, "rollback-signer-2", signing.PurposePolicyBundleRollback)
	resolver := emergencyResolverFromKeys(map[string]conductorcore.SignatureKey{
		id1: {PublicKey: pub1, KeyPurpose: signing.PurposePolicyBundleRollback},
		id2: {PublicKey: pub2, KeyPurpose: signing.PurposePolicyBundleRollback},
	})
	srv := newTestServer(t, testServerOptions{
		now:           now,
		emergencyKeys: resolver,
		rollbackTTL:   serverRollbackTTL,
	})
	opts := rollbackOptions{
		adminTokenFile:  writeAdminToken(t, ""),
		signingKeys:     []string{f1, f2},
		orgID:           testOrgID,
		fleetID:         testFleetID,
		currentBundleID: "bundle-current",
		currentVersion:  42,
		targetBundleID:  "bundle-target",
		targetVersion:   41,
		counter:         100,
		reason:          "bad policy bundle",
		ttl:             rollbackDefaultTTL,
		now:             func() time.Time { return now },
		transport:       srv,
	}
	opts.baseURL = srv.url
	seedRollbackBundles(t, srv.store, opts)
	return opts
}

func seedRollbackBundles(t *testing.T, store *controlplane.FileBundleStore, opts rollbackOptions) {
	t.Helper()
	target := signedRollbackTestBundle(t, opts.targetBundleID, opts.targetVersion, "")
	targetRecord, _, err := store.Publish(context.Background(), target, controlplane.PublishOptions{Now: opts.now()})
	if err != nil {
		t.Fatalf("Publish(rollback target): %v", err)
	}
	current := signedRollbackTestBundle(t, opts.currentBundleID, opts.currentVersion, targetRecord.BundleHash)
	if _, _, err := store.Publish(context.Background(), current, controlplane.PublishOptions{Now: opts.now().Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(rollback current): %v", err)
	}
}

func signedRollbackTestBundle(t *testing.T, bundleID string, version uint64, previousHash string) conductorcore.PolicyBundle {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(policy bundle): %v", err)
	}
	payload := conductorcore.PolicyBundlePayload{ConfigYAML: "mode: strict\napi_allowlist:\n  - api.example.com\n"}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		t.Fatalf("PayloadHash(): %v", err)
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(): %v", err)
	}
	bundle := conductorcore.PolicyBundle{
		SchemaVersion:      conductorcore.SchemaVersion,
		BundleID:           bundleID,
		OrgID:              testOrgID,
		FleetID:            testFleetID,
		Environment:        testEnvironment,
		Audience:           conductorcore.Audience{InstanceIDs: []string{testInstanceID}},
		Version:            version,
		PreviousBundleHash: previousHash,
		CreatedAt:          testFixedNow(t).Add(-time.Minute),
		NotBefore:          testFixedNow(t).Add(-time.Minute),
		ExpiresAt:          testFixedNow(t).Add(time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(): %v", err)
	}
	bundle.Signatures = []conductorcore.SignatureProof{{
		SignerKeyID: rollbackTestPolicyKeyID,
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductorcore.SignatureAlgorithmEd25519,
		Signature:   conductorcore.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(priv, preimage)),
	}}
	if err := bundle.VerifySignaturesAt(testFixedNow(t), func(keyID string) (conductorcore.SignatureKey, error) {
		if keyID != rollbackTestPolicyKeyID {
			return conductorcore.SignatureKey{}, conductorcore.ErrSignatureVerification
		}
		return conductorcore.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposePolicyBundleSigning,
			NotBefore:  testFixedNow(t).Add(-time.Hour),
			NotAfter:   testFixedNow(t).Add(time.Hour),
		}, nil
	}); err != nil {
		t.Fatalf("VerifySignaturesAt(): %v", err)
	}
	return bundle
}

func rollbackCobra(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	return cmd, out
}

func TestRunRollback_HappyPath(t *testing.T) {
	opts := newRollbackRig(t, 0)
	cmd, out := rollbackCobra(t)
	if err := runRollback(cmd, opts); err != nil {
		t.Fatalf("rollback error = %v", err)
	}
	if !strings.Contains(out.String(), "target_version=41") {
		t.Fatalf("output missing target_version: %q", out.String())
	}
}

func TestRunRollback_TargetNotBelowCurrentRejectedAtCLI(t *testing.T) {
	opts := newRollbackRig(t, 0)
	opts.targetVersion = 42 // == current, invalid
	cmd, _ := rollbackCobra(t)
	err := runRollback(cmd, opts)
	if err == nil {
		t.Fatal("rollback target==current = nil error, want local validation error")
	}
	if !errors.Is(err, conductorcore.ErrInvalidRollback) {
		t.Fatalf("error = %v, want ErrInvalidRollback", err)
	}
}

func TestRunRollback_UnderThresholdRejectedAtCLI(t *testing.T) {
	opts := newRollbackRig(t, 0)
	opts.signingKeys = opts.signingKeys[:1]
	cmd, _ := rollbackCobra(t)
	err := runRollback(cmd, opts)
	if err == nil {
		t.Fatal("rollback one signer = nil error, want threshold rejection")
	}
	if !errors.Is(err, conductorcore.ErrThresholdRequired) {
		t.Fatalf("error = %v, want ErrThresholdRequired", err)
	}
}

func TestRunRollback_TTLExceedsServerMaxRejected(t *testing.T) {
	opts := newRollbackRig(t, 15*time.Minute)
	opts.ttl = 2 * time.Hour
	cmd, _ := rollbackCobra(t)
	err := runRollback(cmd, opts)
	if err == nil {
		t.Fatal("rollback over-max TTL = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "conductor rejected request") {
		t.Fatalf("error = %v, want server TTL rejection", err)
	}
}

func TestRunRollback_StaleCounterRejected(t *testing.T) {
	opts := newRollbackRig(t, 0)
	cmd, _ := rollbackCobra(t)
	if err := runRollback(cmd, opts); err != nil {
		t.Fatalf("first rollback error = %v", err)
	}
	replay := opts
	replay.authorizationID = "rollback-replay"
	cmd2, _ := rollbackCobra(t)
	err := runRollback(cmd2, replay)
	if err == nil {
		t.Fatal("rollback stale counter = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "conductor rejected request") {
		t.Fatalf("error = %v, want stale-counter rejection", err)
	}
}

func TestRunRollback_BadAdminTokenRejected(t *testing.T) {
	opts := newRollbackRig(t, 0)
	opts.adminTokenFile = writeAdminToken(t, "wrong-token")
	cmd, _ := rollbackCobra(t)
	err := runRollback(cmd, opts)
	if err == nil {
		t.Fatal("rollback bad token = nil error, want 403")
	}
	if !strings.Contains(err.Error(), "status=403") {
		t.Fatalf("error = %v, want status=403", err)
	}
}

func TestRunRollback_ScopedAudienceRejected(t *testing.T) {
	opts := newRollbackRig(t, 0)
	opts.instanceIDs = []string{testInstanceID}
	cmd, _ := rollbackCobra(t)
	err := runRollback(cmd, opts)
	if err == nil || !strings.Contains(err.Error(), "stream-wide") {
		t.Fatalf("rollback scoped audience error = %v, want stream-wide rejection", err)
	}
}

func TestRunRollback_MissingAdminTokenFileRejected(t *testing.T) {
	opts := newRollbackRig(t, 0)
	opts.adminTokenFile = ""
	cmd, _ := rollbackCobra(t)
	if err := runRollback(cmd, opts); err == nil {
		t.Fatal("rollback missing admin token file = nil error, want required error")
	}
}

func TestRunRollback_ProductionTransportTLSErrorSurfaces(t *testing.T) {
	opts := newRollbackRig(t, 0)
	opts.transport = nil
	cmd, _ := rollbackCobra(t)
	err := runRollback(cmd, opts)
	if err == nil || !strings.Contains(err.Error(), "--tls-cert is required") {
		t.Fatalf("error = %v, want TLS-cert-required", err)
	}
}

func TestRollbackCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{
		"rollback", "--conductor-url", "https://x", "--org", "o", "--fleet", "f",
		"--current-bundle-id", "a", "--target-bundle-id", "b",
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("rollback without license error = %v, want ErrFleetLicenseRequired", err)
	}
}
