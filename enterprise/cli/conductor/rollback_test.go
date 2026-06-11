//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

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
		instanceIDs:     []string{testInstanceID},
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
	return opts
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

func TestRunRollback_InvalidAudienceRejected(t *testing.T) {
	opts := newRollbackRig(t, 0)
	opts.instanceIDs = nil
	opts.labels = nil
	cmd, _ := rollbackCobra(t)
	if err := runRollback(cmd, opts); err == nil {
		t.Fatal("rollback empty audience = nil error, want audience error")
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
