//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// killTestRig builds the two-signer keys, the matching server resolver, and a
// live test server, returning a killOptions populated for the happy path.
type killTestRig struct {
	opts killOptions
	srv  *testServer
	now  time.Time
}

func newKillRig(t *testing.T, serverRemoteKillTTL time.Duration) killTestRig {
	t.Helper()
	now := testFixedNow(t)
	id1, f1, pub1 := writeSigningKey(t, "kill-signer-1")
	id2, f2, pub2 := writeSigningKey(t, "kill-signer-2")
	resolver := emergencyResolverFromKeys(map[string]conductorcore.SignatureKey{
		id1: {PublicKey: pub1, KeyPurpose: signing.PurposeRemoteKillSigning},
		id2: {PublicKey: pub2, KeyPurpose: signing.PurposeRemoteKillSigning},
	})
	srv := newTestServer(t, testServerOptions{
		now:           now,
		emergencyKeys: resolver,
		remoteKillTTL: serverRemoteKillTTL,
	})
	opts := killOptions{
		adminTokenFile: writeAdminToken(t, ""),
		signingKeys:    []string{f1, f2},
		orgID:          testOrgID,
		fleetID:        testFleetID,
		instanceIDs:    []string{testInstanceID},
		reason:         "operator emergency stop",
		counter:        100,
		ttl:            remoteKillDefaultTTL,
		now:            func() time.Time { return now },
		transport:      srv,
	}
	opts.baseURL = srv.url
	return killTestRig{opts: opts, srv: srv, now: now}
}

func newCobraForRun(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	out, errBuf := captureCmd()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	return cmd, out
}

func TestRunRemoteKill_KillThenResume(t *testing.T) {
	rig := newKillRig(t, 0)

	cmd, out := newCobraForRun(t)
	if err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive); err != nil {
		t.Fatalf("kill error = %v", err)
	}
	if !strings.Contains(out.String(), "state=active") {
		t.Fatalf("kill output missing state=active: %q", out.String())
	}

	// Resume with a higher counter supersedes the kill.
	resumeOpts := rig.opts
	resumeOpts.counter = 101
	cmd2, out2 := newCobraForRun(t)
	if err := runRemoteKill(cmd2, resumeOpts, conductorcore.KillSwitchInactive); err != nil {
		t.Fatalf("resume error = %v", err)
	}
	if !strings.Contains(out2.String(), "state=inactive") {
		t.Fatalf("resume output missing state=inactive: %q", out2.String())
	}
}

func TestRunRemoteKill_UnderThresholdRejectedAtCLI(t *testing.T) {
	rig := newKillRig(t, 0)
	// Drop to a single signer: must fail BEFORE any network call.
	rig.opts.signingKeys = rig.opts.signingKeys[:1]
	cmd, _ := newCobraForRun(t)
	err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive)
	if err == nil {
		t.Fatal("kill with one signer = nil error, want threshold rejection")
	}
	if !errors.Is(err, conductorcore.ErrThresholdRequired) {
		t.Fatalf("error = %v, want ErrThresholdRequired", err)
	}
}

func TestRunRemoteKill_UnderThresholdRejectedAtServer(t *testing.T) {
	// Two distinct valid signers, but the server's roster does NOT trust the
	// second. signer-2's signature fails verification, so only one distinct
	// VERIFIED signer remains -> below 2-of-N at the server.
	now := testFixedNow(t)
	id1, f1, pub1 := writeSigningKey(t, "kill-signer-1")
	_, f2, _ := writeSigningKey(t, "kill-signer-2")
	resolver := emergencyResolverFromKeys(map[string]conductorcore.SignatureKey{
		id1: {PublicKey: pub1, KeyPurpose: signing.PurposeRemoteKillSigning},
	})
	srv := newTestServer(t, testServerOptions{now: now, emergencyKeys: resolver})
	opts := killOptions{
		adminTokenFile: writeAdminToken(t, ""),
		signingKeys:    []string{f1, f2},
		orgID:          testOrgID, fleetID: testFleetID, instanceIDs: []string{testInstanceID},
		counter: 100, ttl: remoteKillDefaultTTL,
		now: func() time.Time { return now }, transport: srv,
	}
	opts.baseURL = srv.url
	cmd, _ := newCobraForRun(t)
	err := runRemoteKill(cmd, opts, conductorcore.KillSwitchActive)
	if err == nil {
		t.Fatal("kill with one untrusted signer = nil error, want server rejection")
	}
	if !strings.Contains(err.Error(), "conductor rejected request") {
		t.Fatalf("error = %v, want server rejection", err)
	}
}

func TestRunRemoteKill_SameKeyFileTwiceRejectedAtCLI(t *testing.T) {
	// Adversarial: an operator supplies the SAME keyfile twice to fake a second
	// signer. Both keyfiles declare the same embedded key_id, so the CLI's
	// duplicate-key_id guard rejects it BEFORE any network call. (The server's
	// distinct-public-key threshold check is the defense-in-depth backstop, but
	// failing fast here gives the operator a clearer message.)
	now := testFixedNow(t)
	_, f1, pub1 := writeSigningKey(t, "real-signer")
	resolver := emergencyResolverFromKeys(map[string]conductorcore.SignatureKey{
		"real-signer": {PublicKey: pub1, KeyPurpose: signing.PurposeRemoteKillSigning},
	})
	srv := newTestServer(t, testServerOptions{now: now, emergencyKeys: resolver})
	opts := killOptions{
		adminTokenFile: writeAdminToken(t, ""),
		signingKeys:    []string{f1, f1},
		orgID:          testOrgID, fleetID: testFleetID, instanceIDs: []string{testInstanceID},
		counter: 100, ttl: remoteKillDefaultTTL,
		now: func() time.Time { return now }, transport: srv,
	}
	opts.baseURL = srv.url
	cmd, _ := newCobraForRun(t)
	err := runRemoteKill(cmd, opts, conductorcore.KillSwitchActive)
	if err == nil {
		t.Fatal("same keyfile twice = nil error, want CLI duplicate-key rejection")
	}
	if !errors.Is(err, errControlKeyDuplicateKey) {
		t.Fatalf("error = %v, want errControlKeyDuplicateKey", err)
	}
}

func TestRunRemoteKill_WrongPurposeKeyRejectedByServer(t *testing.T) {
	// Adversarial: signatures are produced with the rollback purpose embedded
	// (forced here via a server that trusts the keys only under the rollback
	// purpose). The remote-kill command always stamps the remote-kill purpose
	// in the proof, and the server requires that purpose, so a key the roster
	// holds under a DIFFERENT purpose fails verification.
	now := testFixedNow(t)
	id1, f1, pub1 := writeSigningKey(t, "k1")
	id2, f2, pub2 := writeSigningKey(t, "k2")
	// Roster holds these keys under the ROLLBACK purpose, not remote-kill.
	resolver := emergencyResolverFromKeys(map[string]conductorcore.SignatureKey{
		id1: {PublicKey: pub1, KeyPurpose: signing.PurposePolicyBundleRollback},
		id2: {PublicKey: pub2, KeyPurpose: signing.PurposePolicyBundleRollback},
	})
	srv := newTestServer(t, testServerOptions{now: now, emergencyKeys: resolver})
	opts := killOptions{
		adminTokenFile: writeAdminToken(t, ""),
		signingKeys:    []string{f1, f2},
		orgID:          testOrgID, fleetID: testFleetID, instanceIDs: []string{testInstanceID},
		counter: 100, ttl: remoteKillDefaultTTL,
		now: func() time.Time { return now }, transport: srv,
	}
	opts.baseURL = srv.url
	cmd, _ := newCobraForRun(t)
	err := runRemoteKill(cmd, opts, conductorcore.KillSwitchActive)
	if err == nil {
		t.Fatal("wrong-purpose roster key = nil error, want server rejection")
	}
	if !strings.Contains(err.Error(), "conductor rejected request") {
		t.Fatalf("error = %v, want server purpose rejection", err)
	}
}

func TestRunRemoteKill_WrongPurposeKeyfileRejectedAtCLI(t *testing.T) {
	// A rollback-purpose keyfile handed to `kill` is rejected locally: the CLI
	// binds the action's required purpose and refuses a mismatched keyfile
	// before signing or any network call.
	rig := newKillRig(t, 0)
	_, fr1, _ := writeSigningKeyWithPurpose(t, "rb-1", signing.PurposePolicyBundleRollback)
	_, fr2, _ := writeSigningKeyWithPurpose(t, "rb-2", signing.PurposePolicyBundleRollback)
	rig.opts.signingKeys = []string{fr1, fr2}
	cmd, _ := newCobraForRun(t)
	err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive)
	if err == nil || !errors.Is(err, errSigningKeyPurposeMismatch) {
		t.Fatalf("error = %v, want errSigningKeyPurposeMismatch", err)
	}
}

func TestRunRemoteKill_TTLExceedsServerMaxRejected(t *testing.T) {
	// Server caps remote-kill validity at 30m; CLI requests a 2h window.
	rig := newKillRig(t, 30*time.Minute)
	rig.opts.ttl = 2 * time.Hour
	cmd, _ := newCobraForRun(t)
	err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive)
	if err == nil {
		t.Fatal("kill with over-max TTL = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "conductor rejected request") {
		t.Fatalf("error = %v, want server TTL rejection", err)
	}
}

func TestRunRemoteKill_StaleCounterRejected(t *testing.T) {
	rig := newKillRig(t, 0)
	cmd, _ := newCobraForRun(t)
	if err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive); err != nil {
		t.Fatalf("first kill error = %v", err)
	}
	// Replay with the SAME counter (not higher) -> stale, server rejects.
	cmd2, _ := newCobraForRun(t)
	replay := rig.opts
	replay.messageID = "remote-kill-replay"
	err := runRemoteKill(cmd2, replay, conductorcore.KillSwitchInactive)
	if err == nil {
		t.Fatal("replay with stale counter = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "conductor rejected request") {
		t.Fatalf("error = %v, want stale-counter rejection", err)
	}
}

func TestRunRemoteKill_BadAdminTokenRejected(t *testing.T) {
	rig := newKillRig(t, 0)
	rig.opts.adminTokenFile = writeAdminToken(t, "wrong-token")
	cmd, _ := newCobraForRun(t)
	err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive)
	if err == nil {
		t.Fatal("kill with bad admin token = nil error, want 403")
	}
	if !strings.Contains(err.Error(), "status=403") {
		t.Fatalf("error = %v, want status=403", err)
	}
}

func TestRunRemoteKill_DefaultCounterFromClock(t *testing.T) {
	rig := newKillRig(t, 0)
	rig.opts.counter = 0 // exercise the clock-derived default
	rig.opts.messageID = ""
	cmd, out := newCobraForRun(t)
	if err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive); err != nil {
		t.Fatalf("kill error = %v", err)
	}
	wantCounter := rig.now.Unix()
	if !strings.Contains(out.String(), "counter="+strconv.FormatInt(wantCounter, 10)) {
		t.Fatalf("output %q missing clock-derived counter %d", out.String(), wantCounter)
	}
}

func TestKillCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"kill", "--conductor-url", "https://x", "--org", "o", "--fleet", "f"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("kill without license error = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestResumeCmd_RegisteredAndLicenseGated(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"resume", "--conductor-url", "https://x", "--org", "o", "--fleet", "f"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("resume without license error = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestRunRemoteKill_InvalidAudienceRejected(t *testing.T) {
	rig := newKillRig(t, 0)
	rig.opts.instanceIDs = nil
	rig.opts.labels = nil // empty audience
	cmd, _ := newCobraForRun(t)
	if err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive); err == nil {
		t.Fatal("kill empty audience = nil error, want audience error")
	}
}

func TestRunRemoteKill_MissingAdminTokenFileRejected(t *testing.T) {
	rig := newKillRig(t, 0)
	rig.opts.adminTokenFile = ""
	cmd, _ := newCobraForRun(t)
	if err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive); err == nil {
		t.Fatal("kill missing admin token file = nil error, want required error")
	}
}

func TestRunRemoteKill_BadSigningKeyFileRejected(t *testing.T) {
	rig := newKillRig(t, 0)
	rig.opts.signingKeys = []string{"/no/such.json", "/no/such2.json"}
	cmd, _ := newCobraForRun(t)
	if err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive); err == nil {
		t.Fatal("kill bad signing key = nil error, want load error")
	}
}

func TestRunRemoteKill_ProductionTransportTLSErrorSurfaces(t *testing.T) {
	// transport=nil forces the production mTLS client build; with no TLS flags
	// it must fail closed BEFORE any request.
	rig := newKillRig(t, 0)
	rig.opts.transport = nil
	cmd, _ := newCobraForRun(t)
	err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive)
	if err == nil || !strings.Contains(err.Error(), "--tls-cert is required") {
		t.Fatalf("error = %v, want TLS-cert-required", err)
	}
}

func TestKillCmd_FlagWiringBuildsValidMessage(t *testing.T) {
	// Confirm the command's flag set populates options that produce an accepted
	// message when the license gate is satisfied and a transport is injected.
	installFleetLicense(t)
	rig := newKillRig(t, 0)
	if err := runRemoteKill(rig.cobraCmd(t), rig.opts, conductorcore.KillSwitchActive); err != nil {
		t.Fatalf("licensed kill error = %v", err)
	}
}

// cobraCmd returns a throwaway cobra command carrying a context and buffers for
// run-function tests.
func (r killTestRig) cobraCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd
}
