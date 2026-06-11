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

	"github.com/luckyPipewrench/pipelock/internal/license"
)

func newEnrollmentRig(t *testing.T) enrollmentTokenOptions {
	t.Helper()
	now := testFixedNow(t)
	// Enrollment-token mint does not sign with control keys; emergencyKeys can
	// be nil for this server (the endpoint gates on admin auth only).
	srv := newTestServer(t, testServerOptions{now: now})
	opts := enrollmentTokenOptions{
		adminTokenFile: writeAdminToken(t, ""),
		tokenID:        "enroll-token-1",
		orgID:          testOrgID,
		fleetID:        testFleetID,
		instanceID:     testInstanceID,
		environment:    testEnvironment,
		ttl:            enrollmentTokenDefaultTTL,
		now:            func() time.Time { return now },
		transport:      srv,
	}
	opts.baseURL = srv.url
	return opts
}

func enrollmentCobra(t *testing.T) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	out, errBuf := &bytes.Buffer{}, &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	return cmd, out, errBuf
}

func TestRunEnrollmentTokenMint_HappyPath(t *testing.T) {
	opts := newEnrollmentRig(t)
	cmd, out, errBuf := enrollmentCobra(t)
	if err := runEnrollmentTokenMint(cmd, opts); err != nil {
		t.Fatalf("mint error = %v", err)
	}
	// The token (credential) goes to stdout; the summary to stderr.
	token := strings.TrimSpace(out.String())
	if !strings.HasPrefix(token, "pl_enroll_") {
		t.Fatalf("stdout token = %q, want pl_enroll_ prefix", token)
	}
	if !strings.Contains(errBuf.String(), "token_id=enroll-token-1") {
		t.Fatalf("stderr summary missing token_id: %q", errBuf.String())
	}
}

func TestRunEnrollmentTokenMint_BadAdminTokenRejected(t *testing.T) {
	opts := newEnrollmentRig(t)
	opts.adminTokenFile = writeAdminToken(t, "wrong-token")
	cmd, _, _ := enrollmentCobra(t)
	err := runEnrollmentTokenMint(cmd, opts)
	if err == nil {
		t.Fatal("mint bad token = nil error, want 403")
	}
	if !strings.Contains(err.Error(), "status=403") {
		t.Fatalf("error = %v, want status=403", err)
	}
}

func TestRunEnrollmentTokenMint_NonPositiveTTLRejected(t *testing.T) {
	opts := newEnrollmentRig(t)
	opts.ttl = 0
	cmd, _, _ := enrollmentCobra(t)
	if err := runEnrollmentTokenMint(cmd, opts); err == nil {
		t.Fatal("mint ttl=0 = nil error, want positive-ttl error")
	}
}

func TestRunEnrollmentTokenMint_DuplicateTokenIDRejected(t *testing.T) {
	opts := newEnrollmentRig(t)
	cmd, _, _ := enrollmentCobra(t)
	if err := runEnrollmentTokenMint(cmd, opts); err != nil {
		t.Fatalf("first mint error = %v", err)
	}
	// Same token_id again -> server conflict.
	cmd2, _, _ := enrollmentCobra(t)
	err := runEnrollmentTokenMint(cmd2, opts)
	if err == nil {
		t.Fatal("duplicate token_id = nil error, want conflict")
	}
	if !strings.Contains(err.Error(), "status=409") {
		t.Fatalf("error = %v, want status=409 conflict", err)
	}
}

func TestRunEnrollmentTokenMint_ExpiredWindowRejected(t *testing.T) {
	// Drive the server's clock past the requested expiry: the CLI computes
	// expires_at from its (earlier) clock, the server validates the window
	// against its (later) clock and rejects the already-expired token. This is
	// the operator-visible failure for a token requested with too short a TTL
	// for the round-trip, or a badly skewed operator clock.
	now := testFixedNow(t)
	serverNow := now.Add(time.Hour)
	srv := newTestServer(t, testServerOptions{now: serverNow})
	opts := enrollmentTokenOptions{
		adminTokenFile: writeAdminToken(t, ""),
		tokenID:        "enroll-expired",
		orgID:          testOrgID, fleetID: testFleetID, instanceID: testInstanceID, environment: testEnvironment,
		ttl: time.Minute, // expires_at = now+1m, which is < serverNow
		now: func() time.Time { return now }, transport: srv,
	}
	opts.baseURL = srv.url
	cmd, _, _ := enrollmentCobra(t)
	err := runEnrollmentTokenMint(cmd, opts)
	if err == nil {
		t.Fatal("mint with already-expired window = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "conductor rejected request") {
		t.Fatalf("error = %v, want server rejection", err)
	}
}

func TestRunEnrollmentTokenMint_MissingAdminTokenFileRejected(t *testing.T) {
	opts := newEnrollmentRig(t)
	opts.adminTokenFile = ""
	cmd, _, _ := enrollmentCobra(t)
	if err := runEnrollmentTokenMint(cmd, opts); err == nil {
		t.Fatal("mint missing admin token file = nil error, want required error")
	}
}

func TestRunEnrollmentTokenMint_ProductionTransportTLSErrorSurfaces(t *testing.T) {
	opts := newEnrollmentRig(t)
	opts.transport = nil
	cmd, _, _ := enrollmentCobra(t)
	err := runEnrollmentTokenMint(cmd, opts)
	if err == nil || !strings.Contains(err.Error(), "--tls-cert is required") {
		t.Fatalf("error = %v, want TLS-cert-required", err)
	}
}

func TestEnrollmentTokenCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{
		"enrollment-token", "mint", "--conductor-url", "https://x",
		"--token-id", "t", "--org", "o", "--fleet", "f", "--instance", "i", "--env", "e",
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("mint without license error = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestEnrollmentTokenCmd_Registered(t *testing.T) {
	cmd := Cmd()
	var found bool
	for _, c := range cmd.Commands() {
		if c.Name() == "enrollment-token" {
			found = true
			// mint subcommand present?
			var hasMint bool
			for _, sc := range c.Commands() {
				if sc.Name() == "mint" {
					hasMint = true
				}
			}
			if !hasMint {
				t.Fatal("enrollment-token missing mint subcommand")
			}
		}
	}
	if !found {
		t.Fatal("enrollment-token command not registered")
	}
}
