//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func enrollCobra(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	return cmd, out
}

func TestRunEnroll_HappyPath(t *testing.T) {
	mintOpts := newEnrollmentRig(t)
	mintCmd, tokenOut, _ := enrollmentCobra(t)
	if err := runEnrollmentTokenMint(mintCmd, mintOpts); err != nil {
		t.Fatalf("mint enrollment token: %v", err)
	}
	_, auditKeyFile, _ := writeSigningKeyWithPurpose(t, "audit-key-1", signing.PurposeAuditBatchSigning)
	opts := enrollOptions{
		emergencyClientOptions: emergencyClientOptions{baseURL: mintOpts.baseURL},
		enrollmentTokenFile:    writeEnrollmentTokenFile(t, tokenOut.String()),
		auditKeyFile:           auditKeyFile,
		transport:              mintOpts.transport,
	}
	cmd, out := enrollCobra(t)
	if err := runEnroll(cmd, opts); err != nil {
		t.Fatalf("runEnroll() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"follower enrolled", "org=org-main", "fleet=prod", "instance=pl-prod-1", "audit_key_id=audit-key-1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("enroll output %q missing %q", got, want)
		}
	}
}

func TestRunEnroll_BadTokenRejected(t *testing.T) {
	mintOpts := newEnrollmentRig(t)
	_, auditKeyFile, _ := writeSigningKeyWithPurpose(t, "audit-key-1", signing.PurposeAuditBatchSigning)
	opts := enrollOptions{
		emergencyClientOptions: emergencyClientOptions{baseURL: mintOpts.baseURL},
		enrollmentTokenFile:    writeEnrollmentTokenFile(t, "pl_enroll_bad"),
		auditKeyFile:           auditKeyFile,
		transport:              mintOpts.transport,
	}
	cmd, _ := enrollCobra(t)
	err := runEnroll(cmd, opts)
	if err == nil {
		t.Fatal("runEnroll(bad token) error = nil, want 401")
	}
	if !strings.Contains(err.Error(), "status=401") {
		t.Fatalf("runEnroll(bad token) error = %v, want status=401", err)
	}
}

func TestRunEnrollRejectsPlainHTTPConductorURL(t *testing.T) {
	mintOpts := newEnrollmentRig(t)
	_, auditKeyFile, _ := writeSigningKeyWithPurpose(t, "audit-key-1", signing.PurposeAuditBatchSigning)
	opts := enrollOptions{
		emergencyClientOptions: emergencyClientOptions{baseURL: "http://conductor.example:8895"},
		enrollmentTokenFile:    writeEnrollmentTokenFile(t, "pl_enroll_test"),
		auditKeyFile:           auditKeyFile,
		transport:              mintOpts.transport,
	}
	cmd, _ := enrollCobra(t)
	err := runEnroll(cmd, opts)
	if err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Fatalf("runEnroll(http) error = %v, want https rejection", err)
	}
}

func TestEnrollCmd_Registered(t *testing.T) {
	cmd := Cmd()
	for _, child := range cmd.Commands() {
		if child.Name() == "enroll" {
			return
		}
	}
	t.Fatal("enroll command not registered")
}

func writeEnrollmentTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enrollment-token")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(token)+"\n"), 0o600); err != nil {
		t.Fatalf("write enrollment token file: %v", err)
	}
	return path
}
