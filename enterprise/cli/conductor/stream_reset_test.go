//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestRunStreamReset_MissingConfirmRejected(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runStreamReset(cmd, streamResetOptions{
		orgID:   "test-org",
		confirm: false,
	})
	if err == nil || !strings.Contains(err.Error(), "--confirm is required") {
		t.Fatalf("missing confirm error = %v, want --confirm required", err)
	}
}

func TestRunStreamReset_MissingOrgIDRejected(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runStreamReset(cmd, streamResetOptions{
		orgID:   "",
		confirm: true,
	})
	if err == nil || !strings.Contains(err.Error(), "--org-id is required") {
		t.Fatalf("missing org-id error = %v, want --org-id required", err)
	}
}

func TestStreamResetCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"stream", "reset", "--org-id", "test-org", "--confirm"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("stream reset without license error = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestRollbackAuthorizationsForReset_EmergencyControlsUnreadable(t *testing.T) {
	_, err := rollbackAuthorizationsForReset(streamStatusResponse{
		EmergencyControlsRead: false,
	})
	if err == nil || !strings.Contains(err.Error(), "emergency controls were not readable") {
		t.Fatalf("error = %v, want unreadable emergency controls refusal", err)
	}
}

func TestRollbackAuthorizationsForReset_ReturnsActiveRollbacks(t *testing.T) {
	want := []controlplane.ActiveRollbackAuthorization{{AuthorizationID: "rollback-1"}}
	got, err := rollbackAuthorizationsForReset(streamStatusResponse{
		EmergencyControlsRead: true,
		ActiveRollbacks:       want,
	})
	if err != nil {
		t.Fatalf("rollbackAuthorizationsForReset: %v", err)
	}
	if len(got) != 1 || got[0].AuthorizationID != "rollback-1" {
		t.Fatalf("got = %+v, want rollback-1", got)
	}
}
