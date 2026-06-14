//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestWriteKillStatusTable_NoKills(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	resp := streamStatusResponse{
		EmergencyControlsRead: true,
	}
	if err := writeKillStatusTable(cmd, resp); err != nil {
		t.Fatalf("writeKillStatusTable: %v", err)
	}
	if got := out.String(); got != "no active remote kills\n" {
		t.Fatalf("output = %q, want 'no active remote kills'", got)
	}
}

func TestWriteKillStatusTable_WithKills(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	resp := streamStatusResponse{
		EmergencyControlsRead: true,
		ActiveRemoteKills: []controlplane.ActiveRemoteKill{
			{
				MessageID: "kill-1",
				FleetID:   "prod",
				State:     "active",
				Counter:   1,
				ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
				Reason:    "emergency",
			},
		},
	}
	if err := writeKillStatusTable(cmd, resp); err != nil {
		t.Fatalf("writeKillStatusTable: %v", err)
	}
	got := out.String()
	if !bytes.Contains([]byte(got), []byte("kill-1")) {
		t.Fatalf("output missing kill-1: %q", got)
	}
	if !bytes.Contains([]byte(got), []byte("1 active remote kill(s)")) {
		t.Fatalf("output missing count: %q", got)
	}
}

func TestWriteKillStatusTable_EmergencyControlsNotAvailable(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	resp := streamStatusResponse{
		EmergencyControlsRead: false,
	}
	if err := writeKillStatusTable(cmd, resp); err != nil {
		t.Fatalf("writeKillStatusTable: %v", err)
	}
	got := out.String()
	if !bytes.Contains([]byte(got), []byte("NOT AVAILABLE")) {
		t.Fatalf("output missing NOT AVAILABLE warning: %q", got)
	}
}

func TestRunKillStatus_MissingOrgIDRejected(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	err := runKillStatus(cmd, killStatusOptions{orgID: ""})
	if err == nil || err.Error() != "--org-id is required" {
		t.Fatalf("error = %v, want --org-id required", err)
	}
}

func TestKillStatusCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"kill", "status", "--org-id", "test-org"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("kill status without license error = %v, want ErrFleetLicenseRequired", err)
	}
}
