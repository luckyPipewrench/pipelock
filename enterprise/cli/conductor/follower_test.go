//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/emergency"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestFollowerResetReplayState_RequiresStateDir(t *testing.T) {
	if err := runFollowerResetReplayState(&cobra.Command{}, followerResetReplayOptions{}); err == nil ||
		!strings.Contains(err.Error(), "--state-dir is required") {
		t.Fatalf("missing --state-dir error = %v, want required", err)
	}
}

func TestFollowerResetReplayState_ErrorPaths(t *testing.T) {
	t.Run("requires state dir before license", func(t *testing.T) {
		t.Setenv(license.EnvLicenseKey, "")
		t.Setenv(license.EnvLicensePublicKey, "")
		t.Setenv(license.EnvLicenseCRLFile, "")

		cmd := followerResetReplayStateCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "--state-dir is required") {
			t.Fatalf("missing --state-dir command error = %v, want required", err)
		}
		if errors.Is(err, license.ErrFleetLicenseRequired) {
			t.Fatalf("missing --state-dir checked license first: %v", err)
		}
	})

	t.Run("confirm surfaces reset error", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "not-a-dir")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("write blocker: %v", err)
		}
		cmd := &cobra.Command{}
		err := runFollowerResetReplayState(cmd, followerResetReplayOptions{stateDir: blocker, confirm: true})
		if err == nil || !strings.Contains(err.Error(), "reset remote-kill replay state") {
			t.Fatalf("confirm reset error = %v, want wrapped reset context", err)
		}
	})
}

func TestFollowerResetReplayState_DryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runFollowerResetReplayState(cmd, followerResetReplayOptions{stateDir: dir, confirm: false}); err != nil {
		t.Fatalf("dry run error = %v", err)
	}
	if !strings.Contains(out.String(), "DRY RUN") {
		t.Fatalf("dry-run output = %q, want DRY RUN notice", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, emergency.RemoteKillStateFileName)); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote a state file (stat err=%v), want none", err)
	}
}

func TestFollowerResetReplayState_ConfirmWritesBaseline(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runFollowerResetReplayState(cmd, followerResetReplayOptions{stateDir: dir, confirm: true}); err != nil {
		t.Fatalf("confirm error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, emergency.RemoteKillStateFileName)); err != nil {
		t.Fatalf("confirm did not write the baseline state file: %v", err)
	}
	if !strings.Contains(out.String(), "reset remote-kill replay state") {
		t.Fatalf("confirm output = %q, want reset confirmation", out.String())
	}
}
