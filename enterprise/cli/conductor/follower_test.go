//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/emergency"
)

func TestFollowerResetReplayState_RequiresStateDir(t *testing.T) {
	if err := runFollowerResetReplayState(&cobra.Command{}, followerResetReplayOptions{}); err == nil ||
		!strings.Contains(err.Error(), "--state-dir is required") {
		t.Fatalf("missing --state-dir error = %v, want required", err)
	}
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
