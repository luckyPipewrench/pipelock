//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/emergency"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestFollowerRemoveSendsDeleteAndRendersSummary(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll(request): %v", err)
		}
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"org_id":"org-main","fleet_id":"prod","instance_id":"pl-prod-1","environment":"prod","audit_key_id":"audit-key-1","enrolled_at":"2026-06-22T12:00:00Z","active":false}`))
	})
	client := newTestClientServer(t, "admin-token", handler)
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := runFollowerRemove(cmd, followerRemoveOptions{
		client:      client,
		orgID:       "org-main",
		fleetID:     "prod",
		instanceID:  "pl-prod-1",
		environment: "prod",
	})
	if err != nil {
		t.Fatalf("runFollowerRemove() error = %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method = %s, want DELETE", gotMethod)
	}
	if gotPath != "/api/v1/conductor/followers" {
		t.Fatalf("path = %s, want followers endpoint", gotPath)
	}
	for _, want := range []string{`"org_id":"org-main"`, `"fleet_id":"prod"`, `"instance_id":"pl-prod-1"`, `"environment":"prod"`} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("body = %s, missing %s", gotBody, want)
		}
	}
	if !strings.Contains(out.String(), "removed follower org=org-main fleet=prod instance=pl-prod-1 environment=prod audit_key_id=audit-key-1") {
		t.Fatalf("output = %q, want remove summary", out.String())
	}
}

func TestFollowerRemoveValidatesExactIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts followerRemoveOptions
		want string
	}{
		{name: "missing org", opts: followerRemoveOptions{fleetID: "prod", instanceID: "i-1", environment: "prod"}, want: "--org-id is required"},
		{name: "missing fleet", opts: followerRemoveOptions{orgID: "org-main", instanceID: "i-1", environment: "prod"}, want: "--fleet-id is required"},
		{name: "missing instance", opts: followerRemoveOptions{orgID: "org-main", fleetID: "prod", environment: "prod"}, want: "--instance-id is required"},
		{name: "missing environment", opts: followerRemoveOptions{orgID: "org-main", fleetID: "prod", instanceID: "i-1"}, want: "--environment is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runFollowerRemove(&cobra.Command{}, tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runFollowerRemove() error = %v, want %q", err, tc.want)
			}
		})
	}
}

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

func TestFollowerResetBundleState_RequiresStateDir(t *testing.T) {
	if err := runFollowerResetBundleState(&cobra.Command{}, followerResetBundleOptions{}); err == nil ||
		!strings.Contains(err.Error(), "--state-dir is required") {
		t.Fatalf("missing --state-dir error = %v, want required", err)
	}
}

func TestFollowerResetBundleState_DryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runFollowerResetBundleState(cmd, followerResetBundleOptions{stateDir: dir, confirm: false}); err != nil {
		t.Fatalf("dry run error = %v", err)
	}
	if !strings.Contains(out.String(), "DRY RUN") {
		t.Fatalf("dry-run output = %q, want DRY RUN notice", out.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(): %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("dry run wrote %d entries, want none", len(entries))
	}
}

func TestFollowerResetBundleState_ConfirmResetsBundleStateOnly(t *testing.T) {
	dir := t.TempDir()
	cache, err := applycache.Open(applycache.Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	replayPath := filepath.Join(dir, emergency.RemoteKillStateFileName)
	if err := os.WriteFile(replayPath, []byte(`{"keep":true}`), 0o600); err != nil {
		t.Fatalf("write replay state: %v", err)
	}
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runFollowerResetBundleState(cmd, followerResetBundleOptions{stateDir: dir, confirm: true}); err != nil {
		t.Fatalf("confirm error = %v", err)
	}
	if _, err := os.Stat(replayPath); err != nil {
		t.Fatalf("remote-kill replay state removed: %v", err)
	}
	if _, err := cache.Active(); !errors.Is(err, applycache.ErrNoValidBundle) {
		t.Fatalf("Active() after reset = %v, want ErrNoValidBundle", err)
	}
	if !strings.Contains(out.String(), "reset policy-bundle apply state") {
		t.Fatalf("confirm output = %q, want reset confirmation", out.String())
	}
}
