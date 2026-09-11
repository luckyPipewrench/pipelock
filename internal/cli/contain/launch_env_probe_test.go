// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
)

// TestProbeLaunchEnvAllowList walks every verdict the launcher-environment
// probe can return. The probe reads the installed plk-launch text, so each case
// writes a launcher and asserts the status plus the operator-facing detail.
func TestProbeLaunchEnvAllowList(t *testing.T) {
	posture := posturebinding.RuntimeProofEnv + `="${` + posturebinding.RuntimeProofEnv + `:-/var/lib/pipelock/proof.json}"`
	cases := []struct {
		name       string
		body       string
		wantStatus string
		wantDetail string
	}{
		{
			name:       "env -i with posture forward passes",
			body:       "#!/bin/bash\nexec env -i \\\n    HOME=/home/agent \\\n    " + posture + " \\\n    PATH=\"$AGENT_PATH\" \\\n    \"$TARGET\" \"$@\"\n",
			wantStatus: statusPass,
			wantDetail: "env -i",
		},
		{
			name:       "plain env leaks the operator environment",
			body:       "#!/bin/bash\nexec env \\\n    HOME=/home/agent \\\n    \"$TARGET\" \"$@\"\n",
			wantStatus: statusFail,
			wantDetail: "plain `env`",
		},
		{
			name:       "no env at all does not clear the environment",
			body:       "#!/bin/bash\nexec \"$TARGET\" \"$@\"\n",
			wantStatus: statusFail,
			wantDetail: "does not clear the environment",
		},
		{
			name:       "env -i without the posture forward grades containment unknown",
			body:       "#!/bin/bash\nexec env -i \\\n    HOME=/home/agent \\\n    \"$TARGET\" \"$@\"\n",
			wantStatus: statusFail,
			wantDetail: "does not forward " + posturebinding.RuntimeProofEnv,
		},
		{
			name:       "explicit operator variable passthrough fails even under env -i",
			body:       "#!/bin/bash\nexec env -i \\\n    " + posture + " \\\n    DISPLAY=\"$DISPLAY\" \\\n    \"$TARGET\" \"$@\"\n",
			wantStatus: statusFail,
			wantDetail: "explicitly forwards an operator variable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t)
			if err := os.WriteFile(env.launchPath, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write launcher: %v", err)
			}
			status, detail := probeLaunchEnvAllowList(context.Background(), env)
			if status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (detail=%q)", status, tc.wantStatus, detail)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("detail = %q, want substring %q", detail, tc.wantDetail)
			}
		})
	}

	t.Run("missing launcher skips rather than passing", func(t *testing.T) {
		env := makeProbeEnv(t)
		_ = os.Remove(env.launchPath)
		status, detail := probeLaunchEnvAllowList(context.Background(), env)
		if status != statusSkip {
			t.Fatalf("status = %q, want skip (detail=%q)", status, detail)
		}
		if !strings.Contains(detail, "install never ran") {
			t.Fatalf("detail = %q", detail)
		}
	})
}

// TestRunGrantWorkspace_RejectsBadExpiry proves an unparseable or already-past
// --expires is a configuration error, never a silently ignored expiry.
func TestRunGrantWorkspace_RejectsBadExpiry(t *testing.T) {
	for _, bad := range []string{"soon", "-1h", "2020-01-01T00:00:00Z"} {
		t.Run(bad, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			env.now = func() time.Time { return testNow }
			env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
			err := runGrantWorkspace(context.Background(), env, t.TempDir(), workspaceOpts{mode: workspaceModeReadOnly, expires: bad})
			if err == nil || !strings.Contains(err.Error(), "invalid --expires") {
				t.Fatalf("err = %v, want invalid --expires", err)
			}
			inv, loadErr := loadWorkspaceInventory(env)
			if loadErr != nil {
				t.Fatalf("load: %v", loadErr)
			}
			if len(inv.Workspaces) != 0 {
				t.Fatalf("a rejected grant must not be recorded: %+v", inv.Workspaces)
			}
		})
	}
}

// TestListWorkspacesCmd_RejectsInvalidAgentUser covers the command wiring's
// fail-closed username validation without touching the host inventory.
func TestListWorkspacesCmd_RejectsInvalidAgentUser(t *testing.T) {
	cmd := listWorkspacesCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--agent-user", "bad user!"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "agent user") {
		t.Fatalf("err = %v, want agent user validation error", err)
	}
}
