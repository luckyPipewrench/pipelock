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
	canonical := canonicalLaunchScript(8888, defaultCABundlePath)
	posture := posturebinding.RuntimeProofEnv + `="${` + posturebinding.RuntimeProofEnv + `:-/var/lib/pipelock/proof.json}"`
	cases := []struct {
		name       string
		body       string
		wantStatus string
		wantDetail string
	}{
		{
			name:       "canonical env -i block passes",
			body:       canonical,
			wantStatus: statusPass,
			wantDetail: "rebuilds exactly",
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
			name:       "a decoy comment does not satisfy the probe",
			body:       "#!/bin/bash\n# exec env -i " + posture + "\nexec env HOME=/home/agent \"$TARGET\" \"$@\"\n",
			wantStatus: statusFail,
			wantDetail: "plain `env`",
		},
		{
			name:       "a missing contract variable fails",
			body:       strings.Replace(canonical, "    NO_PROXY=", "    NOT_PROXY=", 1),
			wantStatus: statusFail,
			wantDetail: "missing: NO_PROXY",
		},
		{
			name:       "an extra operator variable fails even under env -i",
			body:       strings.Replace(canonical, "    PATH=", "    DISPLAY=\"$DISPLAY\" \\\n    PATH=", 1),
			wantStatus: statusFail,
			wantDetail: "unexpected: DISPLAY",
		},
		{
			// env applies the LAST assignment of a repeated name, so a wrapper
			// that sets HTTPS_PROXY twice runs with a value a reader scanning
			// from the top never sees.
			name:       "a duplicated assignment fails",
			body:       strings.Replace(canonical, "    PATH=", "    HTTPS_PROXY=http://127.0.0.1:9 \\\n    PATH=", 1),
			wantStatus: statusFail,
			wantDetail: "assigns HTTPS_PROXY more than once",
		},
		{
			// Two exec blocks make the effective environment depend on which one
			// the shell reaches, so a canonical decoy could front a leaky block.
			name:       "two exec env -i blocks are ambiguous",
			body:       canonical + "\n" + canonical,
			wantStatus: statusFail,
			wantDetail: "contains 2 `exec env -i` blocks",
		},
		{
			// The name-only check passes here: every expected variable is
			// present. Only the value check catches the redirected proxy.
			name:       "a redirected proxy value fails",
			body:       strings.Replace(canonical, "    HTTPS_PROXY=http://127.0.0.1:8888", "    HTTPS_PROXY=http://127.0.0.1:9999", 1),
			wantStatus: statusFail,
			wantDetail: "expected http://127.0.0.1:8888",
		},
		{
			name:       "a swapped CA bundle fails",
			body:       strings.Replace(canonical, "SSL_CERT_FILE="+defaultCABundlePath, "SSL_CERT_FILE=/tmp/attacker-ca.pem", 1),
			wantStatus: statusFail,
			wantDetail: "CA bundle",
		},
		{
			name:       "a dropped posture forward fails",
			body:       strings.Replace(canonical, "    "+posturebinding.RuntimeProofEnv+"=", "    IGNORED_PROOF=", 1),
			wantStatus: statusFail,
			wantDetail: "missing: " + posturebinding.RuntimeProofEnv,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t)
			// This probe reads only the launcher text, never the bundle file.
			// Production renders the wrapper and runs verify from one install
			// state, where both carry the default CA path; pin the probe env to
			// it so the fixture exercises that state rather than an impossible
			// one where the two disagree.
			env.caBundlePath = defaultCABundlePath
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
