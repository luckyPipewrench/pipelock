// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

// TestRunContainRun_RefusesWhenContractCannotBeWritten proves an unwritable
// stdout stops the run before posture emission and launch: a boundary the
// operator never saw is not launched.
func TestRunContainRun_RefusesWhenContractCannotBeWritten(t *testing.T) {
	env := allPassEnv(t)
	var launched, posture bool
	runEnv := containRunEnv{
		probe: env,
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
			launched = true
			return nil
		},
		emitPosture: func(string, string, *probeEnv, []string) (string, error) {
			posture = true
			return "/unused", nil
		},
	}
	sentinel := errors.New("stdout closed")
	err := runContainRun(context.Background(), nil, failingWriter{err: sentinel}, io.Discard, runEnv, containRunOptions{}, []string{"claude"})
	if err == nil || !strings.Contains(err.Error(), "write session contract") || !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want session-contract write failure wrapping the writer error", err)
	}
	if launched || posture {
		t.Fatalf("launched=%v posture=%v after an unwritten contract, want neither", launched, posture)
	}
	if err := renderSessionContract(&bytes.Buffer{}, sessionContract{Tool: "claude"}); err != nil {
		t.Fatalf("render to a healthy writer = %v, want nil", err)
	}
}

// TestProbeWorkspaceAccess_ChecksRecordedGrantPaths proves a recorded grant is
// readability-checked even when no --workspace path was given, and that an
// unreadable grant fails the probe rather than passing with zero paths.
func TestProbeWorkspaceAccess_ChecksRecordedGrantPaths(t *testing.T) {
	dir := t.TempDir()
	env := makeProbeEnv(t)
	env.now = func() time.Time { return testNow }
	env.workspaceGrants = []workspaceGrant{{Path: dir, Mode: workspaceModeReadOnly, Owner: "josh", Created: "2026-05-01T00:00:00Z"}}

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == "sudo" && strings.Contains(strings.Join(args, " "), dir) {
			return "", 1, nil
		}
		return "", 0, nil
	}
	status, detail := probeWorkspaceAccess(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "not readable") {
		t.Fatalf("status=%q detail=%q, want fail on an unreadable recorded grant", status, detail)
	}

	env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
	env.workspacePaths = []string{dir} // duplicate of the grant path: checked once
	status, detail = probeWorkspaceAccess(context.Background(), env)
	if status != statusPass || !strings.Contains(detail, "1 workspace path(s) readable") {
		t.Fatalf("status=%q detail=%q, want pass over one deduplicated path", status, detail)
	}
}

// TestProbeWorkspaceAccess_FailsOnUnreadableInventory proves a permission or
// parse error on the recorded inventory is a probe failure, not an empty grant
// set that lets verify pass.
func TestProbeWorkspaceAccess_FailsOnUnreadableInventory(t *testing.T) {
	env := makeProbeEnv(t)
	env.workspaceInvErr = errors.New("permission denied")
	probes := probesForEnv(env)
	if probes[len(probes)-1].name != "workspace_access" {
		t.Fatalf("workspace_access probe must run when the inventory is unreadable; got %q", probes[len(probes)-1].name)
	}
	status, detail := probeWorkspaceAccess(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "could not be read") {
		t.Fatalf("status=%q detail=%q, want fail on an unreadable inventory", status, detail)
	}
}

// TestLoadWorkspaceInventoryFrom_ParseErrorIsAnError pins the loader contract
// the verify command relies on: absence is empty, corruption is an error.
func TestLoadWorkspaceInventoryFrom_ParseErrorIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspaces.json")
	if _, err := loadWorkspaceInventoryFrom(os.ReadFile, path); err != nil {
		t.Fatalf("missing inventory = %v, want empty and nil", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWorkspaceInventoryFrom(os.ReadFile, path); err == nil {
		t.Fatal("corrupt inventory loaded as empty; want an error")
	}
}

// TestRunListWorkspaces_FiltersByAgentUserAndShowsReason proves the listing
// honors --agent-user for grants that record one, keeps legacy rows visible to
// every agent user, and renders the recorded reason.
func TestRunListWorkspaces_FiltersByAgentUserAndShowsReason(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.now = func() time.Time { return testNow }
	if err := writeWorkspaceInventory(env, workspaceInventory{Workspaces: []workspaceGrant{
		{Path: "/a/mine", Mode: "read-write", Owner: "josh", Created: "2026-05-01T00:00:00Z", Reason: "sprint work", AgentUser: env.agentUserName},
		{Path: "/b/other", Mode: "read-only", Owner: "josh", Created: "2026-05-01T00:00:00Z", AgentUser: "other-agent"},
		{Path: "/c/legacy", Mode: "read-only"},
	}}); err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	var buf bytes.Buffer
	env.out = &buf
	if err := runListWorkspaces(env); err != nil {
		t.Fatalf("list: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"REASON", "/a/mine", "sprint work", "/c/legacy"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/b/other") {
		t.Errorf("list showed another agent user's grant:\n%s", out)
	}

	env.agentUserName = "nobody-here"
	buf.Reset()
	if err := runListWorkspaces(env); err != nil {
		t.Fatalf("list for unknown agent: %v", err)
	}
	if !strings.Contains(buf.String(), "/c/legacy") || strings.Contains(buf.String(), "/a/mine") {
		t.Fatalf("legacy row must stay visible and recorded rows must filter:\n%s", buf.String())
	}
}

// TestRunGrantWorkspace_RecordsAgentUser proves a new grant records the agent
// user it was granted to so list-workspaces can filter on it.
func TestRunGrantWorkspace_RecordsAgentUser(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.now = func() time.Time { return testNow }
	env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
	if err := runGrantWorkspace(context.Background(), env, t.TempDir(), workspaceOpts{mode: workspaceModeReadOnly}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	inv, err := loadWorkspaceInventory(env)
	if err != nil || len(inv.Workspaces) != 1 {
		t.Fatalf("load: %v (%d grants)", err, len(inv.Workspaces))
	}
	if inv.Workspaces[0].AgentUser != env.agentUserName {
		t.Fatalf("agent_user = %q, want %q", inv.Workspaces[0].AgentUser, env.agentUserName)
	}
}
