// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSetfaclCmd = "setfacl"

func TestWorkspaceACLCommands(t *testing.T) {
	commands := workspaceACLCommands("/home/josh/dev/pipelock", "pipelock-agent", workspaceModeReadWrite)
	if len(commands) != 5 {
		t.Fatalf("commands len = %d, want 5", len(commands))
	}
	if commands[0].name != testSetfaclCmd || !containsArg(commands[0].args, "/home/josh/dev") {
		t.Fatalf("ancestor command = %+v", commands[0])
	}
	if got := strings.Join(commands[1].args, " "); !strings.Contains(got, "u:pipelock-agent:rwX") {
		t.Fatalf("recursive command args = %q, want rwX ACL", got)
	}
	if commands[2].name != "find" || !containsArg(commands[2].args, "-mindepth") || !containsArg(commands[2].args, "1") ||
		!containsArg(commands[2].args, "d:u:pipelock-agent:rwX") {
		t.Fatalf("default ACL command = %+v", commands[2])
	}
	if !containsArg(commands[3].args, "auth.json") || !containsArg(commands[3].args, "*.token") ||
		!containsArg(commands[3].args, "u:pipelock-agent") {
		t.Fatalf("credential ACL lock command = %+v", commands[3])
	}
	if !containsArg(commands[4].args, "chmod") || !containsArg(commands[4].args, "0600") {
		t.Fatalf("credential chmod lock command = %+v", commands[4])
	}
}

func TestWorkspaceACLCommandsReadOnly(t *testing.T) {
	commands := workspaceACLCommands("/srv/project", "pipelock-agent", workspaceModeReadOnly)
	if got := strings.Join(commands[1].args, " "); !strings.Contains(got, "u:pipelock-agent:rX") {
		t.Fatalf("recursive command args = %q, want rX ACL", got)
	}
	if !containsArg(commands[2].args, "-mindepth") || !containsArg(commands[2].args, "1") ||
		!containsArg(commands[2].args, "d:u:pipelock-agent:rX") {
		t.Fatalf("default ACL command = %+v", commands[2])
	}
}

func TestRunGrantWorkspaceDryRun(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	var buf bytes.Buffer
	env.out = &buf
	workspace := t.TempDir()
	err := runGrantWorkspace(context.Background(), env, workspace, workspaceOpts{dryRun: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "u:pipelock-agent:rX") || !strings.Contains(out, "workspaces.json") {
		t.Fatalf("dry-run output missing ACL commands:\n%s", out)
	}
}

func TestWorkspaceCommandsWireFlags(t *testing.T) {
	t.Run("grant dry run", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := grantWorkspaceCmd()
		cmd.SetOut(&buf)
		cmd.SetArgs([]string{"--dry-run", "--mode", workspaceModeReadWrite, t.TempDir()})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("grant command: %v", err)
		}
		if out := buf.String(); !strings.Contains(out, "rwX") || !strings.Contains(out, "planned") {
			t.Fatalf("grant dry-run output missing plan:\n%s", out)
		}
	})

	t.Run("grant invalid agent user", func(t *testing.T) {
		cmd := grantWorkspaceCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--dry-run", "--agent-user", "bad user", t.TempDir()})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "agent user") {
			t.Fatalf("err = %v, want agent user validation failure", err)
		}
	})

	t.Run("revoke dry run", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := revokeWorkspaceCmd()
		cmd.SetOut(&buf)
		cmd.SetArgs([]string{"--dry-run", t.TempDir()})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("revoke command: %v", err)
		}
		if out := buf.String(); !strings.Contains(out, "revoke-workspace") || !strings.Contains(out, "planned") {
			t.Fatalf("revoke dry-run output missing plan:\n%s", out)
		}
	})

	t.Run("revoke invalid agent user", func(t *testing.T) {
		cmd := revokeWorkspaceCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--dry-run", "--agent-user", "bad user", t.TempDir()})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "agent user") {
			t.Fatalf("err = %v, want agent user validation failure", err)
		}
	})
}

func TestRunGrantWorkspaceExecutesCommands(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	workspace := t.TempDir()
	err := runGrantWorkspace(context.Background(), env, workspace, workspaceOpts{mode: workspaceModeReadWrite})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("calls = %d, want 5: %+v", len(runner.calls), runner.calls)
	}
	if runner.calls[0].name != testSetfaclCmd || runner.calls[1].name != testSetfaclCmd || runner.calls[2].name != "find" {
		t.Fatalf("unexpected command sequence: %+v", runner.calls)
	}
	inv := readWorkspaceInventory(env)
	if len(inv.Workspaces) != 1 || inv.Workspaces[0].Path != workspace || inv.Workspaces[0].Mode != workspaceModeReadWrite {
		t.Fatalf("workspace inventory = %+v", inv)
	}
}

func TestRunGrantWorkspaceErrorBranches(t *testing.T) {
	t.Run("invalid mode", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		err := runGrantWorkspace(context.Background(), env, t.TempDir(), workspaceOpts{mode: "write-only"})
		if err == nil || !strings.Contains(err.Error(), "invalid --mode") {
			t.Fatalf("err = %v, want invalid mode", err)
		}
	})

	t.Run("command failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		workspace := t.TempDir()
		commands := workspaceACLCommands(workspace, env.agentUserName, workspaceModeReadOnly)
		runner.on(argvFor(commands[0].name, commands[0].args...), "permission denied", 1, nil)
		err := runGrantWorkspace(context.Background(), env, workspace, workspaceOpts{})
		if err == nil || !strings.Contains(err.Error(), "exit 1") {
			t.Fatalf("err = %v, want command exit failure", err)
		}
	})

	t.Run("inventory write failure", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.workspaceInvPath = filepath.Join(t.TempDir(), "inventory-dir")
		if err := os.Mkdir(env.workspaceInvPath, 0o750); err != nil {
			t.Fatalf("mkdir inventory path: %v", err)
		}
		err := runGrantWorkspace(context.Background(), env, t.TempDir(), workspaceOpts{})
		if err == nil || !strings.Contains(err.Error(), "record workspace grant") {
			t.Fatalf("err = %v, want inventory record failure", err)
		}
	})
}

func TestRunGrantWorkspaceRejectsSystemPath(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	for _, prefix := range []string{"/etc", "/opt", "/var", "/usr", "/root"} {
		t.Run("denies "+prefix, func(t *testing.T) {
			_, err := resolveWorkspaceDir(env, prefix, false)
			if err == nil || !strings.Contains(err.Error(), "protected system path") {
				t.Fatalf("err = %v, want protected system path", err)
			}
			_, err = resolveWorkspaceDir(env, prefix, true)
			if err != nil {
				t.Fatalf("allow system path: %v", err)
			}
		})
	}
}

func TestRunRevokeWorkspaceDryRun(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	var buf bytes.Buffer
	env.out = &buf
	workspace := t.TempDir()
	if err := writeWorkspaceInventory(env, workspaceInventory{Workspaces: []workspaceGrant{
		{Path: workspace, Mode: workspaceModeReadOnly},
	}}); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	err := runRevokeWorkspace(context.Background(), env, workspace, workspaceOpts{dryRun: true})
	if err != nil {
		t.Fatalf("dry-run revoke: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "revoke-workspace") || !strings.Contains(out, "workspaces.json") {
		t.Fatalf("dry-run output missing revoke plan:\n%s", out)
	}
}

func TestRunRevokeWorkspaceExecutesCommandsAndUpdatesInventory(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	parent := t.TempDir()
	workspaceA := filepath.Join(parent, "a")
	workspaceB := filepath.Join(parent, "b")
	if err := os.Mkdir(workspaceA, 0o750); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}
	if err := os.Mkdir(workspaceB, 0o750); err != nil {
		t.Fatalf("mkdir b: %v", err)
	}
	if err := writeWorkspaceInventory(env, workspaceInventory{Workspaces: []workspaceGrant{
		{Path: workspaceA, Mode: workspaceModeReadOnly},
		{Path: workspaceB, Mode: workspaceModeReadWrite},
	}}); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	runner.calls = nil
	err := runRevokeWorkspace(context.Background(), env, workspaceA, workspaceOpts{})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %d, want 2 because shared parent ancestors are preserved: %+v", len(runner.calls), runner.calls)
	}
	inv := readWorkspaceInventory(env)
	if len(inv.Workspaces) != 1 || inv.Workspaces[0].Path != workspaceB {
		t.Fatalf("workspace inventory = %+v", inv)
	}
}

func TestRunRevokeWorkspaceErrorBranches(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		err := runRevokeWorkspace(context.Background(), env, "", workspaceOpts{})
		if err == nil || !strings.Contains(err.Error(), "workspace path is empty") {
			t.Fatalf("err = %v, want empty path", err)
		}
	})

	t.Run("command failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		workspace := t.TempDir()
		if err := writeWorkspaceInventory(env, workspaceInventory{Workspaces: []workspaceGrant{
			{Path: workspace, Mode: workspaceModeReadOnly},
		}}); err != nil {
			t.Fatalf("write inventory: %v", err)
		}
		commands := workspaceRevokeCommands(workspace, env.agentUserName, nil, true)
		runner.on(argvFor(commands[0].name, commands[0].args...), "", 0, errors.New("setfacl unavailable"))
		err := runRevokeWorkspace(context.Background(), env, workspace, workspaceOpts{})
		if err == nil || !strings.Contains(err.Error(), "setfacl unavailable") {
			t.Fatalf("err = %v, want command error", err)
		}
	})

	t.Run("inventory update failure", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		workspace := t.TempDir()
		if err := writeWorkspaceInventory(env, workspaceInventory{Workspaces: []workspaceGrant{
			{Path: workspace, Mode: workspaceModeReadOnly},
		}}); err != nil {
			t.Fatalf("write inventory: %v", err)
		}
		env.writeFile = func(string, []byte, os.FileMode) error {
			return errors.New("disk full")
		}
		err := runRevokeWorkspace(context.Background(), env, workspace, workspaceOpts{})
		if err == nil || !strings.Contains(err.Error(), "update workspace inventory") {
			t.Fatalf("err = %v, want inventory update failure", err)
		}
	})
}

func TestRunRevokeWorkspaceHandlesDeletedTrackedWorkspace(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	parent := t.TempDir()
	workspace := filepath.Join(parent, "deleted")
	if err := writeWorkspaceInventory(env, workspaceInventory{Workspaces: []workspaceGrant{
		{Path: workspace, Mode: workspaceModeReadOnly},
	}}); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	err := runRevokeWorkspace(context.Background(), env, workspace, workspaceOpts{})
	if err != nil {
		t.Fatalf("revoke deleted workspace: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d, want only ancestor ACL cleanup: %+v", len(runner.calls), runner.calls)
	}
	if runner.calls[0].name != testSetfaclCmd || !containsArg(runner.calls[0].args, parent) {
		t.Fatalf("unexpected cleanup command: %+v", runner.calls[0])
	}
	inv := readWorkspaceInventory(env)
	if len(inv.Workspaces) != 0 {
		t.Fatalf("workspace inventory = %+v, want empty", inv)
	}
}

func TestRunRevokeWorkspaceFailsOnMalformedInventory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(env.workspaceInvPath), 0o750); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(env.workspaceInvPath, []byte("{nope"), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	err := runRevokeWorkspace(context.Background(), env, workspace, workspaceOpts{})
	if err == nil || !strings.Contains(err.Error(), "read workspace inventory") {
		t.Fatalf("err = %v, want inventory parse failure", err)
	}
}

func TestResolveWorkspaceDirRejectsFile(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := resolveWorkspaceDir(env, path, false)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("err = %v, want not a directory", err)
	}
}

func TestResolveWorkspaceDirRejectsEmptyAndMissing(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if _, err := resolveWorkspaceDir(env, "  ", false); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty path err = %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := resolveWorkspaceDir(env, missing, false); err == nil || !strings.Contains(err.Error(), "resolve workspace symlinks") {
		t.Fatalf("missing path err = %v", err)
	}
}

func TestWorkspaceRevokeAllCommandsDeduplicatesAncestors(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	commands, err := workspaceRevokeAllCommands(env, []workspaceGrant{
		{Path: "/home/josh/dev/a", Mode: workspaceModeReadOnly},
		{Path: "/home/josh/dev/b", Mode: workspaceModeReadOnly},
	}, "pipelock-agent")
	if err != nil {
		t.Fatalf("commands: %v", err)
	}
	if len(commands) != 1 {
		t.Fatalf("commands len = %d, want 1 ancestor cleanup for missing workspaces", len(commands))
	}
	last := commands[len(commands)-1]
	if last.name != testSetfaclCmd {
		t.Fatalf("last command = %+v", last)
	}
	if strings.Count(strings.Join(last.args, " "), "/home/josh/dev") != 1 {
		t.Fatalf("ancestors not deduplicated: %+v", last)
	}
}

func TestWorkspaceRevokeAllCommandsCoversExistingDuplicateAndStatError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	workspace := t.TempDir()
	commands, err := workspaceRevokeAllCommands(env, []workspaceGrant{
		{Path: workspace, Mode: workspaceModeReadOnly},
		{Path: workspace, Mode: workspaceModeReadWrite},
	}, env.agentUserName)
	if err != nil {
		t.Fatalf("commands: %v", err)
	}
	if len(commands) != 3 {
		t.Fatalf("commands len = %d, want revoke file, default ACL, and ancestor cleanup: %+v", len(commands), commands)
	}

	env.stat = func(string) (os.FileInfo, error) {
		return nil, errors.New("stat boom")
	}
	_, err = workspaceRevokeAllCommands(env, []workspaceGrant{{Path: workspace, Mode: workspaceModeReadOnly}}, env.agentUserName)
	if err == nil || !strings.Contains(err.Error(), "stat workspace") {
		t.Fatalf("err = %v, want stat workspace failure", err)
	}
}

func TestRecordWorkspaceGrantReplacesAndSorts(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := recordWorkspaceGrant(env, workspaceGrant{Path: "/tmp/z", Mode: workspaceModeReadOnly}); err != nil {
		t.Fatalf("record z: %v", err)
	}
	if err := recordWorkspaceGrant(env, workspaceGrant{Path: "/tmp/a", Mode: workspaceModeReadOnly}); err != nil {
		t.Fatalf("record a: %v", err)
	}
	if err := recordWorkspaceGrant(env, workspaceGrant{Path: "/tmp/z", Mode: workspaceModeReadWrite}); err != nil {
		t.Fatalf("replace z: %v", err)
	}
	inv := readWorkspaceInventory(env)
	if len(inv.Workspaces) != 2 {
		t.Fatalf("inventory len = %d, want 2: %+v", len(inv.Workspaces), inv)
	}
	if inv.Workspaces[0].Path != "/tmp/a" || inv.Workspaces[1].Mode != workspaceModeReadWrite {
		t.Fatalf("inventory not sorted/replaced: %+v", inv.Workspaces)
	}
}
