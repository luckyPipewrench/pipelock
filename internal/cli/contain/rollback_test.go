// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRollback_DryRunDoesNotShellOut(t *testing.T) {
	env, runner, buf := newFakeEnv(t)
	err := runRollback(context.Background(), env, rollbackOpts{dryRun: true, keepData: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("dry-run shelled out: %v", runner.calls)
	}
	if !strings.Contains(buf.String(), "planned actions") {
		t.Errorf("missing 'planned actions': %q", buf.String())
	}
}

func TestRunRollback_ExecutesActionsInReverse(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Plant some artifacts so several actions have something to remove.
	if err := os.MkdirAll(filepath.Dir(env.sudoersPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.sudoersPath, []byte("sudoers"), 0o440); err != nil { //nolint:gosec // sudoers requires 0o440 per visudo
		t.Fatalf("write: %v", err)
	}
	err := runRollback(context.Background(), env, rollbackOpts{keepData: true, keepUsers: true})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := os.Stat(env.sudoersPath); err == nil {
		t.Errorf("sudoers not removed")
	}
}

func TestReadWrapperInventory_FallsBackToToolsList(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeTestToolsList(t, env, []toolsListEntry{
		{name: "claude", target: "/usr/local/bin/claude"},
		{name: "rustup", target: "/usr/local/bin/rustup"},
	})

	got := readWrapperInventory(env)
	want := []string{"plk-claude", "plk-rustup"}
	if !stringSlicesEqual(got, want) {
		t.Fatalf("wrappers = %#v, want %#v", got, want)
	}
}

func TestRollbackActions_KeepUsersSuppressesUserDel(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Make both users "exist" so the unguarded path would call userdel.
	env.lookupUser = func(name string) (*user.User, error) {
		return &user.User{Uid: "988", Gid: "988", Username: name}, nil
	}
	actions := rollbackActions(rollbackOpts{keepUsers: true, keepData: true})
	// Walk in reverse (matches runUndo) and call each undo. We don't go
	// through runUndo here because we want to assert that userdel was NOT
	// called by any of the user-delete actions.
	for i := len(actions) - 1; i >= 0; i-- {
		a := actions[i]
		if a.undo == nil {
			continue
		}
		_ = a.undo(context.Background(), env)
	}
	for _, c := range runner.calls {
		if c.name == testUserDel {
			t.Errorf("userdel called despite --keep-users: %v", c)
		}
	}
}

func TestRollbackActions_PurgeUsersOverridesKeepUsers(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.lookupUser = func(name string) (*user.User, error) {
		return &user.User{Uid: "988", Gid: "988", Username: name}, nil
	}
	actions := rollbackActions(rollbackOpts{keepUsers: true, purgeUsers: true, keepData: true})
	for i := len(actions) - 1; i >= 0; i-- {
		a := actions[i]
		if a.undo == nil {
			continue
		}
		_ = a.undo(context.Background(), env)
	}
	// userdel must run for BOTH users.
	count := 0
	for _, c := range runner.calls {
		if c.name == testUserDel {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 userdel calls (proxy + agent), got %d in %v", count, runner.calls)
	}
}

func TestRollbackActions_KeepDataLeavesDirs(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Plant the directories so we can check they survive.
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.MkdirAll(env.dataDir, 0o750); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	// keep-data=true (default).
	actions := rollbackActions(rollbackOpts{keepData: true})
	for i := len(actions) - 1; i >= 0; i-- {
		a := actions[i]
		if a.undo == nil {
			continue
		}
		_ = a.undo(context.Background(), env)
	}
	if _, err := os.Stat(env.configDir); err != nil {
		t.Errorf("configDir removed despite --keep-data: %v", err)
	}
	if _, err := os.Stat(env.dataDir); err != nil {
		t.Errorf("dataDir removed despite --keep-data: %v", err)
	}
}

func TestRollbackActions_DropDataWhenKeepDataFalse(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.MkdirAll(env.dataDir, 0o750); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	actions := rollbackActions(rollbackOpts{keepData: false})
	for i := len(actions) - 1; i >= 0; i-- {
		a := actions[i]
		if a.undo == nil {
			continue
		}
		_ = a.undo(context.Background(), env)
	}
	if _, err := os.Stat(env.configDir); err == nil {
		t.Errorf("configDir survived --keep-data=false")
	}
	if _, err := os.Stat(env.dataDir); err == nil {
		t.Errorf("dataDir survived --keep-data=false")
	}
}

func TestRollbackActions_RemovesWrappersFromInventory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Plant wrapper inventory with a custom tool plus standard ones.
	if err := os.MkdirAll(filepath.Dir(env.wrapperInvPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	inv := wrapperInventory{Wrappers: append(append([]string{}, defaultToolWrappers...), "plk-custom")}
	data, _ := json.MarshalIndent(inv, "", "  ")
	if err := os.WriteFile(env.wrapperInvPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	// Plant the wrapper files so we can confirm removal.
	for _, w := range inv.Wrappers {
		if err := os.WriteFile(filepath.Join(env.wrapperDir, w), []byte("#!/bin/bash\n"), 0o755); err != nil { //nolint:gosec // tmpdir
			t.Fatalf("plant wrapper %s: %v", w, err)
		}
	}

	actions := rollbackActions(rollbackOpts{keepData: true})
	// Find the remove-tool-wrappers action and invoke it.
	for _, a := range actions {
		if a.name == "remove-tool-wrappers" {
			if err := a.undo(context.Background(), env); err != nil {
				t.Fatalf("undo: %v", err)
			}
			break
		}
	}
	for _, w := range inv.Wrappers {
		if _, err := os.Stat(filepath.Join(env.wrapperDir, w)); err == nil {
			t.Errorf("wrapper %s not removed", w)
		}
	}
}

func TestRollback_DryRunPrintsPlan(t *testing.T) {
	actions := rollbackActions(rollbackOpts{keepData: true})
	var buf bytes.Buffer
	printPlan(&buf, "rollback plan:", actions)
	out := buf.String()
	// Spot-check a few entries from the install order.
	for _, want := range []string{
		"delete proxy user",
		"delete agent user",
		"remove pipelock binary",
		"remove /etc/sudoers.d/50-pipelock-agent",
		"drop pipelock_containment table",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan missing %q in:\n%s", want, out)
		}
	}
}

func TestRollback_RunUndoContinuesOnPerActionError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Force an undo to fail.
	first := step{
		name: "fails", desc: "fails",
		undo: func(context.Context, *installEnv) error { return errAny() },
	}
	second := step{
		name: "ok", desc: "ok",
		undo: func(context.Context, *installEnv) error { return nil },
	}
	var buf bytes.Buffer
	if err := runUndo(context.Background(), env, &buf, []step{first, second}); err == nil {
		t.Fatalf("expected joined error")
	}
	out := buf.String()
	if !strings.Contains(out, "[FAIL] fails") {
		t.Errorf("missing fail line: %q", out)
	}
	if !strings.Contains(out, "[ OK ] ok") {
		t.Errorf("missing ok line: %q", out)
	}
}

func errAny() error { return jsonError("synthetic") }

// jsonError makes a small typed error for the test above without inflating
// the package's import surface.
type jsonError string

func (j jsonError) Error() string { return string(j) }

func TestReadWrapperInventory_FallsBackToDefaults(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	got := readWrapperInventory(env) // file does not exist yet
	if len(got) != len(defaultToolWrappers) {
		t.Errorf("fallback len: got %d, want %d", len(got), len(defaultToolWrappers))
	}
}

func TestRollbackCmd_Wiring(t *testing.T) {
	cmd := rollbackCmd()
	if cmd.Use != "rollback" {
		t.Errorf("Use: %q", cmd.Use)
	}
	for _, f := range []string{"dry-run", "keep-data", "keep-users", "purge-users"} {
		if cmd.Flag(f) == nil {
			t.Errorf("missing flag %s", f)
		}
	}
}
