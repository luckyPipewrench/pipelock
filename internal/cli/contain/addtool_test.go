// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestAddToolNamePattern(t *testing.T) {
	good := []string{"claude", "codex", "tool-1", "x", "a_b", "tool-with-dashes"}
	for _, n := range good {
		if !addToolNamePattern.MatchString(n) {
			t.Errorf("expected %q to validate", n)
		}
	}
	bad := []string{"", "Capital", "-leading", "_leading", "../etc", "a b", "tool!", strings.Repeat("a", 32)}
	for _, n := range bad {
		if addToolNamePattern.MatchString(n) {
			t.Errorf("expected %q to be rejected", n)
		}
	}
}

func TestRunAddTool_DryRunNonMutating(t *testing.T) {
	env, runner, buf := newFakeEnv(t)
	if err := os.WriteFile(filepath.Join(env.wrapperDir, "plk-launch"), []byte("#!/bin/bash\n"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant: %v", err)
	}
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant target: %v", err)
	}
	err := runAddTool(context.Background(), env, "claude", addToolOpts{dryRun: true, target: target})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	// No wrapper should have been written.
	if _, err := os.Stat(filepath.Join(env.wrapperDir, "plk-claude")); err == nil {
		t.Errorf("dry-run wrote wrapper")
	}
	// No inventory file either.
	if _, err := os.Stat(env.wrapperInvPath); err == nil {
		t.Errorf("dry-run wrote inventory")
	}
	_ = runner
	if !strings.Contains(buf.String(), "planned") {
		t.Errorf("output: %q", buf.String())
	}
}

func TestRunAddTool_UsesCommandVToResolveTarget(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.WriteFile(filepath.Join(env.wrapperDir, "plk-launch"), []byte("#!/bin/bash\n"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant: %v", err)
	}
	resolvedTarget := filepath.Join(t.TempDir(), "discovered-tool")
	if err := os.WriteFile(resolvedTarget, []byte("x"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant: %v", err)
	}
	runner.on(argvFor(testSudoCmd, "-n", "-u", "pipelock-agent", "--", "env", "PATH="+agentExecPath("pipelock-agent"), "sh", "-c", "command -v -- \"$1\"", "sh", "discovered"), resolvedTarget+"\n", 0, nil)
	err := runAddTool(context.Background(), env, "discovered", addToolOpts{})
	if err != nil {
		t.Fatalf("addTool: %v", err)
	}
	if _, err := os.Stat(filepath.Join(env.wrapperDir, "plk-discovered")); err != nil {
		t.Errorf("wrapper not written: %v", err)
	}
}

func TestRunAddTool_FailsWhenCommandVFindsNoTarget(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor(testSudoCmd, "-n", "-u", "pipelock-agent", "--", "env", "PATH="+agentExecPath("pipelock-agent"), "sh", "-c", "command -v -- \"$1\"", "sh", "nopath"), "", 1, nil)
	err := runAddTool(context.Background(), env, "nopath", addToolOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit: %d", cliutil.ExitCodeOf(err))
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("err: %v", err)
	}
}

func TestRunAddTool_FailsWhenCommandVCannotStart(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor(testSudoCmd, "-n", "-u", "pipelock-agent", "--", "env", "PATH="+agentExecPath("pipelock-agent"), "sh", "-c", "command -v -- \"$1\"", "sh", "broken"), "", -1, errors.New("fork/exec sudo: permission denied"))
	err := runAddTool(context.Background(), env, "broken", addToolOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit: %d", cliutil.ExitCodeOf(err))
	}
	if !strings.Contains(err.Error(), "resolve tool") {
		t.Errorf("err: %v", err)
	}
}

func TestRunAddTool_FailsWhenExplicitTargetNotExecutableByAgent(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "private-tool")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant target: %v", err)
	}
	runner.on(argvFor(testSudoCmd, "-n", "-u", "pipelock-agent", "--", "test", "-x", target), "permission denied\n", 1, nil)
	err := runAddTool(context.Background(), env, "private", addToolOpts{target: target})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not executable by pipelock-agent") {
		t.Fatalf("err: %v", err)
	}
}

func TestRunAddTool_IdempotentWhenWrapperAndInventoryMatch(t *testing.T) {
	env, _, buf := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant: %v", err)
	}
	if err := runAddTool(context.Background(), env, "claude", addToolOpts{target: target}); err != nil {
		t.Fatalf("first: %v", err)
	}
	buf.Reset()
	if err := runAddTool(context.Background(), env, "claude", addToolOpts{target: target}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if !strings.Contains(buf.String(), "already installed") {
		t.Errorf("expected idempotent message, got %q", buf.String())
	}
}

// runAddToolBypassRoot exercises the post-root-check path. runAddTool is
// already the testable post-Cobra entry point; the Cobra wrapper owns the
// os.Geteuid check.
func runAddToolBypassRoot(t *testing.T, env *installEnv, name string, opts addToolOpts) error {
	t.Helper()
	if !addToolNamePattern.MatchString(name) {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("invalid tool name %q", name))
	}
	return runAddTool(context.Background(), env, name, opts)
}

func TestAddTool_WritesWrapperAndAppendsInventory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Plant plk-launch since the wrapper template references it (otherwise
	// the rendered file is fine but verify checks would later spot it).
	if err := os.WriteFile(filepath.Join(env.wrapperDir, "plk-launch"), []byte("#!/bin/bash\n"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant plk-launch: %v", err)
	}
	target := filepath.Join(t.TempDir(), "rustup")
	if err := os.WriteFile(target, []byte("#!/bin/bash\n"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant target: %v", err)
	}
	if err := runAddToolBypassRoot(t, env, "rustup", addToolOpts{target: target}); err != nil {
		t.Fatalf("runAddTool: %v", err)
	}
	wrapperPath := filepath.Join(env.wrapperDir, "plk-rustup")
	if _, err := os.Stat(wrapperPath); err != nil {
		t.Errorf("wrapper not written: %v", err)
	}
	// Inventory must list the new wrapper.
	data, err := os.ReadFile(env.wrapperInvPath)
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	var inv wrapperInventory
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatalf("unmarshal inventory: %v", err)
	}
	found := false
	for _, w := range inv.Wrappers {
		if w == "plk-rustup" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("inventory missing plk-rustup: %v", inv.Wrappers)
	}
}

func TestAddTool_IdempotentReapply(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant target: %v", err)
	}
	// First call writes.
	if err := runAddToolBypassRoot(t, env, "claude", addToolOpts{target: target}); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Second call must be no-op.
	var buf bytes.Buffer
	env.out = &buf
	if err := runAddToolBypassRoot(t, env, "claude", addToolOpts{target: target}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if !strings.Contains(buf.String(), "already installed") {
		t.Errorf("expected noop output, got %q", buf.String())
	}
}

func TestAppendInventory_DeduplicatesEntries(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := appendInventory(env, "plk-claude"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := appendInventory(env, "plk-claude"); err != nil {
		t.Fatalf("second: %v", err)
	}
	inv := readWrapperInventory(env)
	count := 0
	for _, w := range inv {
		if w == "plk-claude" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate entries: got %d plk-claude rows, want 1: %v", count, inv)
	}
}

func TestAppendInventory_RejectsMalformedInventory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.wrapperInvPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.wrapperInvPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	err := appendInventory(env, "plk-claude")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "parse inventory") {
		t.Fatalf("err: %v", err)
	}
}

func TestWrapperInInventory_NoFile(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if wrapperInInventory(env, "plk-anything") {
		t.Errorf("expected false when inventory file is absent")
	}
}

func TestWrapperInInventory_Hit(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := appendInventory(env, "plk-codex"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if !wrapperInInventory(env, "plk-codex") {
		t.Errorf("expected true after append")
	}
	if wrapperInInventory(env, "plk-other") {
		t.Errorf("expected false for unrelated name")
	}
}

func TestAddToolCmd_Wiring(t *testing.T) {
	cmd := addToolCmd()
	if cmd.Use != "add-tool <name>" {
		t.Errorf("Use: %q", cmd.Use)
	}
	for _, f := range []string{"dry-run", "target"} {
		if cmd.Flag(f) == nil {
			t.Errorf("missing flag %s", f)
		}
	}
	// Args validator rejects 0 / 2+ positional.
	if err := cmd.Args(cmd, nil); err == nil {
		t.Errorf("expected error for 0 args")
	}
	if err := cmd.Args(cmd, []string{"a", "b"}); err == nil {
		t.Errorf("expected error for 2 args")
	}
}

func TestAddToolCmdRejectsInvalidNameBeforeRootCheck(t *testing.T) {
	cmd := addToolCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"bad/name", "--dry-run"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected invalid tool name error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Fatalf("exit code: got %d want %d", cliutil.ExitCodeOf(err), cliutil.ExitConfig)
	}
	if !strings.Contains(err.Error(), "invalid tool name") {
		t.Fatalf("err: %v", err)
	}
}

func TestAddTool_RejectsMissingTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	missing := filepath.Join(t.TempDir(), "nope")
	err := runAddToolBypassRoot(t, env, "tool", addToolOpts{target: missing})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, err) { // sanity
		_ = err
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
}

func TestAddTool_RejectsInvalidName(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	err := runAddToolBypassRoot(t, env, "INVALID", addToolOpts{target: "/bin/ls"})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
}

func TestAddTool_RejectsRelativeTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	err := runAddToolBypassRoot(t, env, "tool", addToolOpts{target: "relative-tool"})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("err: %v", err)
	}
}

func TestAddTool_RejectsNonExecutableTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("plant target: %v", err)
	}
	err := runAddToolBypassRoot(t, env, "tool", addToolOpts{target: target})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
	if !strings.Contains(err.Error(), "not executable") {
		t.Errorf("err: %v", err)
	}
}
