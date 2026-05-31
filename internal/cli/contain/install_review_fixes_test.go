// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests covering review blockers found during contain install hardening:
//   - stepStopUserService must have an undo that restarts the user service without changing enablement
//   - plk-launch must validate $TOOL against the runtime allow-list
//   - per-tool wrappers must use `sudo -n` for fail-fast
//   - --target must be honored at runtime (baked into tools.list)

func TestStepStopUserService_UndoRestartsStoppedUserService(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor(testSystemctl, "--user", "-M", "operator@.host", "is-active", "pipelock"), "active\n", 0, nil)
	s := stepStopUserService()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected apply")
	}
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	var sawStart, sawEnable bool
	for _, c := range runner.calls {
		if c.name == testSystemctl && containsArg(c.args, "start") && containsArg(c.args, "pipelock") {
			sawStart = true
		}
		if c.name == testSystemctl && containsArg(c.args, "enable") && containsArg(c.args, "pipelock") {
			sawEnable = true
		}
	}
	if !sawStart {
		t.Errorf("undo did not restart user pipelock, calls=%v", runner.calls)
	}
	if sawEnable {
		t.Errorf("undo changed user service enablement, calls=%v", runner.calls)
	}
}

func TestStepStopUserService_UndoNoOpWhenNoOperator(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.operatorUser = ""
	s := stepStopUserService()
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("expected no shell-out when operator empty, got %v", runner.calls)
	}
}

func TestRenderLaunchWrapper_EmbedsAllowListLookup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderLaunchWrapper(env)
	requirements := []string{
		"TOOLS_LIST=", // file path baked in
		env.toolsListPath,
		"not in pipelock contain allow-list",
		"refusing non-absolute target",
		`[[ ! "$TOOL" =~ ` + containToolNameRegex, // shared regex check
		"set -euo pipefail",
	}
	for _, r := range requirements {
		if !strings.Contains(body, r) {
			t.Errorf("plk-launch body missing %q in:\n%s", r, body)
		}
	}
	// MUST NOT just exec $TOOL - must exec $TARGET resolved through the
	// allow-list pipeline.
	if !strings.Contains(body, `"$TARGET" "$@"`) {
		t.Errorf("plk-launch must exec $TARGET, not $TOOL")
	}
}

func TestRenderDefaultToolsList_IncludesEveryDefaultTool(t *testing.T) {
	got := renderDefaultToolsList()
	for _, name := range defaultToolNames() {
		// Each default tool appears on its own line with an empty target
		// (single tab + newline) so plk-launch resolves via PATH.
		want := name + "\t\n"
		if !strings.Contains(got, want) {
			t.Errorf("tools.list missing line %q in:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "# Managed by") {
		t.Errorf("tools.list missing header comment")
	}
}

func TestReadToolsList_RoundTrips(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := "# comment\n\nclaude\t\ncodex\t/usr/local/bin/codex\nrustup\t/home/pipelock-agent/.cargo/bin/rustup\n"
	if err := os.WriteFile(env.toolsListPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readToolsList(env)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("entries: got %d, want 3 (got %+v)", len(got), got)
	}
	if got[0].name != "claude" || got[0].target != "" {
		t.Errorf("[0]: %+v", got[0])
	}
	if got[1].name != "codex" || got[1].target != "/usr/local/bin/codex" {
		t.Errorf("[1]: %+v", got[1])
	}
	if got[2].name != testRustup || got[2].target != "/home/pipelock-agent/.cargo/bin/rustup" {
		t.Errorf("[2]: %+v", got[2])
	}
}

func TestReadToolsList_MissingFileSurfacesNotExist(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	_, err := readToolsList(env)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing-file error, got %v", err)
	}
}

func TestUpsertToolEntry_InsertsNew(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Seed the defaults.
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.toolsListPath, []byte(renderDefaultToolsList()), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	changed, err := upsertToolEntry(env, testRustup, "/home/pipelock-agent/.cargo/bin/rustup")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !changed {
		t.Errorf("expected changed=true on insert")
	}
	got, err := readToolsList(env)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	found := false
	for _, e := range got {
		if e.name == testRustup && e.target == "/home/pipelock-agent/.cargo/bin/rustup" {
			found = true
		}
	}
	if !found {
		t.Errorf("rustup not present after upsert: %+v", got)
	}
}

func TestUpsertToolEntry_IdempotentOnIdenticalEntry(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.toolsListPath, []byte(renderDefaultToolsList()), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// claude is already present with empty target.
	changed, err := upsertToolEntry(env, "claude", "")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if changed {
		t.Errorf("expected changed=false on identical entry")
	}
}

func TestUpsertToolEntry_UpdatesExistingTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.toolsListPath, []byte("claude\t\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	changed, err := upsertToolEntry(env, "claude", "/usr/local/bin/claude")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !changed {
		t.Errorf("expected changed=true on target change")
	}
	entries, err := readToolsList(env)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if entries[0].target != "/usr/local/bin/claude" {
		t.Errorf("target not updated: %+v", entries)
	}
}

func TestUpsertToolEntry_BootstrapsDefaultsWhenMissing(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantResolvableDefaultTools(t, env, "claude", "codex")
	changed, err := upsertToolEntry(env, testRustup, "/usr/local/bin/rustup")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !changed {
		t.Errorf("expected changed=true on bootstrap")
	}
	entries, err := readToolsList(env)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	names := map[string]bool{}
	for _, entry := range entries {
		names[entry.name] = true
	}
	for _, want := range []string{"claude", "codex", testRustup} {
		if !names[want] {
			t.Fatalf("tools.list missing %q after bootstrap: %+v", want, entries)
		}
	}
}

func TestStepWriteToolsList_SeedsDefaults(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantResolvableDefaultTools(t, env, "claude", "codex")
	s := stepWriteToolsList()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Errorf("first apply should write file")
	}
	body, err := os.ReadFile(env.toolsListPath) //nolint:gosec // tmpdir-scoped
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, name := range []string{"claude", "codex"} {
		if !strings.Contains(string(body), name+"\t/usr/local/bin/"+name+"\n") {
			t.Errorf("tools.list missing %q", name)
		}
	}
	if strings.Contains(string(body), "playwright") {
		t.Errorf("tools.list included unresolved playwright:\n%s", body)
	}
}

func TestStepWriteToolsList_IdempotentReapply(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantResolvableDefaultTools(t, env, "claude")
	s := stepWriteToolsList()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if applied {
		t.Errorf("expected idempotent skip on rerun")
	}
}

func TestStepWriteToolsList_PreservesCustomEntries(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantResolvableDefaultTools(t, env, "claude")
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	custom := renderToolsList([]toolsListEntry{
		{name: "claude", target: "/usr/local/bin/claude"},
		{name: "rustup", target: "/tmp/rustup"},
	})
	if err := os.WriteFile(env.toolsListPath, []byte(custom), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := stepWriteToolsList()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Fatal("expected no-op when defaults and custom entries are present")
	}
	body, err := os.ReadFile(env.toolsListPath) //nolint:gosec // tmpdir-scoped
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "rustup\t/tmp/rustup\n") {
		t.Fatalf("custom entry was not preserved:\n%s", body)
	}
}

func TestStepWriteToolsList_AddsMissingDefaultWithoutDroppingCustom(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	plantResolvableDefaultTools(t, env, "claude", "codex", "gemini")
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.toolsListPath, []byte("rustup\t/tmp/rustup\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := stepWriteToolsList()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected missing defaults to be added")
	}
	body, err := os.ReadFile(env.toolsListPath) //nolint:gosec // tmpdir-scoped
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "rustup\t/tmp/rustup\n") {
		t.Fatalf("custom entry was dropped:\n%s", body)
	}
	for _, name := range []string{"claude", "codex", "gemini"} {
		if !strings.Contains(string(body), name+"\t/usr/local/bin/"+name+"\n") {
			t.Fatalf("default %q missing after merge:\n%s", name, body)
		}
	}
	if strings.Contains(string(body), "playwright") {
		t.Fatalf("unresolved default present after merge:\n%s", body)
	}
}

func plantResolvableDefaultTools(t *testing.T, env *installEnv, names ...string) {
	t.Helper()
	targets := make(map[string]string, len(names))
	for _, name := range names {
		target, err := os.Executable()
		if err != nil {
			t.Fatalf("locate test executable: %v", err)
		}
		targets["/usr/local/bin/"+name] = target
	}
	origStat := env.stat
	env.stat = func(path string) (os.FileInfo, error) {
		if target, ok := targets[path]; ok {
			return origStat(target)
		}
		if strings.HasPrefix(path, "/home/"+env.agentUserName+"/.local/bin/") ||
			strings.HasPrefix(path, "/usr/local/bin/") ||
			strings.HasPrefix(path, "/usr/bin/") ||
			strings.HasPrefix(path, "/bin/") {
			return nil, os.ErrNotExist
		}
		return origStat(path)
	}
}

func writeScriptFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write script fixture %s: %v", path, err)
	}
}

func TestAddTool_RecordsTargetInToolsList(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeScriptFixture(t, filepath.Join(env.wrapperDir, "plk-launch"), "#!/bin/bash\n")
	// Seed default tools.list so we observe append behaviour, not bootstrap.
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.toolsListPath, []byte(renderDefaultToolsList()), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	target, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test executable: %v", err)
	}
	if err := runAddTool(context.Background(), env, testRustup, addToolOpts{target: target}); err != nil {
		t.Fatalf("addTool: %v", err)
	}
	entries, err := readToolsList(env)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got *toolsListEntry
	for i := range entries {
		if entries[i].name == testRustup {
			got = &entries[i]
		}
	}
	if got == nil {
		t.Fatalf("rustup not in tools.list: %+v", entries)
	}
	if got.target != target {
		t.Errorf("target: got %q, want %q", got.target, target)
	}
}

func TestRollback_RemovesToolsList(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.toolsListPath, []byte("claude\t\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	actions := rollbackActions(rollbackOpts{keepData: true})
	for i := len(actions) - 1; i >= 0; i-- {
		a := actions[i]
		if a.undo == nil {
			continue
		}
		_ = a.undo(context.Background(), env)
	}
	if _, err := os.Stat(env.toolsListPath); err == nil {
		t.Errorf("tools.list not removed")
	}
}

// Smoke-test the rendered plk-launch script by spawning a real bash to
// parse + reject malformed input. Skipped when bash is missing (none of
// our supported platforms ship without it, but CI containers vary).
func TestRenderedCCLaunch_ParsesUnderBash(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash unavailable")
	}
	env, _, _ := newFakeEnv(t)
	tmp := t.TempDir()
	scriptPath := filepath.Join(tmp, "plk-launch")
	writeScriptFixture(t, scriptPath, renderLaunchWrapper(env))
	// bash -n parses without executing. Any syntax error fails the test.
	cmd := execRealCommand(t, "/bin/bash", "-n", scriptPath)
	if cmd.exit != 0 {
		t.Fatalf("bash -n rejected plk-launch:\n%s\n--- script ---\n%s", cmd.output, renderLaunchWrapper(env))
	}
}

// TestRenderedCCLaunch_ExecutesUnderBash exercises the rendered plk-launch
// against a real bash with controlled inputs and asserts each documented
// exit code path is reachable. This is the test that would have caught a
// silent allow-list bypass before live install - the Go-side unit tests
// can't, because they don't run the script as bash sees it.
func TestRenderedCCLaunch_ExecutesUnderBash(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash unavailable")
	}
	env, _, _ := newFakeEnv(t)
	tmp := t.TempDir()
	scriptPath := filepath.Join(tmp, "plk-launch")
	toolsListPath := filepath.Join(tmp, "tools.list")
	env.toolsListPath = toolsListPath
	writeScriptFixture(t, scriptPath, renderLaunchWrapper(env))
	// Seed an allow-list with one entry pointing at /bin/true so we can
	// exercise the happy path without depending on pipelock-agent's PATH.
	allowList := "claude\t/bin/true\n"
	if err := os.WriteFile(toolsListPath, []byte(allowList), 0o600); err != nil {
		t.Fatalf("write tools.list: %v", err)
	}

	cases := []struct {
		name     string
		argv     []string
		mutate   func()
		wantExit int
	}{
		{name: "no-args-exits-2", argv: nil, wantExit: 2},
		{name: "bad-name-exits-3", argv: []string{"BadName!"}, wantExit: 3},
		{
			name: "missing-list-exits-4",
			argv: []string{"claude"},
			mutate: func() {
				if err := os.Remove(toolsListPath); err != nil {
					t.Fatalf("remove list: %v", err)
				}
			},
			wantExit: 4,
		},
		{name: "not-in-list-exits-5", argv: []string{probe11Sentinel}, wantExit: 5},
		{name: "happy-path-exits-0", argv: []string{"claude"}, wantExit: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Re-seed list before each subtest to undo prior mutations.
			if err := os.WriteFile(toolsListPath, []byte(allowList), 0o600); err != nil {
				t.Fatalf("reseed: %v", err)
			}
			if tc.mutate != nil {
				tc.mutate()
			}
			args := append([]string{scriptPath}, tc.argv...)
			out := execRealCommand(t, "/bin/bash", args...)
			if out.exit != tc.wantExit {
				t.Fatalf("exit: got %d, want %d (output: %s)", out.exit, tc.wantExit, out.output)
			}
		})
	}
}

// execRealCommand runs cmd outside the runner abstraction. Used only for
// the rendered-script smoke test above; this is the one place we need a
// real subprocess and not a fake. Kept tiny on purpose.
type cmdResult struct {
	output string
	exit   int
}

func execRealCommand(t *testing.T, name string, args ...string) cmdResult {
	t.Helper()
	out, code, err := realRunCommand(context.Background(), name, args...)
	if err != nil {
		return cmdResult{output: err.Error(), exit: -1}
	}
	return cmdResult{output: out, exit: code}
}
