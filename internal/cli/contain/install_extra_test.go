// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// Extra coverage for the install step builders that hit error / undo paths
// missed by the happy-path tests in install_test.go.

func TestStepCreateUser_LookupNonUnknownErrorPropagates(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.lookupUser = func(string) (*user.User, error) {
		return nil, errors.New("transient lookup failure")
	}
	s := stepCreateUser(false)
	_, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "user lookup") {
		t.Errorf("err: %v", err)
	}
}

func TestStepCreateUser_UndoSkipsUnknownUser(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.lookupUser = func(name string) (*user.User, error) {
		return nil, user.UnknownUserError(name)
	}
	s := stepCreateUser(true)
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	for _, c := range runner.calls {
		if c.name == testUserDel {
			t.Errorf("userdel called on missing user: %v", c)
		}
	}
}

func TestStepCreateDir_AppliedThenUndoIsNoop(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "newdir")
	s := stepCreateDir("test", func(*installEnv) string { return target }, modeDirSystem)
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Errorf("first apply should create dir")
	}
	// Second apply: dir exists, skip.
	applied, err = s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if applied {
		t.Errorf("second apply should skip")
	}
	// Undo: empty dir gets removed.
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
}

func TestStepCreateDir_RejectsExistingFile(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	s := stepCreateDir("test", func(*installEnv) string { return target }, modeDirSystem)
	_, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("err: %v", err)
	}
}

func TestStepWritePipelockConfig_CopiesFromSource(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	src := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(src, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	opts := installOpts{configSource: src}
	s := stepWritePipelockConfig(opts)
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Errorf("expected applied=true when source given and dest missing")
	}
	dst := filepath.Join(env.configDir, "pipelock.yaml")
	got, _ := os.ReadFile(dst) //nolint:gosec // tmpdir-scoped test path
	if string(got) != "mode: balanced\n" {
		t.Errorf("dst: %q", got)
	}
}

func TestStepWritePipelockConfig_SkipsWhenNoSource(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	s := stepWritePipelockConfig(installOpts{})
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Errorf("expected skip when --config not set")
	}
}

func TestStepWritePipelockConfig_SkipsWhenIdentical(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	src := filepath.Join(t.TempDir(), "src.yaml")
	body := []byte("mode: balanced\n")
	if err := os.WriteFile(src, body, 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	dst := filepath.Join(env.configDir, "pipelock.yaml")
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatalf("write dst: %v", err)
	}
	s := stepWritePipelockConfig(installOpts{configSource: src})
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Errorf("expected skip when src and dst contents match")
	}
}

func TestStepWritePipelockConfig_OverwritesAndWarnsOnDifference(t *testing.T) {
	env, _, buf := newFakeEnv(t)
	src := filepath.Join(t.TempDir(), "new.yaml")
	if err := os.WriteFile(src, []byte("mode: strict\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	dst := filepath.Join(env.configDir, "pipelock.yaml")
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := stepWritePipelockConfig(installOpts{configSource: src})
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Errorf("expected overwrite when --config differs")
	}
	got, _ := os.ReadFile(dst) //nolint:gosec // tmpdir-scoped test path
	if string(got) != "mode: strict\n" {
		t.Errorf("dst not overwritten: %q", got)
	}
	bak, _ := os.ReadFile(dst + ".bak") //nolint:gosec // tmpdir-scoped test path
	if string(bak) != "mode: balanced\n" {
		t.Errorf("backup missing prior content: %q", bak)
	}
	if !strings.Contains(buf.String(), "WARN: --config") {
		t.Errorf("expected warning in output, got %q", buf.String())
	}
}

func TestStepChownToProxy_CallsChownPerFile(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(env.configDir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	chownCalls := 0
	env.chown = func(string, int, int) error {
		chownCalls++
		return nil
	}
	s := stepChownToProxy("config", func(e *installEnv) string { return e.configDir })
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if chownCalls < 2 {
		t.Errorf("expected at least 2 chown calls (dir + file), got %d", chownCalls)
	}
}

func TestStepStopUserService_NoOpWhenNoOperator(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.operatorUser = ""
	s := stepStopUserService()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Errorf("expected skip when operator user empty")
	}
	if len(runner.calls) != 0 {
		t.Errorf("expected no shell-out, got %v", runner.calls)
	}
}

func TestStepStopUserService_StopsWhenActive(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// runCmd returns "active" for is-active.
	runner.on(argvFor(testSystemctl, "--user", "-M", "operator@.host", "is-active", "pipelock"), "active\n", 0, nil)
	s := stepStopUserService()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Errorf("expected applied=true when active")
	}
	var sawStop bool
	for _, c := range runner.calls {
		if c.name == testSystemctl && containsArg(c.args, "stop") {
			sawStop = true
		}
	}
	if !sawStop {
		t.Errorf("expected systemctl stop, got %v", runner.calls)
	}
}

func TestStepEnableSystemUnit_SkipsWhenActive(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
	runner.on(argvFor(testSystemctl, "is-active", "pipelock"), "active\n", 0, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", "pipelock"), "enabled\n", 0, nil)
	s := stepEnableSystemUnit()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Errorf("expected skip when unit already active")
	}
}

func TestStepEnableSystemUnit_EnablesWhenActiveButDisabled(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
	runner.on(argvFor(testSystemctl, "is-active", "pipelock"), "active\n", 0, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", "pipelock"), "disabled\n", 1, nil)
	s := stepEnableSystemUnit()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected apply=true when active but disabled")
	}
	var sawEnable bool
	for _, c := range runner.calls {
		if c.name == testSystemctl && containsArg(c.args, "enable") {
			sawEnable = true
		}
	}
	if !sawEnable {
		t.Errorf("expected systemctl enable, got %v", runner.calls)
	}
}

func TestStepEnableSystemUnit_EnablesWhenInactive(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	s := stepEnableSystemUnit()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var sawEnable bool
	for _, c := range runner.calls {
		if c.name == testSystemctl && containsArg(c.args, "enable") {
			sawEnable = true
		}
	}
	if !sawEnable {
		t.Errorf("expected systemctl enable, got %v", runner.calls)
	}
}

func TestStepEnableSystemUnit_UndoDisables(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	s := stepEnableSystemUnit()
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	var sawDisable bool
	for _, c := range runner.calls {
		if c.name == testSystemctl && containsArg(c.args, "disable") {
			sawDisable = true
		}
	}
	if !sawDisable {
		t.Errorf("expected systemctl disable in undo, got %v", runner.calls)
	}
}

func TestStepEnableSystemUnit_UndoRestoresPreviouslyEnabledInactive(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
	runner.on(argvFor(testSystemctl, "is-active", "pipelock"), "inactive\n", 3, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", "pipelock"), "enabled\n", 0, nil)
	s := stepEnableSystemUnit()
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
	var sawStop, sawDisable bool
	for _, c := range runner.calls {
		if c.name == testSystemctl && len(c.args) > 0 && c.args[0] == "stop" {
			sawStop = true
		}
		if c.name == testSystemctl && len(c.args) > 0 && c.args[0] == "disable" {
			sawDisable = true
		}
	}
	if !sawStop {
		t.Fatalf("expected undo to stop previously inactive unit, calls=%v", runner.calls)
	}
	if sawDisable {
		t.Fatalf("undo disabled previously enabled unit, calls=%v", runner.calls)
	}
}

func TestStepEnableSystemUnit_UndoRestoresPreviouslyActiveDisabled(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
	runner.on(argvFor(testSystemctl, "is-active", "pipelock"), "active\n", 0, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", "pipelock"), "disabled\n", 1, nil)
	s := stepEnableSystemUnit()
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
	var sawDisable, sawStop bool
	for _, c := range runner.calls {
		if c.name == testSystemctl && len(c.args) > 0 && c.args[0] == "disable" {
			sawDisable = true
		}
		if c.name == testSystemctl && len(c.args) > 0 && c.args[0] == "stop" {
			sawStop = true
		}
	}
	if !sawDisable {
		t.Fatalf("expected undo to disable previously disabled unit, calls=%v", runner.calls)
	}
	if sawStop {
		t.Fatalf("undo stopped previously active unit, calls=%v", runner.calls)
	}
}

func TestStepExportPipelockCA_SkipsWhenAlreadyPresent(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.caExportPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.caExportPath, []byte("CA"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := stepExportPipelockCA()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Errorf("expected skip when ca.pem present")
	}
	if len(runner.calls) != 0 {
		t.Errorf("no shell-out expected, got %v", runner.calls)
	}
}

func TestStepExportPipelockCA_ExportsViaSudo(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Stub show-ca to return a PEM.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		runner.mu.Lock()
		runner.calls = append(runner.calls, fakeCall{name: name, args: append([]string(nil), args...)})
		runner.mu.Unlock()
		if name == testSudoCmd && containsArg(args, "show-ca") {
			return testPEMCA(t), 0, nil
		}
		return "", 0, nil
	}
	s := stepExportPipelockCA()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("expected 1 call, got %v", runner.calls)
	}
	if runner.calls[0].name != testSudoCmd {
		t.Errorf("expected sudo, got %s", runner.calls[0].name)
	}
}

func TestStepWriteCombinedCABundle_FailsWhenCAMissing(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// System bundle is plumbed by newFakeEnv. caExportPath is NOT planted,
	// so the read must fail.
	s := stepWriteCombinedCABundle()
	_, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatal("expected error on missing pipelock CA")
	}
	if !strings.Contains(err.Error(), "read pipelock CA") {
		t.Errorf("err: %v", err)
	}
}

func TestStepWriteCombinedCABundle_Succeeds(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.caExportPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.caExportPath, []byte("PIPE_CA"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := stepWriteCombinedCABundle()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Errorf("expected applied=true on first run")
	}
	got, _ := os.ReadFile(env.caBundlePath)
	if !strings.Contains(string(got), "PIPE_CA") {
		t.Errorf("bundle missing pipelock CA: %q", got)
	}
	if !strings.Contains(string(got), "system bundle") {
		t.Errorf("bundle missing system root marker: %q", got)
	}
}

func TestStepWriteLaunchWrapper_IdempotentAndUndoable(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	s := stepWriteLaunchWrapper()
	a1, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !a1 {
		t.Errorf("first apply should write")
	}
	a2, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if a2 {
		t.Errorf("second apply should skip")
	}
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
}

func TestStepInstallNFTRules_UndoDropsTable(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	s := stepInstallNFTRules()
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	var sawDelete bool
	for _, c := range runner.calls {
		if c.name == testNFT && containsArg(c.args, "delete") && containsArg(c.args, "pipelock_containment") {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Errorf("expected nft delete table in undo, got %v", runner.calls)
	}
}

func TestStepInstallNFTRules_ValidationFailureSurfaces(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Force nft validate to fail.
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "", 1, fmt.Errorf("not loaded"))
	runner.on(argvFor(testNFT, "-c", "-f", env.nftRulesPath), "syntax error", 1, nil)
	s := stepInstallNFTRules()
	_, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("err: %v", err)
	}
}

func TestRollbackApplied_HandlesUndoFailureNonFatally(t *testing.T) {
	env, _, out := newFakeEnv(t)
	applied := []step{
		{
			name: "ok", desc: "ok",
			undo: func(context.Context, *installEnv) error { return nil },
		},
		{
			name: "boom", desc: "boom",
			undo: func(context.Context, *installEnv) error { return errors.New("kaboom") },
		},
	}
	// applied[0] was first; rollbackApplied walks in reverse: boom then ok.
	rollbackApplied(context.Background(), env, out, applied)
	got := out.String()
	if !strings.Contains(got, "[FAIL] undo boom") {
		t.Errorf("missing fail line for boom: %q", got)
	}
	if !strings.Contains(got, "[ OK ] undo ok") {
		t.Errorf("missing ok line for ok: %q", got)
	}
}

func TestRollbackApplied_HandlesEmptySliceAsNoop(t *testing.T) {
	env, _, out := newFakeEnv(t)
	rollbackApplied(context.Background(), env, out, nil)
	if out.Len() != 0 {
		t.Errorf("expected no output: %q", out.String())
	}
}

func TestRollbackApplied_SkipsStepsWithNilUndo(t *testing.T) {
	env, _, out := newFakeEnv(t)
	applied := []step{{name: "nostep", desc: "nostep", undo: nil}}
	rollbackApplied(context.Background(), env, out, applied)
	if !strings.Contains(out.String(), "[SKIP] undo nostep") {
		t.Errorf("expected skip line: %q", out.String())
	}
}

func TestResolveUIDs_BothLookupsSucceed(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	pUID, aUID, err := resolveUIDs(env)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pUID != 988 || aUID != 987 {
		t.Errorf("UIDs: proxy=%d agent=%d", pUID, aUID)
	}
}

func TestResolveUIDs_AgentLookupErrorPropagates(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.lookupUser = func(name string) (*user.User, error) {
		if name == "pipelock-agent" {
			return nil, errors.New("nope")
		}
		return &user.User{Uid: "988", Gid: "988"}, nil
	}
	if _, _, err := resolveUIDs(env); err == nil {
		t.Fatal("expected error")
	}
}

func TestOperatorUIDFromEnv_ErrorsWhenUnset(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.operatorUser = ""
	if _, err := operatorUIDFromEnv(env); err == nil {
		t.Fatal("expected error when operatorUser empty")
	}
}

func TestProbeBinaryIntegrity_SkipsWhenPinAbsent(t *testing.T) {
	env := makeProbeEnv(t)
	env.pinPath = filepath.Join(t.TempDir(), "absent")
	env.readFile = os.ReadFile
	env.selfPath = func() (string, error) { return "/bin/ls", nil }
	status, _ := probeBinaryIntegrity(context.Background(), env)
	if status != statusSkip {
		t.Errorf("status: %s, want skip", status)
	}
}

func TestProbeBinaryIntegrity_FailsOnMismatch(t *testing.T) {
	env := makeProbeEnv(t)
	tmp := t.TempDir()
	pinPath := filepath.Join(tmp, "pin")
	if err := os.WriteFile(pinPath, []byte("0000000000000000000000000000000000000000000000000000000000000000\n"), 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	env.pinPath = pinPath
	env.readFile = os.ReadFile
	env.selfPath = func() (string, error) { return "/bin/ls", nil }
	env.hashFile = func(string) (string, error) {
		return "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", nil
	}
	status, detail := probeBinaryIntegrity(context.Background(), env)
	if status != statusFail {
		t.Errorf("status: %s, want fail", status)
	}
	if !strings.Contains(detail, "mismatch") {
		t.Errorf("detail: %s", detail)
	}
}

func TestProbeBinaryIntegrity_FailsOnCorruptedPin(t *testing.T) {
	env := makeProbeEnv(t)
	pinPath := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(pinPath, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	env.pinPath = pinPath
	env.readFile = os.ReadFile
	status, detail := probeBinaryIntegrity(context.Background(), env)
	if status != statusFail {
		t.Errorf("status: %s, want fail (empty pin is corrupted)", status)
	}
	if !strings.Contains(detail, "empty") {
		t.Errorf("detail: %s", detail)
	}
}

func TestProbeBinaryIntegrity_FailsOnMalformedPin(t *testing.T) {
	env := makeProbeEnv(t)
	pinPath := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(pinPath, []byte("short\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	env.pinPath = pinPath
	env.readFile = os.ReadFile
	status, detail := probeBinaryIntegrity(context.Background(), env)
	if status != statusFail {
		t.Errorf("status: %s, want fail (malformed pin is corrupted)", status)
	}
	if !strings.Contains(detail, "malformed") {
		t.Errorf("detail: %s", detail)
	}
}

func TestActionRemovePath_RemovesFileAndBak(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(target+".bak", []byte("y"), 0o600); err != nil {
		t.Fatalf("write bak: %v", err)
	}
	a := actionRemovePath("test", func(*installEnv) string { return target })
	if err := a.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Errorf("target not removed")
	}
	if _, err := os.Stat(target + ".bak"); err == nil {
		t.Errorf("bak not removed")
	}
}

func TestActionRemoveSystemUnit_RemovesAndReloads(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.systemUnitPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.systemUnitPath, []byte("unit"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := actionRemoveSystemUnit()
	if err := a.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if _, err := os.Stat(env.systemUnitPath); err == nil {
		t.Errorf("unit not removed")
	}
	var sawReload bool
	for _, c := range runner.calls {
		if c.name == testSystemctl && containsArg(c.args, "daemon-reload") {
			sawReload = true
		}
	}
	if !sawReload {
		t.Errorf("expected daemon-reload, got %v", runner.calls)
	}
}

func TestActionDisablePipelockService_SkipsWhenAbsent(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// runCmd default returns ("", 0, nil) for unmatched calls, but we want
	// list-unit-files to return code 0 with empty output (meaning unit not
	// known). The default behavior already does that.
	a := actionDisablePipelockService()
	if err := a.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	for _, c := range runner.calls {
		if c.name == testSystemctl && containsArg(c.args, "disable") {
			t.Errorf("disable called despite unit being absent: %v", c)
		}
	}
}

func TestActionRemoveNFTRules_DropsAndCleans(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte("rules"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(env.nftRulesPath+".bak", []byte("bak"), 0o600); err != nil {
		t.Fatalf("write bak: %v", err)
	}
	a := actionRemoveNFTRules()
	if err := a.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	var sawDelete bool
	for _, c := range runner.calls {
		if c.name == testNFT && containsArg(c.args, "delete") {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Errorf("expected nft delete in undo, got %v", runner.calls)
	}
	if _, err := os.Stat(env.nftRulesPath); err == nil {
		t.Errorf("rules file not removed")
	}
	if _, err := os.Stat(env.nftRulesPath + ".bak"); err == nil {
		t.Errorf("bak not removed")
	}
}

func TestRenderCredentialGuardScriptLocksCredentialNames(t *testing.T) {
	body := renderCredentialGuardScript("pipelock-agent", "/home/operator")
	for _, want := range []string{
		"AGENT_USER='pipelock-agent'",
		"lock_home_root '/home/operator'",
		"lock_matches \"$1\" -maxdepth 1",
		"setfacl -m \"u:${AGENT_USER}:--x\" \"$root\"",
		"-name auth.json",
		"-name .claude.json",
		"-name .credentials.json",
		"-name '*.token'",
		"setfacl -x \"u:${AGENT_USER}\"",
		"chmod 0600",
		"lock_config_root '/home/operator/.codex'",
	} {
		want := want
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(body, want) {
				t.Fatalf("credential guard script missing %q:\n%s", want, body)
			}
		})
	}
}

func TestStepWriteCredentialGuardWritesAndEnablesPathUnit(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	step := stepWriteCredentialGuard()
	changed, err := step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply credential guard: %v", err)
	}
	if !changed {
		t.Fatal("expected credential guard apply to report changed")
	}
	for _, path := range []string{env.guardScriptPath, env.guardServiceUnit, env.guardPathUnit} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s written: %v", path, err)
		}
	}
	pathUnit, err := os.ReadFile(env.guardPathUnit)
	if err != nil {
		t.Fatalf("read path unit: %v", err)
	}
	for _, want := range []string{
		"PathChanged=/home/operator",
		"PathModified=/home/operator/.claude.json",
		"PathExistsGlob=/home/operator/*.token",
		"PathChanged=/home/operator/.codex",
	} {
		want := want
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(string(pathUnit), want) {
				t.Fatalf("path unit missing %q:\n%s", want, string(pathUnit))
			}
		})
	}
	if len(runner.calls) < 3 {
		t.Fatalf("credential guard calls = %v, want guard run, daemon-reload, and enable", runner.calls)
	}
	if runner.calls[len(runner.calls)-3].name != env.guardScriptPath {
		t.Fatalf("missing initial credential guard run: %+v", runner.calls)
	}
	if runner.calls[len(runner.calls)-2].name != testSystemctl ||
		!containsArg(runner.calls[len(runner.calls)-2].args, "daemon-reload") {
		t.Fatalf("missing daemon-reload call: %+v", runner.calls)
	}
	if runner.calls[len(runner.calls)-1].name != testSystemctl ||
		!containsArg(runner.calls[len(runner.calls)-1].args, "enable") ||
		!containsArg(runner.calls[len(runner.calls)-1].args, "--now") ||
		!containsArg(runner.calls[len(runner.calls)-1].args, "pipelock-cred-guard.path") {
		t.Fatalf("missing enable --now path unit call: %+v", runner.calls)
	}
}
