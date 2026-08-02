// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// applyStagePromote drives the two steps the installer runs around the config
// preflight. Production never applies one without the other, so tests that
// assert on the managed config must drive both.
func applyStagePromote(t *testing.T, env *installEnv, opts installOpts) bool {
	t.Helper()
	if _, err := stepStagePipelockConfig(opts).apply(context.Background(), env); err != nil {
		t.Fatalf("stage: %v", err)
	}
	// Staging always reports a mutation when --config is set, so the managed
	// config's fate is the promote step's verdict.
	promoted, err := stepPromotePipelockConfig(opts).apply(context.Background(), env)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	return promoted
}

func TestStepWritePipelockConfig_CopiesFromSource(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	src := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(src, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	opts := installOpts{configSource: src}
	applied := applyStagePromote(t, env, opts)
	if !applied {
		t.Errorf("expected applied=true when source given and dest missing")
	}
	dst := filepath.Join(env.configDir, "pipelock.yaml")
	got, _ := os.ReadFile(dst) //nolint:gosec // tmpdir-scoped test path
	if string(got) != "mode: balanced\nmetrics_listen: 127.0.0.1:9091\n" {
		t.Errorf("dst: %q", got)
	}
}

func TestStepWritePipelockConfig_SkipsWhenNoSource(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	applied := applyStagePromote(t, env, installOpts{})
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
	if err := os.WriteFile(dst, []byte("mode: balanced\nmetrics_listen: 127.0.0.1:9091\n"), 0o600); err != nil {
		t.Fatalf("write dst: %v", err)
	}
	applied := applyStagePromote(t, env, installOpts{configSource: src})
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
	applied := applyStagePromote(t, env, installOpts{configSource: src})
	if !applied {
		t.Errorf("expected overwrite when --config differs")
	}
	got, _ := os.ReadFile(dst) //nolint:gosec // tmpdir-scoped test path
	if string(got) != "mode: strict\nmetrics_listen: 127.0.0.1:9091\n" {
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

func TestStepWaitPipelockReadyFailsWhenServiceExited(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.dialCtx = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	runner.on("systemctl show pipelock.service --property=ActiveState,SubState",
		"ActiveState=failed\nSubState=failed\n", 0, nil)

	applied, err := stepWaitPipelockReady().apply(t.Context(), env)
	if applied {
		t.Fatal("readiness step reported a mutation")
	}
	if err == nil || !strings.Contains(err.Error(), "service exited before readiness") {
		t.Fatalf("readiness error = %v, want exited-service refusal", err)
	}
}

func TestStepWaitPipelockReadyUsesInstallBudget(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on("systemctl show pipelock.service --property=ActiveState,SubState",
		"ActiveState=active\nSubState=running\n", 0, nil)
	attempts := 0
	env.dialCtx = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		attempts++
		if attempts > int(readinessTimeout/readinessInterval)+1 {
			return &fakeConn{}, nil
		}
		return nil, errors.New("connection refused")
	}

	applied, err := stepWaitPipelockReady().apply(t.Context(), env)
	if err != nil {
		t.Fatalf("readiness with slow healthy startup: %v", err)
	}
	if applied {
		t.Fatal("readiness step reported a mutation")
	}
	if attempts <= int(readinessTimeout/readinessInterval)+1 {
		t.Fatalf("dial attempts = %d, want beyond diagnostic budget", attempts)
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

func TestStepEnableSystemUnit_RestartsActiveServiceAfterRuntimeChange(t *testing.T) {
	for _, changed := range []struct {
		name  string
		apply func(*installEnv)
	}{
		{name: "binary", apply: func(env *installEnv) { env.serviceBinaryChanged = true }},
		{name: "config", apply: func(env *installEnv) { env.serviceConfigChanged = true }},
		{name: "unit", apply: func(env *installEnv) { env.serviceUnitChanged = true }},
	} {
		t.Run(changed.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			changed.apply(env)
			runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
			runner.on(argvFor(testSystemctl, "is-active", "pipelock"), "active\n", 0, nil)
			runner.on(argvFor(testSystemctl, "is-enabled", "pipelock"), "enabled\n", 0, nil)
			runner.on(argvFor(testSystemctl, "restart", "pipelock"), "", 0, nil)

			applied, err := stepEnableSystemUnit().apply(context.Background(), env)
			if err != nil || !applied {
				t.Fatalf("apply = %v, %v; want true, nil", applied, err)
			}
			if !runnerSawSystemctl(runner, "restart", "pipelock") {
				t.Fatalf("changed %s did not restart active service: %v", changed.name, runner.calls)
			}
		})
	}
}

func TestStepEnableSystemUnit_ActiveDisabledChangeEnablesAndRestarts(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.serviceBinaryChanged = true
	runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
	runner.on(argvFor(testSystemctl, "is-active", "pipelock"), "active\n", 0, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", "pipelock"), "disabled\n", 1, nil)

	applied, err := stepEnableSystemUnit().apply(context.Background(), env)
	if err != nil || !applied {
		t.Fatalf("apply = %v, %v; want true, nil", applied, err)
	}
	if !runnerSawSystemctl(runner, "enable", "pipelock") || !runnerSawSystemctl(runner, "restart", "pipelock") {
		t.Fatalf("active disabled changed service was not enabled and restarted: %v", runner.calls)
	}
	if runnerSawSystemctl(runner, "enable", "--now", "pipelock") {
		t.Fatalf("active service should not use enable --now: %v", runner.calls)
	}
}

func TestStepEnableSystemUnit_ActiveDisabledReportsEnableFailure(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.serviceBinaryChanged = true
	runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
	runner.on(argvFor(testSystemctl, "is-active", "pipelock"), "active\n", 0, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", "pipelock"), "disabled\n", 1, nil)
	runner.on(argvFor(testSystemctl, "enable", "pipelock"), "failed", 1, errors.New("enable failed"))

	if applied, err := stepEnableSystemUnit().apply(t.Context(), env); err == nil || !applied {
		t.Fatalf("apply = %v, %v; want true, error", applied, err)
	}
}

func TestRenderSystemUnit_FileSentryHomeIsNarrowlyVisibleReadOnly(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.serviceReadOnlyPaths = []string{"/home/operator/project", "/home/operator/project with spaces"}
	body := renderSystemUnit(env)
	if !strings.Contains(body, "ProtectHome=tmpfs") {
		t.Fatalf("system unit does not hide unlisted home paths:\n%s", body)
	}
	for _, want := range []string{`BindReadOnlyPaths=-"/home/operator/project"`, `BindReadOnlyPaths=-"/home/operator/project with spaces"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("system unit missing %q:\n%s", want, body)
		}
	}
}

func TestRenderSystemUnit_WithoutFileSentryKeepsHomeInaccessible(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderSystemUnit(env)
	if !strings.Contains(body, "ProtectHome=true") || strings.Contains(body, "BindReadOnlyPaths=") {
		t.Fatalf("system unit weakens home isolation without file-sentry paths:\n%s", body)
	}
}

func TestRenderSystemUnit_FileSentryPrivateTmpPathIsVisibleReadOnly(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.serviceReadOnlyPaths = []string{"/tmp/pipelock-watch", "/var/tmp/pipelock-watch"}
	body := renderSystemUnit(env)
	if !strings.Contains(body, "ProtectHome=true") {
		t.Fatalf("system unit weakens home isolation for tmp-only paths:\n%s", body)
	}
	for _, want := range []string{`BindReadOnlyPaths=-"/tmp/pipelock-watch"`, `BindReadOnlyPaths=-"/var/tmp/pipelock-watch"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("system unit missing %q:\n%s", want, body)
		}
	}
}

func TestChangedRuntimeArtifacts_RollbackRestoresAndRestartsPriorService(t *testing.T) {
	t.Run("binary", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		if err := os.WriteFile(filepath.Clean(env.pipelockTarget), []byte("old binary"), 0o600); err != nil {
			t.Fatalf("WriteFile old binary: %v", err)
		}
		step := stepInstallPipelockBinary()
		if applied, err := step.apply(context.Background(), env); err != nil || !applied {
			t.Fatalf("apply = %v, %v", applied, err)
		}
		env.installServiceStateKnown = true
		env.installServiceWasActive = true
		if err := step.undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		assertRestoredFileAndRestart(t, env.pipelockTarget, "old binary", runner)
	})

	t.Run("config", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		managed := managedPipelockConfigPath(env)
		if err := os.WriteFile(managed, []byte("old config"), 0o600); err != nil {
			t.Fatalf("WriteFile old config: %v", err)
		}
		if err := os.WriteFile(stagedPipelockConfigPath(env), []byte("new config"), 0o600); err != nil {
			t.Fatalf("WriteFile staged config: %v", err)
		}
		step := stepPromotePipelockConfig(installOpts{configSource: "/candidate.yaml"})
		if applied, err := step.apply(context.Background(), env); err != nil || !applied {
			t.Fatalf("apply = %v, %v", applied, err)
		}
		env.installServiceStateKnown = true
		env.installServiceWasActive = true
		if err := step.undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		assertRestoredFileAndRestart(t, managed, "old config", runner)
	})

	t.Run("unit", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		if err := os.WriteFile(env.systemUnitPath, []byte("old unit"), 0o600); err != nil {
			t.Fatalf("WriteFile old unit: %v", err)
		}
		step := stepWriteSystemUnit()
		if applied, err := step.apply(context.Background(), env); err != nil || !applied {
			t.Fatalf("apply = %v, %v", applied, err)
		}
		env.installServiceStateKnown = true
		env.installServiceWasActive = true
		if err := step.undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		assertRestoredFileAndRestart(t, env.systemUnitPath, "old unit", runner)
		if !runnerSawSystemctl(runner, "daemon-reload") {
			t.Fatalf("unit rollback did not reload systemd: %v", runner.calls)
		}
	})
}

func assertRestoredFileAndRestart(t *testing.T, path, want string, runner *fakeRunner) {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile restored artifact: %v", err)
	}
	if string(got) != want {
		t.Fatalf("restored artifact = %q, want %q", got, want)
	}
	if !runnerSawSystemctl(runner, "restart", "pipelock") {
		t.Fatalf("rollback did not restart prior active service: %v", runner.calls)
	}
}

func runnerSawSystemctl(runner *fakeRunner, args ...string) bool {
	for _, call := range runner.calls {
		if call.name == testSystemctl && strings.Join(call.args, "\x00") == strings.Join(args, "\x00") {
			return true
		}
	}
	return false
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

func TestStepInstallNFTRules_UndoDoesNotRestoreNewlyCreatedTable(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, nil)
	runner.on(argvFor(testNFT, "-c", "-f", env.nftRulesPath), "", 0, nil)
	runner.on(argvFor(testNFT, "-f", env.nftRulesPath), "", 0, nil)
	runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
	runner.on(argvFor(testSystemctl, "enable", filepath.Base(env.nftPersistUnitPath)), "", 0, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.nftPersistUnitPath)), "disabled\n", 1, nil)

	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected nft rules to apply")
	}
	if !env.prevNFTTableStateKnown {
		t.Fatal("previous absent nft table state was not captured")
	}
	if env.prevNFTTableDump != "" {
		t.Fatalf("expected no previous table dump, got %q", env.prevNFTTableDump)
	}

	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	restorePath := env.nftRulesPath + ".restore"
	for _, c := range runner.calls {
		if c.name == testNFT && len(c.args) == 2 && c.args[0] == "-f" && c.args[1] == restorePath {
			t.Fatalf("undo restored a table that did not exist before install: %v", runner.calls)
		}
	}
}

func TestStepInstallNFTRules_ValidationFailureSurfaces(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Force nft validate to fail.
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, fmt.Errorf("not loaded"))
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

// An uppercase pin is valid hex and the right length, but hashFile returns a
// lowercase digest, so it could never match. Reporting it as a hash mismatch
// would read as a swapped binary and send an operator hunting a compromise that
// did not happen, so it must be reported as a malformed pin instead. hashFile is
// left unstubbed so the test also proves the pin is rejected before any hashing.
func TestProbeBinaryIntegrity_UppercasePinIsMalformedNotMismatch(t *testing.T) {
	env := makeProbeEnv(t)
	pinPath := filepath.Join(t.TempDir(), "pin")
	upper := strings.ToUpper(strings.Repeat("ab", 32))
	if err := os.WriteFile(pinPath, []byte(upper+"\n"), 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	env.pinPath = pinPath
	env.readFile = os.ReadFile

	status, detail := probeBinaryIntegrity(context.Background(), env)
	if status != statusFail {
		t.Fatalf("status = %s, want fail", status)
	}
	if !strings.Contains(detail, "malformed") {
		t.Errorf("detail = %q, want it to name the pin as malformed", detail)
	}
	if strings.Contains(detail, "mismatch") || strings.Contains(detail, "unstubbed") {
		t.Errorf("detail = %q, must reject the pin before hashing anything", detail)
	}
}

// A stat failure leaves file identity unknown rather than different. Reporting a
// difference there would assert something unverified, which is the exact class of
// overstatement this probe was changed to stop making. Each lookup is failed
// independently, because either one alone is enough to leave identity unknown.
func TestProbeBinaryIntegrity_StatFailureReportsUnknownNotDifference(t *testing.T) {
	digest := "cc" + strings.Repeat("0", 62)

	tests := []struct {
		name string
		fail string // which path's stat fails
	}{
		{name: "deployed binary stat fails", fail: "target"},
		{name: "invoking binary stat fails", fail: "self"},
		{name: "both stats fail", fail: "both"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := makeProbeEnv(t)
			dir := t.TempDir()

			target := filepath.Join(dir, "pipelock")
			if err := os.WriteFile(target, []byte("deployed"), 0o600); err != nil {
				t.Fatalf("write target: %v", err)
			}
			self := filepath.Join(dir, "elsewhere")
			if err := os.WriteFile(self, []byte("operator copy"), 0o600); err != nil {
				t.Fatalf("write self: %v", err)
			}

			pinPath := filepath.Join(dir, "pin")
			if err := os.WriteFile(pinPath, []byte(digest+"\n"), 0o600); err != nil {
				t.Fatalf("write pin: %v", err)
			}

			env.pipelockTarget = target
			env.pinPath = pinPath
			env.readFile = os.ReadFile
			env.hashFile = func(string) (string, error) { return digest, nil }
			env.selfPath = func() (string, error) { return self, nil }
			env.stat = func(path string) (os.FileInfo, error) {
				switch tt.fail {
				case "both":
					return nil, errors.New("stat unavailable")
				case "target":
					if path == target {
						return nil, errors.New("stat unavailable")
					}
				case "self":
					if path == self {
						return nil, errors.New("stat unavailable")
					}
				}
				return os.Stat(path)
			}

			status, detail := probeBinaryIntegrity(context.Background(), env)
			if status != statusPass {
				t.Fatalf("status = %s, want pass (the deployed binary still matches its pin)", status)
			}
			if !strings.Contains(detail, "could not compare") {
				t.Errorf("detail = %q, want it to say the comparison was unavailable", detail)
			}
			if strings.Contains(detail, "differs") {
				t.Errorf("detail = %q, must not assert a difference it did not verify", detail)
			}
		})
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
		if c.name == testNFT && strings.Join(c.args, " ") == "delete table inet "+env.nftTableOrDefault() {
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

// TestActionRemoveNFTRules_CleansLegacyMainInclude proves the rollback
// action actually reaches restoreOrRemoveNFTMainInclude when nftMainPath is
// populated the way defaultInstallEnv now wires it. The pre-portability
// install appended an `include` line to the distro nft config; if rollback
// skips this cleanup, the dangling include breaks the host nftables.service
// at the next boot once the rules file is gone. A direct unit test of the
// cleanup helper (which sets nftMainPath itself) would mask a regression
// where the production env stops wiring the path.
func TestActionRemoveNFTRules_CleansLegacyMainInclude(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Mirror defaultInstallEnv wiring: rollback must know the legacy path.
	if defaultInstallEnv(io.Discard).nftMainPath == "" {
		t.Fatal("defaultInstallEnv no longer wires nftMainPath; rollback legacy cleanup is unreachable")
	}
	env.nftMainPath = filepath.Join(t.TempDir(), "nftables.conf")
	if err := os.MkdirAll(filepath.Dir(env.nftMainPath), 0o750); err != nil {
		t.Fatalf("mkdir main config parent: %v", err)
	}
	includeLine := nftRulesIncludeLine(env.nftRulesPath)
	body := "flush ruleset\n\n# Pipelock containment persistence\n" + includeLine + "\n"
	if err := os.WriteFile(env.nftMainPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write legacy main config: %v", err)
	}

	a := actionRemoveNFTRules()
	if err := a.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}

	got, err := os.ReadFile(env.nftMainPath)
	if err != nil {
		t.Fatalf("read legacy main config: %v", err)
	}
	if strings.Contains(string(got), includeLine) {
		t.Fatalf("rollback left dangling legacy include:\n%s", got)
	}
}

func TestRenderCredentialGuardScriptLocksCredentialNames(t *testing.T) {
	body := renderCredentialGuardScript("pipelock-agent", "/home/operator", "/bin/bash")
	for _, want := range []string{
		"AGENT_USER='pipelock-agent'",
		"lock_home_root '/home/operator'",
		"lock_matches \"$1\" -maxdepth 1",
		"setfacl -m \"u:${AGENT_USER}:--x\" \"$root\"",
		"-name 'auth.json'",
		"-name '.claude.json'",
		"-name '.credentials.json'",
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
		"PathChanged=/home/operator\n",
		"PathChanged=/home/operator/auth.json\n",
		"PathChanged=/home/operator/.claude.json\n",
		"PathChanged=/home/operator/.credentials.json\n",
		"PathChanged=/home/operator/.claude\n",
		"PathChanged=/home/operator/.claude/auth.json\n",
		"PathChanged=/home/operator/.claude/.credentials.json\n",
		"PathChanged=/home/operator/.claude-cc2\n",
		"PathChanged=/home/operator/.claude-cc2/.credentials.json\n",
		"PathChanged=/home/operator/.codex\n",
		"PathChanged=/home/operator/.codex/.claude.json\n",
	} {
		want := want
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(string(pathUnit), want) {
				t.Fatalf("path unit missing %q:\n%s", want, string(pathUnit))
			}
		})
	}
	for _, bad := range []string{"PathExists=", "PathExistsGlob=", "PathModified="} {
		if strings.Contains(string(pathUnit), bad) {
			t.Fatalf("path unit should avoid level-triggered directive %q:\n%s", bad, string(pathUnit))
		}
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

func TestRenderCredentialGuardPathUnitUsesOnlyChangedWatches(t *testing.T) {
	pathUnit := renderCredentialGuardPathUnit("/home/operator", "pipelock-cred-guard.service")
	for _, root := range credentialGuardWatchRoots("/home/operator") {
		want := "PathChanged=" + root + "\n"
		if got := strings.Count(pathUnit, want); got != 1 {
			t.Fatalf("PathChanged count for %q = %d, want 1:\n%s", root, got, pathUnit)
		}
		for _, name := range credentialGuardFileNames() {
			path := filepath.Join(root, name)
			want := "PathChanged=" + path + "\n"
			if got := strings.Count(pathUnit, want); got != 1 {
				t.Fatalf("PathChanged count for %q = %d, want 1:\n%s", path, got, pathUnit)
			}
		}
	}
	for _, bad := range []string{"PathExists=", "PathExistsGlob=", "PathModified="} {
		if strings.Contains(pathUnit, bad) {
			t.Fatalf("path unit should not use level-triggered directive %q:\n%s", bad, pathUnit)
		}
	}
}

// TestRenderCredentialGuardServiceDisablesStartRateLimit pins the fix for a
// self-disabling security control. The guard is a path-triggered idempotent
// oneshot, so one tool rewriting several credential files at once fires it
// repeatedly within seconds. Under systemd's default limit that burst reads as a
// crash loop: systemd fails the service, then fails the .path unit that triggers
// it, and the credential guard stays dead until a human notices. Observed on a
// real host sitting in unit-start-limit-hit for over a day, with every individual
// service run having completed successfully.
func TestRenderCredentialGuardServiceDisablesStartRateLimit(t *testing.T) {
	unit := renderCredentialGuardService("/usr/local/bin/plk-cred-guard")
	if !strings.Contains(unit, "StartLimitIntervalSec=0") {
		t.Fatalf("credential guard service must disable the start rate limiter, or a burst of credential writes permanently fails the guard:\n%s", unit)
	}
	// The directive only takes effect in [Unit], so pin the section it lands in.
	unitIdx := strings.Index(unit, "[Unit]")
	svcIdx := strings.Index(unit, "[Service]")
	limIdx := strings.Index(unit, "StartLimitIntervalSec=0")
	if unitIdx < 0 || svcIdx < 0 || limIdx < unitIdx || limIdx > svcIdx {
		t.Fatalf("StartLimitIntervalSec must appear in the [Unit] section:\n%s", unit)
	}
	if !strings.Contains(unit, "Type=oneshot") {
		t.Fatalf("credential guard should remain a oneshot:\n%s", unit)
	}
}
