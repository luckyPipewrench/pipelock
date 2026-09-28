// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// These cover the install steps that write, then fail: each must either put
// back what it wrote before returning, or report applied so rollback does.

// A later managed file's chmod fails after the namespace unit was written.
func TestNetworkNamespaceChmodFailureAfterWriteReportsApplied(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	socket := env.proxyForwarderSocketPath
	if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, []byte(renderContainedProxySocketUnit(env.agentUserName)), 0o600); err != nil {
		t.Fatal(err)
	}
	chmodDenied := 0
	chmod := env.chmod
	env.chmod = func(p string, m os.FileMode) error {
		if filepath.Clean(p) == filepath.Clean(socket) {
			chmodDenied++
			return errors.New("chmod denied")
		}
		return chmod(p, m)
	}
	applied, err := stepInstallNetworkNamespace().apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "chmod denied") {
		t.Fatalf("apply error = %v, want the chmod failure", err)
	}
	if chmodDenied == 0 {
		t.Fatal("positive control: the chmod of the current socket unit never ran")
	}
	if _, statErr := os.Stat(env.networkNamespaceUnitPath); statErr != nil {
		t.Fatalf("positive control: the namespace unit was not written first: %v", statErr)
	}
	if !applied {
		t.Fatal("applied=false after the namespace unit was written; rollback would leave it")
	}
}

// The CA export's own restore fails after a post-write check failed. The step
// must report applied so rollback retries the restore.
func TestCAExportFailedInlineRestoreIsRetriedByRollback(t *testing.T) {
	env, _, caStep, previous, _ := newCAExportStepEnv(t)
	originalRead := env.readFile
	reads := 0
	env.readFile = func(path string) ([]byte, error) {
		if path == env.caExportPath {
			reads++
			if reads == 3 {
				return nil, errors.New("post-write read denied")
			}
		}
		return originalRead(path)
	}
	renameDenied := 0
	rename := env.rename
	env.rename = func(from, to string) error {
		if to == env.caExportPath && strings.HasSuffix(from, ".bak") && renameDenied == 0 {
			renameDenied++
			return errors.New("rename denied once")
		}
		return rename(from, to)
	}
	var out strings.Builder
	_, err := runSteps(context.Background(), env, &out, []step{caStep})
	if err == nil || !strings.Contains(err.Error(), "post-write read denied") {
		t.Fatalf("runSteps error = %v, want the post-write failure", err)
	}
	if renameDenied == 0 {
		t.Fatal("positive control: the inline restore never ran")
	}
	if strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("rollback retry should have restored the export: %v\n%s", err, out.String())
	}
	if got, readErr := os.ReadFile(filepath.Clean(env.caExportPath)); readErr != nil || string(got) != previous {
		t.Fatalf("CA export after rollback = %q, %v; want the previous export", got, readErr)
	}
}

// A tool wrapper write fails and the inline restore of the wrapper written
// before it also fails once. Rollback must retry and restore it.
func TestToolWrappersFailedInlineRestoreIsRetriedByRollback(t *testing.T) {
	env, _, out := newFakeEnv(t)
	if err := writeToolsList(env, []toolsListEntry{
		{name: "claude", target: "/usr/bin/claude"},
		{name: "codex", target: "/usr/bin/codex"},
	}); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(env.wrapperDir, "plk-claude")
	if err := os.MkdirAll(env.wrapperDir, 0o750); err != nil {
		t.Fatal(err)
	}
	const prior = "#!/bin/sh\n# previous claude wrapper\n"
	if err := os.WriteFile(first, []byte(prior), 0o600); err != nil {
		t.Fatal(err)
	}
	writeFile := env.writeFile
	env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
		if filepath.Base(path) == "plk-codex" {
			return errors.New("disk full")
		}
		return writeFile(path, contents, mode)
	}
	renameDenied := 0
	rename := env.rename
	env.rename = func(from, to string) error {
		if to == first && strings.HasSuffix(from, ".bak") && renameDenied == 0 {
			renameDenied++
			return errors.New("rename denied once")
		}
		return rename(from, to)
	}
	_, err := runSteps(context.Background(), env, out, []step{stepWriteToolWrappers()})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("runSteps error = %v, want the write failure", err)
	}
	if renameDenied == 0 {
		t.Fatal("positive control: the inline restore never ran")
	}
	if got, readErr := os.ReadFile(filepath.Clean(first)); readErr != nil || string(got) != prior {
		t.Fatalf("wrapper after rollback = %q, %v; want the previous wrapper\n%s", got, readErr, out.String())
	}
}

// A guard that was running before install gets its previous files back and is
// started again, instead of being left disabled.
func TestCredentialGuardRollbackRestartsPreviouslyActiveGuard(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.guardScriptPath), 0o750); err != nil {
		t.Fatal(err)
	}
	const old = "#!/bin/sh\n# previous guard\n"
	if err := os.WriteFile(env.guardScriptPath, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Base(env.guardPathUnit)
	runner.on(argvFor(testSystemctl, "is-active", unit), "active\n", 0, nil)
	runner.on(argvFor(testSystemctl, "daemon-reload"), "", 0, nil)
	enableCalls := 0
	runCmd := env.runCmd
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if name == testSystemctl && strings.Join(args, " ") == "enable --now "+unit {
			enableCalls++
			if enableCalls == 1 {
				return "denied", 1, nil
			}
		}
		return runCmd(ctx, name, args...)
	}
	if _, err := runSteps(context.Background(), env, out, []step{stepWriteCredentialGuard()}); err == nil {
		t.Fatal("want enable failure")
	}
	if got, _ := os.ReadFile(filepath.Clean(env.guardScriptPath)); string(got) != old {
		t.Fatalf("guard script after rollback = %q, want previous", got)
	}
	if enableCalls != 1 || !rollbackRunnerCalled(runner, testSystemctl, "start "+unit) {
		t.Fatalf("enable --now calls = %d, start called = %t; want one failed install enable and a rollback start\n%s", enableCalls, rollbackRunnerCalled(runner, testSystemctl, "start "+unit), out.String())
	}
}

func TestCredentialGuardRollbackContinuesAfterRestoreError(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	prior := map[string]string{
		env.guardScriptPath:  "#!/bin/sh\n# previous guard\n",
		env.guardServiceUnit: "[Service]\nExecStart=/bin/true\n",
		env.guardPathUnit:    "[Path]\nPathChanged=/previous\n",
	}
	for path, body := range prior {
		if err := os.MkdirAll(filepath.Dir(path), modeDirReadable); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), modeUnitFile); err != nil {
			t.Fatal(err)
		}
	}
	unit := filepath.Base(env.guardPathUnit)
	runner.on(argvFor(testSystemctl, "is-active", unit), "active\n", 0, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled\n", 0, nil)
	renamed := 0
	rename := env.rename
	env.rename = func(from, to string) error {
		if from == env.guardPathUnit+".bak" && to == env.guardPathUnit {
			renamed++
			return errors.New("path unit restore denied")
		}
		return rename(from, to)
	}
	failingStep := step{name: "later-failure", apply: func(context.Context, *installEnv) (bool, error) {
		return false, errors.New("later step failed")
	}}
	_, err := runSteps(context.Background(), env, out, []step{stepWriteCredentialGuard(), failingStep})
	if err == nil || !strings.Contains(err.Error(), "rollback incomplete") || !strings.Contains(err.Error(), "path unit restore denied") {
		t.Fatalf("rollback error = %v, want the restore failure reported", err)
	}
	if renamed == 0 {
		t.Fatal("positive control: the path-unit restore did not run")
	}
	for _, path := range []string{env.guardServiceUnit, env.guardScriptPath} {
		got, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil || string(got) != prior[path] {
			t.Fatalf("later backup %s = %q, %v; want previous content", path, got, readErr)
		}
	}
	if !rollbackRunnerCalled(runner, testSystemctl, "daemon-reload") ||
		!rollbackRunnerCalled(runner, testSystemctl, "enable "+unit) ||
		!rollbackRunnerCalled(runner, testSystemctl, "start "+unit) {
		t.Fatalf("rollback did not reload and restore the previous enabled and active guard\n%s", out.String())
	}
}

func TestCredentialGuardRollbackRestoresModeOnlyChanges(t *testing.T) {
	env, _, out := newFakeEnv(t)
	operator, err := env.lookupUser(env.operatorUser)
	if err != nil {
		t.Fatal(err)
	}
	writes := []struct {
		path string
		body string
		mode os.FileMode
	}{
		{env.guardScriptPath, renderCredentialGuardScript(env.agentUserName, filepath.Clean(operator.HomeDir), env.bashPath), 0o600},
		{env.guardServiceUnit, renderCredentialGuardService(env.guardScriptPath), modeUnitFile},
		{env.guardPathUnit, renderCredentialGuardPathUnit(filepath.Clean(operator.HomeDir), filepath.Base(env.guardServiceUnit)), modeUnitFile},
	}
	for _, item := range writes {
		if err := os.MkdirAll(filepath.Dir(item.path), modeDirReadable); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(item.path, []byte(item.body), item.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(env.guardScriptPath, 0o400); err != nil {
		t.Fatal(err)
	}
	failingStep := step{name: "later-failure", apply: func(context.Context, *installEnv) (bool, error) {
		return false, errors.New("later step failed")
	}}
	_, err = runSteps(context.Background(), env, out, []step{stepWriteCredentialGuard(), failingStep})
	if err == nil || !strings.Contains(err.Error(), "later step failed") {
		t.Fatalf("runSteps error = %v, want later failure", err)
	}
	info, err := os.Stat(env.guardScriptPath)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("guard script mode after rollback = %v, %v; want 0400", info, err)
	}
	if _, err := os.Stat(env.guardScriptPath + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mode-only change created a content backup: %v", err)
	}
}

func TestCredentialGuardRollbackPreservesRuntimeEnable(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.guardPathUnit), modeDirReadable); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.guardPathUnit, []byte("previous path unit"), modeUnitFile); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Base(env.guardPathUnit)
	runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled-runtime\n", 0, nil)
	failingStep := step{name: "later-failure", apply: func(context.Context, *installEnv) (bool, error) {
		return false, errors.New("later step failed")
	}}
	_, err := runSteps(context.Background(), env, out, []step{stepWriteCredentialGuard(), failingStep})
	if err == nil || !strings.Contains(err.Error(), "later step failed") {
		t.Fatalf("runSteps error = %v, want later failure", err)
	}
	if !rollbackRunnerCalled(runner, testSystemctl, "enable --runtime "+unit) ||
		rollbackRunnerCalled(runner, testSystemctl, "enable "+unit) {
		t.Fatalf("rollback did not preserve runtime enable state\n%s", out.String())
	}
}

// A current display unit on a rerun is not rewritten, so rollback must not
// delete it.
func TestDisplayRollbackLeavesUnitThisAttemptDidNotWrite(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
	if _, err := stepProvisionAgentDisplay().apply(context.Background(), env); err != nil {
		t.Fatalf("first install: %v", err)
	}
	body, err := os.ReadFile(filepath.Clean(env.displayUnitPath))
	if err != nil {
		t.Fatalf("positive control: display unit not written: %v", err)
	}
	if _, err := os.Stat(env.displayUnitPath + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("positive control: a fresh install should leave no backup: %v", err)
	}
	env.prevDisplayStateKnown = false
	rerun := stepProvisionAgentDisplay()
	if applied, err := rerun.apply(context.Background(), env); err != nil || !applied {
		t.Fatalf("rerun apply = %t, %v", applied, err)
	}
	if err := rerun.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if got, err := os.ReadFile(filepath.Clean(env.displayUnitPath)); err != nil || string(got) != string(body) {
		t.Fatalf("display unit after rollback = %q, %v; want the unit left in place", got, err)
	}
}

// Staging fails after migration wrote an artifact and the inline cleanup
// fails once. Rollback must retry the cleanup.
func TestStageConfigFailedCleanupIsRetriedByRollback(t *testing.T) {
	env, _, out := newFakeEnv(t)
	home := t.TempDir()
	env.lookupUser = func(name string) (*user.User, error) {
		if name == containInstallOperatorUser {
			return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: home}, nil
		}
		return &user.User{Uid: "988", Gid: "988", Username: name, HomeDir: "/tmp"}, nil
	}
	configDir := filepath.Join(home, ".config", "pipelock")
	license := filepath.Join(configDir, "license.token")
	mustWriteFile(t, license, "token\n")
	src := filepath.Join(configDir, "pipelock.yaml")
	mustWriteFile(t, src, "license_file: "+license+"\n")
	migrated := filepath.Join(env.configDir, "license.token")
	staged := stagedPipelockConfigPath(env)
	writeFile := env.writeFile
	env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
		if path == staged {
			return errors.New("stage denied")
		}
		return writeFile(path, contents, mode)
	}
	removeDenied := 0
	removeFile := env.removeFile
	env.removeFile = func(p string) error {
		if filepath.Clean(p) == filepath.Clean(migrated) && removeDenied == 0 {
			removeDenied++
			return errors.New("remove denied once")
		}
		return removeFile(p)
	}
	_, err := runSteps(context.Background(), env, out, []step{stepStagePipelockConfig(installOpts{configSource: src})})
	if err == nil || !strings.Contains(err.Error(), "stage denied") {
		t.Fatalf("runSteps error = %v, want the staging failure", err)
	}
	if removeDenied == 0 {
		t.Fatal("positive control: the inline cleanup never ran")
	}
	if strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("rollback retry should have removed the migrated artifact: %v\n%s", err, out.String())
	}
	if _, statErr := os.Stat(migrated); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("migrated artifact left after rollback: %v", statErr)
	}
}
