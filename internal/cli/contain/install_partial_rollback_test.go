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

// A failed install must leave the host as it found it. These tests cover
// steps that change a file and then fail on a later operation in the same
// step: each must report the change as applied so its undo restores it.

func TestStepInstallNFTRulesUnitFailureAfterRulesWriteRestoresRules(t *testing.T) {
	for _, failed := range []string{"persist", "expiry-service", "expiry-timer"} {
		t.Run(failed, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
				t.Fatal(err)
			}
			const oldRules = "# previous managed rules\n"
			if err := os.WriteFile(env.nftRulesPath, []byte(oldRules), 0o600); err != nil {
				t.Fatal(err)
			}
			// Units already current, so the only change before the failure
			// is the rules file itself.
			for path, body := range map[string]string{
				env.nftPersistUnitPath:   renderNFTPersistUnit(env),
				env.nftExpiryServicePath: renderNFTExpiryService(env),
				env.nftExpiryTimerPath:   renderNFTExpiryTimer(env),
			} {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), modeUnitFile); err != nil {
					t.Fatal(err)
				}
			}
			fail := map[string]string{
				"persist":        env.nftPersistUnitPath,
				"expiry-service": env.nftExpiryServicePath,
				"expiry-timer":   env.nftExpiryTimerPath,
			}[failed]
			// A current unit is not rewritten, so fail its read-compare to
			// force the write path, then deny the write.
			readFile := env.readFile
			env.readFile = func(path string) ([]byte, error) {
				if path == fail {
					return []byte("stale unit\n"), nil
				}
				return readFile(path)
			}
			writeFile := env.writeFile
			failing := true
			env.writeFile = func(path string, body []byte, mode os.FileMode) error {
				if failing && path == fail {
					return errors.New("write denied")
				}
				return writeFile(path, body, mode)
			}
			// No table is loaded, and deleting an absent table fails on a
			// real host.
			runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, errors.New("not loaded"))
			runner.on(argvFor(testNFT, "delete", "table", "inet", defaultNFTTable), "Error: No such file or directory", 1, nil)

			s := stepInstallNFTRules()
			changed, err := s.apply(context.Background(), env)
			if err == nil {
				t.Fatal("apply succeeded, want unit write failure")
			}
			got, rerr := os.ReadFile(env.nftRulesPath)
			if rerr != nil || string(got) == oldRules {
				t.Fatalf("positive control: rules file was not rewritten before the failure (%q, %v)", got, rerr)
			}
			if !changed {
				t.Fatal("rules file was rewritten but the step reported nothing applied, so rollback skips it")
			}
			failing = false
			env.readFile = readFile
			if err := s.undo(context.Background(), env); err != nil {
				t.Fatalf("undo: %v", err)
			}
			got, err = os.ReadFile(env.nftRulesPath)
			if err != nil || string(got) != oldRules {
				t.Fatalf("rules after rollback = %q, %v; want previous rules", got, err)
			}
			if nftDeletedTable(runner) {
				t.Fatal("rollback deleted a table this attempt never loaded")
			}
		})
	}
}

func TestStepInstallNFTRulesUndoStillDropsTableThisAttemptLoaded(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	writeNFTPersistUnitFixture(t, env)
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, errors.New("not loaded"))
	runner.on(argvFor("systemctl", "daemon-reload"), "", 1, nil)
	changed, err := stepInstallNFTRulesApply(context.Background(), env)
	if err == nil || !changed {
		t.Fatalf("apply = (%t, %v), want a failure after loading", changed, err)
	}
	if !env.nftTableMutatedByInstall {
		t.Fatal("load ran but the attempt was not recorded as having changed the table")
	}
	runner.on(argvFor("systemctl", "daemon-reload"), "", 0, nil)
	if err := stepInstallNFTRulesUndo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if !nftDeletedTable(runner) {
		t.Fatal("rollback left the table this attempt loaded")
	}
}

func TestRunStepsFailedAtomicNFTLoadRestoresRulesFile(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	const oldRules = "# previous managed rules\n"
	if err := os.WriteFile(env.nftRulesPath, []byte(oldRules), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, errors.New("not loaded"))
	runner.on(argvFor(testNFT, "-f", env.nftRulesPath), "atomic batch rejected", 1, nil)
	runner.on(argvFor(testNFT, "delete", "table", "inet", defaultNFTTable), "no such table", 1, nil)

	_, err := runSteps(context.Background(), env, out, []step{stepInstallNFTRules()})
	if err == nil || !strings.Contains(err.Error(), "nft load failed") {
		t.Fatalf("runSteps error = %v, want failed nft batch", err)
	}
	if strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("runSteps error = %v, want file rollback after failed atomic batch", err)
	}
	if nftDeletedTable(runner) {
		t.Fatal("rollback tried to delete a table the failed batch never loaded")
	}
	got, readErr := os.ReadFile(env.nftRulesPath)
	if readErr != nil || string(got) != oldRules {
		t.Fatalf("rules after rollback = %q, %v; want previous rules", got, readErr)
	}
}

func TestStepWriteIntegrityPinOwnershipFailureRestoresPreviousPin(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.pipelockTarget), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.pipelockTarget, []byte("new pipelock"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(env.integrityPin), 0o750); err != nil {
		t.Fatal(err)
	}
	const oldPin = "0000000000000000000000000000000000000000000000000000000000000000\n"
	if err := os.WriteFile(env.integrityPin, []byte(oldPin), 0o600); err != nil {
		t.Fatal(err)
	}
	env.chown = func(path string, _, _ int) error {
		if path == env.integrityPin {
			return errors.New("chown denied")
		}
		return nil
	}
	s := stepWriteIntegrityPin()
	applied, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatal("apply succeeded, want ownership failure")
	}
	got, _ := os.ReadFile(env.integrityPin)
	if string(got) == oldPin {
		t.Fatal("positive control: pin was not rewritten before the ownership failure")
	}
	if !applied {
		t.Fatal("pin was rewritten but the step reported nothing applied, so rollback keeps the new pin")
	}
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	got, _ = os.ReadFile(env.integrityPin)
	if string(got) != oldPin {
		t.Fatalf("pin after rollback = %q, want previous pin", got)
	}
}

func TestStepWriteProfileScriptChownFailureRestoresPreviousScript(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := profileScriptPathOrDefault(env)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	const oldScript = "# previous profile script\n"
	if err := os.WriteFile(path, []byte(oldScript), 0o600); err != nil {
		t.Fatal(err)
	}
	env.chown = func(string, int, int) error { return errors.New("chown denied") }
	s := stepWriteProfileScript()
	applied, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatal("apply succeeded, want chown failure")
	}
	got, _ := os.ReadFile(filepath.Clean(path))
	if string(got) == oldScript {
		t.Fatal("positive control: script was not rewritten before the chown failure")
	}
	if !applied {
		t.Fatal("script was rewritten but the step reported nothing applied")
	}
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	got, _ = os.ReadFile(filepath.Clean(path))
	if string(got) != oldScript {
		t.Fatalf("script after rollback = %q, want previous script", got)
	}
}

func TestRunStepsReportsIncompleteRollback(t *testing.T) {
	env, _, out := newFakeEnv(t)
	steps := []step{
		{
			name: "first", desc: "first",
			apply: func(context.Context, *installEnv) (bool, error) { return true, nil },
			undo:  func(context.Context, *installEnv) error { return errors.New("restore denied") },
		},
		{
			name: "second", desc: "second",
			apply: func(context.Context, *installEnv) (bool, error) { return false, errors.New("boom") },
		},
	}
	_, err := runSteps(context.Background(), env, out, steps)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("runSteps error = %v, want the step failure", err)
	}
	if !strings.Contains(err.Error(), "rollback incomplete") || !strings.Contains(err.Error(), "undo first") {
		t.Fatalf("runSteps error = %v, want the failed undo named", err)
	}

	cleanSteps := []step{
		{
			name: "first", desc: "first",
			apply: func(context.Context, *installEnv) (bool, error) { return true, nil },
			undo:  func(context.Context, *installEnv) error { return nil },
		},
		steps[1],
	}
	_, err = runSteps(context.Background(), env, out, cleanSteps)
	if err == nil || strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("clean rollback error = %v, want only the step failure", err)
	}
}

// nftDeletedTable reports whether the fake runner saw rollback drop the
// containment table. runnerCalled matches systemctl only.
func nftDeletedTable(runner *fakeRunner) bool {
	for _, call := range runner.calls {
		if call.name == testNFT && strings.Join(call.args, " ") == "delete table inet "+defaultNFTTable {
			return true
		}
	}
	return false
}

func TestStepInstallSudoersReportsFailedRestoreAfterVisudoRejects(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.sudoersPath), 0o750); err != nil {
		t.Fatal(err)
	}
	runner.on(argvFor("visudo", "-cf", env.sudoersPath), "parse error", 1, nil)
	removeFile := env.removeFile
	env.removeFile = func(path string) error {
		if path == filepath.Clean(env.sudoersPath) {
			return errors.New("remove denied")
		}
		return removeFile(path)
	}
	_, err := stepInstallSudoers().apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "visudo rejected") {
		t.Fatalf("apply error = %v, want visudo rejection", err)
	}
	if !strings.Contains(err.Error(), "restore previous sudoers") {
		t.Fatalf("apply error = %v, want the failed restore reported", err)
	}
}

func TestRunStepsRetriesSudoersRestoreAfterVisudoRejects(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.sudoersPath), 0o750); err != nil {
		t.Fatal(err)
	}
	runner.on(argvFor("visudo", "-cf", env.sudoersPath), "parse error", 1, nil)
	removeFile := env.removeFile
	removeAttempts := 0
	env.removeFile = func(path string) error {
		if path == filepath.Clean(env.sudoersPath) {
			removeAttempts++
			if removeAttempts == 1 {
				return errors.New("temporary remove failure")
			}
		}
		return removeFile(path)
	}

	_, err := runSteps(context.Background(), env, out, []step{stepInstallSudoers()})
	if err == nil || !strings.Contains(err.Error(), "visudo rejected") {
		t.Fatalf("runSteps error = %v, want visudo rejection", err)
	}
	if strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("runSteps error = %v, want successful retry", err)
	}
	if removeAttempts != 2 {
		t.Fatalf("sudoers remove attempts = %d, want immediate restore plus orchestrator undo", removeAttempts)
	}
	if _, statErr := os.Stat(env.sudoersPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("sudoers remained after rollback: %v", statErr)
	}
}

func TestRunStepsReportsIncompleteSudoersRollback(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.sudoersPath), 0o750); err != nil {
		t.Fatal(err)
	}
	runner.on(argvFor("visudo", "-cf", env.sudoersPath), "parse error", 1, nil)
	env.removeFile = func(path string) error {
		if path == filepath.Clean(env.sudoersPath) {
			return errors.New("remove denied")
		}
		return os.Remove(path)
	}

	_, err := runSteps(context.Background(), env, out, []step{stepInstallSudoers()})
	if err == nil || !strings.Contains(err.Error(), "visudo rejected") ||
		!strings.Contains(err.Error(), "rollback incomplete") || !strings.Contains(err.Error(), "undo install-sudoers") {
		t.Fatalf("runSteps error = %v, want visudo failure and incomplete rollback", err)
	}
	if _, statErr := os.Stat(env.sudoersPath); statErr != nil {
		t.Fatalf("positive control: rejected sudoers file was not left in place: %v", statErr)
	}
}

func TestStepInstallNFTRulesUndoLeavesUntouchedPriorTable(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	const oldRules = "# previous managed rules\n"
	if err := os.WriteFile(env.nftRulesPath+".bak", []byte(oldRules), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte("# this attempt's rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A table existed before the attempt, and the attempt failed before any
	// nft batch changed it.
	env.prevNFTTableStateKnown = true
	env.prevNFTTableDump = "table inet " + defaultNFTTable + " {\n}\n"
	env.nftTableMutatedByInstall = false

	if err := stepInstallNFTRulesUndo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	got, err := os.ReadFile(env.nftRulesPath)
	if err != nil || string(got) != oldRules {
		t.Fatalf("rules after rollback = %q, %v; want previous rules", got, err)
	}
	for _, call := range runner.calls {
		if call.name != testNFT {
			continue
		}
		args := strings.Join(call.args, " ")
		if strings.Contains(args, "delete table") || strings.HasSuffix(args, ".restore") {
			t.Fatalf("rollback changed a table this attempt never touched: nft %s", args)
		}
	}
}

func TestStepInstallNFTRulesUndoLeavesTableWhenPriorStateUnknown(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	const oldRules = "# previous managed rules\n"
	if err := os.WriteFile(env.nftRulesPath+".bak", []byte(oldRules), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte("# this attempt's rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Capture failed, so nothing is known about a live table, and the attempt
	// failed before any nft batch ran.
	env.prevNFTTableStateKnown = false
	env.nftTableMutatedByInstall = false

	if err := stepInstallNFTRulesUndo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if nftDeletedTable(runner) {
		t.Fatal("rollback deleted a table whose owner it could not establish")
	}
	got, err := os.ReadFile(env.nftRulesPath)
	if err != nil || string(got) != oldRules {
		t.Fatalf("rules after rollback = %q, %v; want previous rules", got, err)
	}
}

func TestRunStepsReportsIncompleteRollbackAfterCancellation(t *testing.T) {
	env, _, out := newFakeEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	steps := []step{
		{
			name: "first", desc: "first",
			apply: func(context.Context, *installEnv) (bool, error) {
				cancel()
				return true, nil
			},
			undo: func(context.Context, *installEnv) error { return errors.New("restore denied") },
		},
		{name: "second", desc: "second", apply: func(context.Context, *installEnv) (bool, error) { return true, nil }},
	}
	_, err := runSteps(ctx, env, out, steps)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("runSteps error = %v, want cancellation", err)
	}
	if !strings.Contains(err.Error(), "rollback incomplete") || !strings.Contains(err.Error(), "undo first") {
		t.Fatalf("runSteps error = %v, want the failed undo named", err)
	}
}
