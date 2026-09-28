// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These tests pin one rule for a failed install: rollback restores exactly
// what this attempt changed, never deletes containment it did not create, and
// reports an undo it could not finish instead of a clean rollback.

const rollbackDriftedLiveChain = `table inet pipelock_containment {
		chain output_filter {
			meta oif "lo" accept
			meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept
			meta skuid 987 drop
		}
	}
`

func rollbackNFTFixture(t *testing.T, live string) (*installEnv, *fakeRunner, string) {
	t.Helper()
	env, runner, _ := newFakeEnv(t)
	body := renderNFTRules(1000, 988, 987, env.proxyPort, defaultNFTTable, defaultNFTChain)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	writeNFTPersistUnitFixture(t, env)
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), live, 0, nil)
	return env, runner, body
}

func rollbackRunnerCalled(runner *fakeRunner, name, args string) bool {
	for _, c := range runner.calls {
		if c.name == name && strings.Join(c.args, " ") == args {
			return true
		}
	}
	return false
}

// A containment table was live before install, its contents could not be
// captured, and this attempt reloaded it. Rollback must keep the table and
// say the rollback is incomplete, not delete it and leave the agent unfiltered.
func TestNFTUndoKeepsPreexistingTableWhenPriorDumpUnknown(t *testing.T) {
	for _, mode := range []string{"exec-error", "nonzero"} {
		t.Run(mode, func(t *testing.T) {
			env, runner, _ := rollbackNFTFixture(t, rollbackDriftedLiveChain)
			if mode == "exec-error" {
				runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "", 0, errors.New("exec: nft timed out"))
			} else {
				runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "Error: transient", 1, nil)
			}
			applied, err := stepInstallNFTRulesApply(context.Background(), env)
			if err != nil || !applied {
				t.Fatalf("apply = %t, %v; want a reload of the drifted table", applied, err)
			}
			if !env.nftTableMutatedByInstall {
				t.Fatal("positive control: apply did not record that it reloaded the table")
			}
			beforeUndo := len(runner.calls)
			undoErr := stepInstallNFTRulesUndo(context.Background(), env)
			for _, call := range runner.calls[beforeUndo:] {
				if call.name == testNFT {
					t.Fatalf("rollback mutated or reopened a containment table whose prior state is unknown: %+v", call)
				}
			}
			if undoErr == nil {
				t.Fatal("undo reported success although the previous table could not be restored")
			}
			if !strings.Contains(undoErr.Error(), "pipelock contain install") {
				t.Fatalf("undo error %q does not name the remedy", undoErr)
			}
		})
	}
}

// With no table before install, a table this attempt loaded is still dropped.
func TestNFTUndoDropsTableItCreatedWhenNoneExisted(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "Error: No such file", 1, nil)
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "Error: No such file", 1, nil)
	applied, err := stepInstallNFTRulesApply(context.Background(), env)
	if err != nil || !applied {
		t.Fatalf("apply = %t, %v", applied, err)
	}
	if err := stepInstallNFTRulesUndo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if !rollbackRunnerCalled(runner, testNFT, "delete table inet "+defaultNFTTable) {
		t.Fatal("rollback left the table this attempt created")
	}
}

// The step can report applied without writing the rules file (only the
// expiry timer needed starting). Rollback must leave that file alone rather
// than delete it or swap in an older release's backup.
func TestNFTUndoLeavesRulesFileThisAttemptDidNotWrite(t *testing.T) {
	for _, mode := range []string{"no-bak", "stale-bak"} {
		t.Run(mode, func(t *testing.T) {
			env, runner, body := rollbackNFTFixture(t, "")
			runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), body, 0, nil)
			runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.nftPersistUnitPath)), "enabled\n", 0, nil)
			runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.nftExpiryTimerPath)), "enabled\n", 0, nil)
			runner.on(argvFor(testSystemctl, "is-active", filepath.Base(env.nftExpiryTimerPath)), "inactive\n", 0, nil)
			runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), body, 0, nil)
			const staleRules = "# rules from an older release\n"
			const staleUnit = "# unit from an older release\n"
			unitPaths := []string{env.nftPersistUnitPath, env.nftExpiryServicePath, env.nftExpiryTimerPath}
			if mode == "stale-bak" {
				if err := os.WriteFile(env.nftRulesPath+".bak", []byte(staleRules), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			applied, err := stepInstallNFTRulesApply(context.Background(), env)
			if err != nil || !applied {
				t.Fatalf("apply = %t, %v; positive control wants applied via the timer reconcile", applied, err)
			}
			if got, _ := os.ReadFile(filepath.Clean(env.nftRulesPath)); string(got) != body {
				t.Fatal("positive control: apply rewrote the rules file")
			}
			unitBodies := map[string][]byte{}
			for _, p := range unitPaths {
				data, err := os.ReadFile(filepath.Clean(p))
				if err != nil {
					t.Fatalf("positive control: unit %s missing after apply: %v", p, err)
				}
				unitBodies[p] = data
				if mode == "stale-bak" {
					if err := os.WriteFile(p+".bak", []byte(staleUnit), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			// The fixture already installed every unit before apply. The
			// ownership flags must be naturally false, not reset by the test.
			if env.nftPersistUnitWrittenByInstall || env.nftExpiryServiceWrittenByInstall || env.nftExpiryTimerWrittenByInstall {
				t.Fatal("positive control: apply unexpectedly rewrote a unit")
			}
			if err := stepInstallNFTRulesUndo(context.Background(), env); err != nil {
				t.Fatalf("undo: %v", err)
			}
			if got, err := os.ReadFile(filepath.Clean(env.nftRulesPath)); err != nil || string(got) != body {
				t.Fatalf("rules file after rollback = %q, %v; want the current rules the kernel still holds", got, err)
			}
			for _, p := range unitPaths {
				if got, err := os.ReadFile(filepath.Clean(p)); err != nil || string(got) != string(unitBodies[p]) {
					t.Fatalf("unit %s after rollback = %q, %v; want it untouched", p, got, err)
				}
			}
		})
	}
}

// A rules file this attempt did write is still restored from its backup.
func TestNFTUndoRestoresRulesFileThisAttemptWrote(t *testing.T) {
	env, runner, body := rollbackNFTFixture(t, "")
	const prior = "# previous rules\n"
	if err := os.WriteFile(env.nftRulesPath, []byte(prior), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "Error: No such file", 1, nil)
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "Error: No such file", 1, nil)
	applied, err := stepInstallNFTRulesApply(context.Background(), env)
	if err != nil || !applied {
		t.Fatalf("apply = %t, %v", applied, err)
	}
	if got, _ := os.ReadFile(filepath.Clean(env.nftRulesPath)); string(got) != body {
		t.Fatal("positive control: apply did not write the rules file")
	}
	if err := stepInstallNFTRulesUndo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if got, err := os.ReadFile(filepath.Clean(env.nftRulesPath)); err != nil || string(got) != prior {
		t.Fatalf("rules file after rollback = %q, %v; want %q", got, err, prior)
	}
}

// A drift-only reload changes the kernel table; a later systemctl failure in
// the same step must still report it applied so rollback runs.
func TestNFTApplyReportsKernelReloadWhenSystemctlFailsAfter(t *testing.T) {
	for _, failing := range []string{"daemon-reload", "enable-persist", "enable-timer"} {
		t.Run(failing, func(t *testing.T) {
			env, runner, _ := rollbackNFTFixture(t, rollbackDriftedLiveChain)
			// The units already match, so only the kernel reload changes state.
			if _, err := ensureNFTExpiryUnits(env); err != nil {
				t.Fatal(err)
			}
			if _, err := ensureNFTPersistUnit(env); err != nil {
				t.Fatal(err)
			}
			switch failing {
			case "daemon-reload":
				runner.on(argvFor(testSystemctl, "daemon-reload"), "", 1, nil)
			case "enable-persist":
				runner.on(argvFor(testSystemctl, "enable", filepath.Base(env.nftPersistUnitPath)), "", 1, nil)
			default:
				runner.on(argvFor(testSystemctl, "enable", "--now", filepath.Base(env.nftExpiryTimerPath)), "", 1, nil)
			}
			applied, err := stepInstallNFTRulesApply(context.Background(), env)
			if err == nil {
				t.Fatalf("want a %s failure", failing)
			}
			if !env.nftTableMutatedByInstall {
				t.Fatal("positive control: the drifted table was not reloaded")
			}
			if !applied {
				t.Fatalf("applied=false after the kernel table was reloaded (%v)", err)
			}
		})
	}
}

func TestNFTApplyReportsFailedEnableWithoutFileOrTableChange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failTimer bool
		unknown   bool
		runtime   bool
		disabled  bool
	}{
		{name: "persist known"},
		{name: "persist unknown", unknown: true},
		{name: "persist runtime", runtime: true},
		{name: "persist disabled", disabled: true},
		{name: "timer known", failTimer: true},
		{name: "timer unknown", failTimer: true, unknown: true},
		{name: "timer runtime", failTimer: true, runtime: true},
		{name: "timer disabled", failTimer: true, disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, body := rollbackNFTFixture(t, "")
			runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), body, 0, nil)
			runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), body, 0, nil)
			runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.nftPersistUnitPath)), "enabled\n", 0, nil)
			runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.nftExpiryTimerPath)), "enabled\n", 0, nil)
			runner.on(argvFor(testSystemctl, "is-active", filepath.Base(env.nftExpiryTimerPath)), "active\n", 0, nil)
			if tc.runtime || tc.disabled {
				unit := env.nftPersistUnitPath
				if tc.failTimer {
					unit = env.nftExpiryTimerPath
				}
				state, code := "enabled-runtime\n", 0
				if tc.disabled {
					state, code = "disabled\n", 1
				}
				runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(unit)), state, code, nil)
			}
			if tc.unknown {
				unit := env.nftPersistUnitPath
				if tc.failTimer {
					unit = env.nftExpiryTimerPath
				}
				runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(unit)), "", 0, errors.New("state query failed"))
			}
			args := []string{"enable", filepath.Base(env.nftPersistUnitPath)}
			if tc.failTimer {
				args = []string{"enable", "--now", filepath.Base(env.nftExpiryTimerPath)}
			}
			runner.on(argvFor(testSystemctl, args...), "", 1, nil)
			applied, err := stepInstallNFTRulesApply(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), "enable") {
				t.Fatalf("apply error = %v, want failed enable", err)
			}
			if env.nftTableMutatedByInstall || env.nftRulesWrittenByInstall || env.nftPersistUnitWrittenByInstall ||
				env.nftExpiryServiceWrittenByInstall || env.nftExpiryTimerWrittenByInstall {
				t.Fatal("positive control: this case must change no file or nft table")
			}
			if !applied {
				t.Fatal("failed enable may mutate systemd state, so rollback must run")
			}
			if !tc.failTimer {
				// The injected failure is one-shot; the rollback retry succeeds.
				runner.on(argvFor(testSystemctl, args...), "", 0, nil)
			}
			beforeUndo := len(runner.calls)
			undoErr := stepInstallNFTRulesUndo(context.Background(), env)
			if tc.unknown {
				if undoErr == nil || !strings.Contains(undoErr.Error(), "unknown") {
					t.Fatalf("undo error = %v, want unknown previous unit state", undoErr)
				}
			} else if undoErr != nil {
				t.Fatalf("undo: %v", undoErr)
			}
			if tc.runtime {
				unit := env.nftPersistUnitPath
				if tc.failTimer {
					unit = env.nftExpiryTimerPath
				}
				foundRuntime := false
				for _, call := range runner.calls[beforeUndo:] {
					if call.name != testSystemctl {
						continue
					}
					if slices.Equal(call.args, []string{"enable", filepath.Base(unit)}) {
						t.Fatalf("rollback made runtime-only enablement permanent: %+v", call)
					}
					if slices.Equal(call.args, []string{"enable", "--runtime", filepath.Base(unit)}) {
						foundRuntime = true
					}
				}
				if !foundRuntime {
					t.Fatal("rollback did not restore runtime-only enablement")
				}
			}
			if tc.disabled {
				unit := env.nftPersistUnitPath
				wantArgs := []string{"disable", filepath.Base(unit)}
				if tc.failTimer {
					unit = env.nftExpiryTimerPath
					wantArgs = []string{"disable", "--now", filepath.Base(unit)}
				}
				foundDisable := false
				for _, call := range runner.calls[beforeUndo:] {
					if call.name == testSystemctl && slices.Equal(call.args, wantArgs) {
						foundDisable = true
					}
				}
				if !foundDisable {
					t.Fatal("rollback did not restore disabled unit state")
				}
			}
		})
	}
}

// visudo rejects the new sudoers after a prior install left both the file and
// an older, different backup. Rollback must end with the previous sudoers in
// place: never deleted, and never reported OK while missing.
func TestSudoersRejectedRollbackRestoresOnceAndReports(t *testing.T) {
	for _, archiveFails := range []bool{false, true} {
		name := "archive-restore-ok"
		if archiveFails {
			name = "archive-restore-fails"
		}
		t.Run(name, func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			if err := os.MkdirAll(filepath.Dir(env.sudoersPath), 0o750); err != nil {
				t.Fatal(err)
			}
			const prior = "# previous pipelock sudoers\n"
			if err := os.WriteFile(env.sudoersPath, []byte(prior), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(env.sudoersPath+".bak", []byte("# even older\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runner.on(argvFor("visudo", "-cf", env.sudoersPath), "parse error", 1, nil)
			archiveRenames := 0
			rename := env.rename
			env.rename = func(from, to string) error {
				if strings.Contains(from, ".archived-") && strings.HasSuffix(to, ".bak") {
					archiveRenames++
					if archiveFails {
						return errors.New("rename archive denied")
					}
				}
				return rename(from, to)
			}
			_, err := runSteps(context.Background(), env, out, []step{stepInstallSudoers()})
			if err == nil {
				t.Fatal("want visudo rejection")
			}
			if archiveFails && archiveRenames == 0 {
				t.Fatal("positive control: the archived backup restore never ran")
			}
			got, rerr := os.ReadFile(filepath.Clean(env.sudoersPath))
			if rerr != nil || string(got) != prior {
				t.Fatalf("sudoers after rollback = %q, %v; want the previous file\n%s", got, rerr, out.String())
			}
			incomplete := strings.Contains(err.Error(), "rollback incomplete")
			if archiveFails && !incomplete {
				t.Fatalf("a failed backup restore was reported as a clean rollback: %v", err)
			}
			if !archiveFails && incomplete {
				t.Fatalf("a clean rollback was reported incomplete: %v", err)
			}
		})
	}
}

// restoreBackup may run twice for one path (a step's own recovery and the
// rollback). The second call must not delete the file the first put back.
func TestRestoreBackupRetryKeepsRestoredFile(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "managed")
	const prior = "prior\n"
	if err := os.WriteFile(path, []byte(prior), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", []byte("older\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backupAndWrite(env, path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failArchive := true
	rename := env.rename
	env.rename = func(from, to string) error {
		if failArchive && strings.Contains(from, ".archived-") {
			return errors.New("rename archive denied")
		}
		return rename(from, to)
	}
	if err := restoreBackup(env, path); err == nil {
		t.Fatal("positive control: want the archived backup restore to fail")
	}
	if err := restoreBackup(env, path); err == nil {
		t.Fatal("retry reported success although the archived backup is still not restored")
	}
	if got, err := os.ReadFile(filepath.Clean(path)); err != nil || string(got) != prior {
		t.Fatalf("file after retried restore = %q, %v; want %q", got, err, prior)
	}
	failArchive = false
	if err := restoreBackup(env, path); err != nil {
		t.Fatalf("retry after the archive became restorable: %v", err)
	}
	if got, err := os.ReadFile(filepath.Clean(path + ".bak")); err != nil || string(got) != "older\n" {
		t.Fatalf("backup after completed retry = %q, %v; want the older backup back", got, err)
	}
	if got, err := os.ReadFile(filepath.Clean(path)); err != nil || string(got) != prior {
		t.Fatalf("file after completed retry = %q, %v; want %q", got, err, prior)
	}
}

// Agent tool config written, then its chown fails: rollback must put back the
// previous config instead of leaving a root-owned new one in the agent home.
func TestAgentToolConfigChownFailureRestoresPreviousConfig(t *testing.T) {
	env, _, out := newFakeEnv(t)
	cfg := agentToolConfigs()[0]
	path := filepath.Join(env.agentHome, cfg.rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	const old = "# previous agent config\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	chowns := 0
	env.lchown = func(p string, _, _ int) error {
		if filepath.Clean(p) == filepath.Clean(path) {
			chowns++
			return errors.New("lchown denied")
		}
		return nil
	}
	if _, err := runSteps(context.Background(), env, out, []step{stepWriteAgentToolConfigs()}); err == nil {
		t.Fatal("want chown failure")
	}
	if chowns == 0 {
		t.Fatal("positive control: chown of the new config never ran")
	}
	if got, _ := os.ReadFile(filepath.Clean(path)); string(got) != old {
		t.Fatalf("config after failed step = %q, want previous", got)
	}
}

// Credential guard: the script is rewritten, then the next unit's mkdir fails.
// The step must report applied so rollback restores the script.
func TestCredentialGuardLaterMkdirFailureRestoresScript(t *testing.T) {
	env, _, out := newFakeEnv(t)
	if filepath.Dir(env.guardServiceUnit) == filepath.Dir(env.guardScriptPath) {
		t.Skip("script and unit share a directory in this fixture")
	}
	if err := os.MkdirAll(filepath.Dir(env.guardScriptPath), 0o750); err != nil {
		t.Fatal(err)
	}
	const old = "#!/bin/sh\n# previous guard\n"
	if err := os.WriteFile(env.guardScriptPath, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	mkdirDenied := 0
	mk := env.mkdirAll
	env.mkdirAll = func(p string, m os.FileMode) error {
		if filepath.Clean(p) == filepath.Dir(env.guardServiceUnit) {
			mkdirDenied++
			return errors.New("mkdir denied")
		}
		return mk(p, m)
	}
	if _, err := runSteps(context.Background(), env, out, []step{stepWriteCredentialGuard()}); err == nil {
		t.Fatal("want mkdir failure")
	}
	if mkdirDenied == 0 {
		t.Fatal("positive control: the unit mkdir never ran")
	}
	if got, _ := os.ReadFile(filepath.Clean(env.guardScriptPath)); string(got) != old {
		t.Fatalf("guard script after failed step = %q, want previous", got)
	}
}

// Credential guard already installed and current; a rerun fails while running
// the guard. Rollback must not delete or disable the guard it did not write.
func TestCredentialGuardUndoLeavesUnwrittenGuardInPlace(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	first := stepWriteCredentialGuard()
	if _, err := first.apply(context.Background(), env); err != nil {
		t.Fatalf("first install: %v", err)
	}
	for _, p := range []string{env.guardScriptPath, env.guardServiceUnit, env.guardPathUnit} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("positive control: %s not installed: %v", p, err)
		}
	}
	runner.on(argvFor(env.guardScriptPath), "boom", 1, nil)
	if _, err := runSteps(context.Background(), env, out, []step{stepWriteCredentialGuard()}); err == nil {
		t.Fatal("want guard script failure")
	}
	for _, p := range []string{env.guardScriptPath, env.guardServiceUnit, env.guardPathUnit} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("rollback removed %s that this attempt did not write: %v\n%s", p, err, out.String())
		}
	}
	if rollbackRunnerCalled(runner, testSystemctl, "disable --now "+filepath.Base(env.guardPathUnit)) {
		t.Fatal("rollback disabled a credential guard this attempt did not write")
	}
}
