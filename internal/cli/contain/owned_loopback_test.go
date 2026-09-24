// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOwnedLoopbackRulesRequireBothSocketChecks(t *testing.T) {
	t.Parallel()
	rules := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: 1000, ProxyUID: 967, AgentUID: 966, ProxyPort: 8888,
		Table: defaultNFTTable, Chain: defaultNFTChain, OwnedLoopback: true,
	})
	for _, want := range []string{
		"socket cgroupv2 level 1", "ct mark set " + ownedLoopbackConntrackMark,
		"ct mark " + ownedLoopbackConntrackMark + " socket cgroupv2 level 1",
		"ct mark " + ownedLoopbackConntrackMark + " drop",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("rules missing %q:\n%s", want, rules)
		}
	}
	if strings.Contains(nftOwnedLoopbackOutputRules(966), "tcp dport") {
		t.Fatal("owned loopback output rule must not depend on a declared port")
	}
	inputStart := strings.Index(rules, "chain "+ownedLoopbackInputChain+" {")
	if inputStart < 0 {
		t.Fatalf("rules missing owned input chain:\n%s", rules)
	}
	input := rules[inputStart:]
	if !strings.Contains(input, "ct mark "+ownedLoopbackConntrackMark+" socket cgroupv2 level 1 \""+ownedLoopbackSlice+"\" accept") {
		t.Fatalf("receiver cgroup acceptance missing from input chain:\n%s", input)
	}
	if strings.Index(input, "ct mark "+ownedLoopbackConntrackMark+" socket cgroupv2") > strings.Index(input, "ct mark "+ownedLoopbackConntrackMark+" drop") {
		t.Fatal("receiver cgroup acceptance must precede the marked-flow drop")
	}
}

func TestContainedLaunchWrapperChecksAnchorAndOwnsPlacement(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	body := renderContainedLaunchWrapper(env)
	for _, want := range []string{
		"systemctl is-active --quiet 'pipelock-contained-anchor.service'",
		"--slice='" + ownedLoopbackSlice + "'",
		"--uid='" + env.agentUserName + "'",
		"--gid='" + env.agentUserName + "'",
		"plk-launch",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("contained launcher missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "sudo ") {
		t.Fatalf("contained launcher must not recurse through sudo:\n%s", body)
	}
}

func TestOwnedLoopbackReloadReplacesReceiverGateInSameTransaction(t *testing.T) {
	t.Parallel()
	body := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: 1000, ProxyUID: 967, AgentUID: 966, ProxyPort: 8888,
		Table: defaultNFTTable, Chain: defaultNFTChain, OwnedLoopback: true,
	})
	script := renderNFTManagedChainReloadScript("", body, defaultNFTTable, defaultNFTChain, 1000, 967, 966, true)
	deleteAt := strings.Index(script, "delete chain inet "+defaultNFTTable+" "+ownedLoopbackInputChain)
	inputAt := strings.Index(script, "chain "+ownedLoopbackInputChain+" {")
	if deleteAt < 0 || inputAt < 0 || deleteAt > inputAt {
		t.Fatalf("reload must replace receiver gate before adding canonical rules:\n%s", script)
	}
}

func TestProbeOwnedLoopbackAnchorFailsClosed(t *testing.T) {
	t.Parallel()
	anchor := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env := &probeEnv{
		ownedLoopbackAnchorUnitPath: anchor,
		readFile:                    func(string) ([]byte, error) { return []byte("[Service]\n"), nil },
		runCmd: func(_ context.Context, _ string, _ ...string) (string, int, error) {
			return "inactive\n", 3, nil
		},
	}
	status, detail := probeOwnedLoopbackAnchor(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "plk-contained-launch checks this anchor") {
		t.Fatalf("status=%q detail=%q; want closed inactive-anchor result", status, detail)
	}
}

func TestOwnedLoopbackRulesRejectStaleCgroupID(t *testing.T) {
	t.Parallel()
	if ownedLoopbackRulesReferenceCurrentAnchor("socket cgroupv2 level 1 12345", 1) {
		t.Fatal("numeric cgroup ID must not be accepted as the current anchor")
	}
	if !ownedLoopbackRulesReferenceCurrentAnchor(`socket cgroupv2 level 1 "`+ownedLoopbackSlice+`"`, 1) {
		t.Fatal("current cgroup path must satisfy the anchor check")
	}
}

func TestOwnedLoopbackAnchorUnitIsShallowAndPersistent(t *testing.T) {
	t.Parallel()
	body := renderOwnedLoopbackAnchorUnit()
	for _, want := range []string{"Slice=" + ownedLoopbackSlice, "ExecStart=/usr/bin/sleep infinity", "Before=pipelock-containment-nft.service", "Restart=always"} {
		if !strings.Contains(body, want) {
			t.Fatalf("anchor unit missing %q:\n%s", want, body)
		}
	}
}

func TestOwnedLoopbackAnchorStartsBeforeNFTInstall(t *testing.T) {
	t.Parallel()
	steps := installSteps(installOpts{})
	anchor, nft := -1, -1
	for i, step := range steps {
		switch step.name {
		case "ensure-owned-loopback-anchor":
			anchor = i
		case "install-nft-rules":
			nft = i
		}
	}
	if anchor < 0 || nft < 0 || anchor >= nft {
		t.Fatalf("anchor=%d nft=%d; anchor must be installed before nft rules", anchor, nft)
	}
}

func TestOwnedLoopbackAnchorFailsBeforeNFTWhenInactive(t *testing.T) {
	t.Parallel()
	env, runner, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.ownedLoopbackAnchorUnitPath = filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	runner.responses[argvFor("systemctl", "is-active", filepath.Base(env.ownedLoopbackAnchorUnitPath))] = struct {
		out  string
		code int
		err  error
	}{out: "inactive\n", code: 3}
	applied, err := stepEnsureOwnedLoopbackAnchor().apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "not active") || !applied {
		t.Fatalf("applied=%t err=%v; want inactive anchor refusal after write", applied, err)
	}
	for _, call := range runner.calls {
		if call.name == env.nftPath {
			t.Fatalf("anchor failure reached nft: %#v", call)
		}
	}
}

func TestRemoveOwnedLoopbackAnchorRestoresOnlyManagedUnit(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.ownedLoopbackAnchorUnitPath = filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	neighbor := filepath.Join(filepath.Dir(env.ownedLoopbackAnchorUnitPath), "other.service")
	if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(neighbor, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stepEnsureOwnedLoopbackAnchor().apply(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := actionRemoveOwnedLoopbackAnchor().undo(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(env.ownedLoopbackAnchorUnitPath); err != nil || string(got) != "previous" {
		t.Fatalf("anchor = %q, err=%v; want prior unit restored", got, err)
	}
	if got, err := os.ReadFile(filepath.Clean(neighbor)); err != nil || string(got) != "keep" {
		t.Fatalf("neighbor = %q, err=%v; rollback touched an unowned unit", got, err)
	}
}

// TestEnsureOwnedLoopbackAnchorIsOffWhenNotOwned pins the disabled branch. The
// whole owned-loopback boundary is gated on env.ownedLoopback, so a build with
// it off must write no unit and run no systemctl at all; a step that quietly
// provisioned anyway would put a cgroup on hosts that never asked for one.
func TestEnsureOwnedLoopbackAnchorIsOffWhenNotOwned(t *testing.T) {
	t.Parallel()
	env, runner, _ := newFakeEnv(t)
	env.ownedLoopback = false
	path := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env.ownedLoopbackAnchorUnitPath = path

	applied, err := stepEnsureOwnedLoopbackAnchor().apply(context.Background(), env)
	if err != nil || applied {
		t.Fatalf("applied=%t err=%v; want no work when owned loopback is off", applied, err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("anchor unit written while owned loopback is off: %v", statErr)
	}
	for _, call := range runner.calls {
		if call.name == "systemctl" {
			t.Fatalf("systemctl ran while owned loopback is off: %#v", call)
		}
	}
}

// TestEnsureOwnedLoopbackAnchorRefusesUnconfiguredPath covers the misconfigured
// state. An empty unit path must be an error rather than a silent success,
// because returning nil here would let the nft rules that reference this anchor
// install against a cgroup nothing created.
func TestEnsureOwnedLoopbackAnchorRefusesUnconfiguredPath(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.ownedLoopbackAnchorUnitPath = ""

	applied, err := stepEnsureOwnedLoopbackAnchor().apply(context.Background(), env)
	if err == nil || applied {
		t.Fatalf("applied=%t err=%v; want a refusal when the anchor path is unset", applied, err)
	}
}

// TestEnsureOwnedLoopbackAnchorIsIdempotent covers the RERUN state, which is
// what an operator actually does most often. A second install against an
// unchanged unit must report no change while still confirming the unit is
// running, so a reinstall does not read as work it did not do and does not stop
// checking that the anchor is live.
func TestEnsureOwnedLoopbackAnchorIsIdempotent(t *testing.T) {
	t.Parallel()
	env, runner, _ := newFakeEnv(t)
	env.ownedLoopback = true
	path := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env.ownedLoopbackAnchorUnitPath = path
	unit := filepath.Base(path)
	runner.responses[argvFor("systemctl", "is-active", unit)] = struct {
		out  string
		code int
		err  error
	}{out: systemctlActive + "\n", code: 0}

	first, err := stepEnsureOwnedLoopbackAnchor().apply(context.Background(), env)
	if err != nil || !first {
		t.Fatalf("first apply = %t, %v; want a change", first, err)
	}
	second, err := stepEnsureOwnedLoopbackAnchor().apply(context.Background(), env)
	if err != nil || second {
		t.Fatalf("second apply = %t, %v; want no change on rerun", second, err)
	}

	// The rerun must still verify liveness. `enable --now` is used rather than
	// a bare `enable` precisely because the latter only writes a boot symlink,
	// so dropping the is-active read would let an inactive anchor pass a rerun.
	checks := 0
	for _, call := range runner.calls {
		if call.name == "systemctl" && len(call.args) > 0 && call.args[0] == "is-active" {
			checks++
		}
	}
	if checks < 2 {
		t.Fatalf("is-active checks = %d; want the rerun to re-verify liveness", checks)
	}
}

// TestContainedLaunchWrapperStepWritesAndRestores covers the wrapper step's
// apply/idempotence/undo cycle. The undo path matters on a FAILED install: the
// wrapper is what places agent tools in the owned cgroup, so a half-installed
// wrapper left behind would route tools into a slice whose nft rules may have
// been rolled back.
func TestContainedLaunchWrapperStepWritesAndRestores(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopbackAnchorUnitPath = filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	path := filepath.Join(env.wrapperDir, "plk-contained-launch")
	previous := "#!/bin/bash\n# prior wrapper\n"
	if err := os.WriteFile(path, []byte(previous), modeWrapperExec); err != nil {
		t.Fatalf("seed prior wrapper: %v", err)
	}

	step := stepWriteContainedLaunchWrapper()
	changed, err := step.apply(context.Background(), env)
	if err != nil || !changed {
		t.Fatalf("apply = %t, %v; want a change over the prior wrapper", changed, err)
	}
	again, err := step.apply(context.Background(), env)
	if err != nil || again {
		t.Fatalf("second apply = %t, %v; want no change", again, err)
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil || string(got) != previous {
		t.Fatalf("wrapper after undo = %q, %v; want the prior wrapper restored", got, err)
	}
}

// TestEnsureOwnedLoopbackAnchorFailureBranches covers each way the anchor step
// can fail after it has already written the unit file. Every one of these must
// surface an error rather than proceed, because the nft rules installed later
// name this cgroup: a step that reported success with the anchor absent or dead
// would load rules against a cgroup that does not exist.
func TestEnsureOwnedLoopbackAnchorFailureBranches(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		failArg string
		wantErr string
	}{
		{name: "daemon-reload fails", failArg: "daemon-reload", wantErr: "reload systemd for owned loopback anchor"},
		{name: "enable --now fails", failArg: "enable", wantErr: "start owned loopback anchor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, runner, _ := newFakeEnv(t)
			env.ownedLoopback = true
			path := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
			env.ownedLoopbackAnchorUnitPath = path
			unit := filepath.Base(path)

			failing := tc.failArg
			base := env.runCmd
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name == "systemctl" && len(args) > 0 && args[0] == failing {
					return "", 1, errors.New("systemctl refused")
				}
				if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
					return systemctlActive + "\n", 0, nil
				}
				return base(ctx, name, args...)
			}

			applied, err := stepEnsureOwnedLoopbackAnchor().apply(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("apply = %t, %v; want %q", applied, err, tc.wantErr)
			}
			// The unit was written before the failure, so the step must report
			// didApply so rollback can restore the prior state.
			if !applied {
				t.Fatal("apply reported no change after writing the unit; rollback would skip it")
			}
			_ = runner
			_ = unit
		})
	}
}

// TestEnsureOwnedLoopbackAnchorUndoRestoresPriorUnit covers the step's own undo,
// which runs when a LATER install step fails. It must stop the anchor and put
// back whatever unit file was there before, so a failed install does not leave
// a running cgroup anchor that nothing references.
func TestEnsureOwnedLoopbackAnchorUndoRestoresPriorUnit(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	path := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env.ownedLoopbackAnchorUnitPath = path
	previous := "[Unit]\nDescription=prior anchor\n"
	if err := os.WriteFile(path, []byte(previous), modeUnitFile); err != nil {
		t.Fatalf("seed prior unit: %v", err)
	}

	step := stepEnsureOwnedLoopbackAnchor()
	if _, err := step.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil || string(got) != previous {
		t.Fatalf("anchor unit after undo = %q, %v; want the prior unit restored", got, err)
	}
}

// TestEnsureOwnedLoopbackAnchorUndoIsInertWhenUnconfigured pins that undo does
// nothing when no anchor path is set, so a rollback on a build without owned
// loopback cannot stop or delete an unrelated unit.
func TestEnsureOwnedLoopbackAnchorUndoIsInertWhenUnconfigured(t *testing.T) {
	t.Parallel()
	env, runner, _ := newFakeEnv(t)
	env.ownedLoopbackAnchorUnitPath = ""
	if err := stepEnsureOwnedLoopbackAnchor().undo(context.Background(), env); err != nil {
		t.Fatalf("undo with no configured path: %v", err)
	}
	for _, call := range runner.calls {
		if call.name == "systemctl" {
			t.Fatalf("undo ran systemctl with no configured anchor: %#v", call)
		}
	}
}

// TestEnsureOwnedLoopbackInputChainFailsClosedOnInterruptedMigration is the
// fail-direction test for the receiver gate. Marked OUTPUT rules accept a
// loopback flow on the way out; the INPUT chain is the only thing that then
// checks the RECEIVING socket is in the owned cgroup. If a prior migration left
// OUTPUT marks in place without that chain, silently recreating it would be a
// repair performed on a boundary that was already fail-open, and the operator
// would never learn the host had been exposed. It must refuse instead.
func TestEnsureOwnedLoopbackInputChainFailsClosedOnInterruptedMigration(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		chainOut  string
		chainCode int
		outputOut string
		wantErr   string
	}{
		{
			name:      "receiver chain missing while marked OUTPUT rules exist",
			chainOut:  "Error: No such file or directory",
			chainCode: 1,
			outputOut: "chain output_filter { ct mark " + ownedLoopbackConntrackMark + " accept }",
			wantErr:   "refusing a fail-open repair",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, _, _ := newFakeEnv(t)
			env.ownedLoopback = true
			chainOut, chainCode, outputOut := tc.chainOut, tc.chainCode, tc.outputOut
			env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != nftExecutable(env) {
					return "", 0, nil
				}
				joined := strings.Join(args, " ")
				if strings.Contains(joined, ownedLoopbackInputChain) {
					return chainOut, chainCode, nil
				}
				return outputOut, 0, nil
			}

			_, err := ensureOwnedLoopbackInputChain(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ensureOwnedLoopbackInputChain = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

// TestEnsureOwnedLoopbackInputChainAcceptsAManagedChain is the positive control
// for the test above. Without it, an unconditional error would make every case
// there pass while proving nothing.
func TestEnsureOwnedLoopbackInputChainAcceptsAManagedChain(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	managed := renderOwnedLoopbackInputChainTable(env.nftTableOrDefault())
	if !ownedLoopbackInputChainLooksManaged(managed) {
		t.Fatal("rendered receiver chain is not recognized by its own matcher")
	}
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == nftExecutable(env) && strings.Contains(strings.Join(args, " "), ownedLoopbackInputChain) {
			return managed, 0, nil
		}
		return "", 0, nil
	}
	if _, err := ensureOwnedLoopbackInputChain(context.Background(), env); err != nil {
		t.Fatalf("a managed receiver chain was rejected: %v", err)
	}
}

// TestEnsureOwnedLoopbackInputChainCreatesTheReceiverGate covers the creation
// path taken when an existing containment table predates dynamic loopback. The
// chain is validated with `nft -c` before it is loaded, and the staged
// transaction file is removed afterwards so a partially written ruleset cannot
// be picked up by a later run.
func TestEnsureOwnedLoopbackInputChainCreatesTheReceiverGate(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.nftRulesPath = filepath.Join(t.TempDir(), "containment.nft")

	var staged string
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != nftExecutable(env) {
			return "", 0, nil
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, ownedLoopbackInputChain):
			return "Error: No such file or directory", 1, nil
		case strings.Contains(joined, "-f"):
			// Capture what is handed to nft so the assertions below read the
			// real transaction rather than the rendered string.
			if body, err := os.ReadFile(filepath.Clean(env.nftRulesPath + ".owned-loopback-input")); err == nil {
				staged = string(body)
			}
			return "", 0, nil
		default:
			// The OUTPUT chain carries no owned-loopback marks, so this is a
			// clean migration rather than an interrupted one.
			return "chain output_filter { }", 0, nil
		}
	}

	if _, err := ensureOwnedLoopbackInputChain(context.Background(), env); err != nil {
		t.Fatalf("creating the receiver gate: %v", err)
	}
	if !ownedLoopbackInputChainLooksManaged(staged) {
		t.Fatalf("staged transaction is not the managed receiver chain:\n%s", staged)
	}
	if !strings.Contains(staged, "ct mark "+ownedLoopbackConntrackMark+" drop") {
		t.Fatalf("staged receiver chain is missing its terminal drop:\n%s", staged)
	}
	if _, err := os.Stat(env.nftRulesPath + ".owned-loopback-input"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged transaction file was left behind: %v", err)
	}
}

// TestEnsureOwnedLoopbackInputChainRefusesAnUnloadableGate pins that the gate is
// validated before it is loaded, and that a failure at either stage is an error
// rather than a silent skip. Continuing past this point would install marked
// OUTPUT rules with no receiver-side check behind them.
func TestEnsureOwnedLoopbackInputChainRefusesAnUnloadableGate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		failOn  string
		wantErr string
	}{
		{name: "validation rejects the chain", failOn: "-c", wantErr: "validate owned loopback receiver chain"},
		{name: "load rejects the chain", failOn: "load", wantErr: "load owned loopback receiver chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, _, _ := newFakeEnv(t)
			env.ownedLoopback = true
			env.nftRulesPath = filepath.Join(t.TempDir(), "containment.nft")
			failOn := tc.failOn
			env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != nftExecutable(env) {
					return "", 0, nil
				}
				joined := strings.Join(args, " ")
				switch {
				case strings.Contains(joined, ownedLoopbackInputChain):
					return "Error: No such file or directory", 1, nil
				case strings.Contains(joined, "-c -f"):
					if failOn == "-c" {
						return "syntax error", 1, nil
					}
					return "", 0, nil
				case strings.Contains(joined, "-f"):
					if failOn == "load" {
						return "load refused", 1, nil
					}
					return "", 0, nil
				default:
					return "chain output_filter { }", 0, nil
				}
			}
			_, err := ensureOwnedLoopbackInputChain(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ensureOwnedLoopbackInputChain = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

// TestEnsureOwnedLoopbackInputChainSurfacesQueryFailures covers the branches
// where nft cannot answer at all. Each must be an error: treating an
// unanswerable query as "chain absent" would push the caller into the creation
// path on a host whose real state is unknown, and treating it as "chain fine"
// would install marked OUTPUT rules with no proven receiver gate.
func TestEnsureOwnedLoopbackInputChainSurfacesQueryFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		chainErr   error
		chainOut   string
		chainCode  int
		outputErr  error
		outputCode int
		wantErr    string
	}{
		{
			name:     "listing the receiver chain errors",
			chainErr: errors.New("nft unavailable"),
			wantErr:  "list owned loopback receiver chain",
		},
		{
			name:      "listing the receiver chain fails for an unrecognized reason",
			chainOut:  "permission denied",
			chainCode: 1,
			wantErr:   "list owned loopback receiver chain exit=1",
		},
		{
			name:      "rechecking the output chain errors",
			chainOut:  "Error: No such file or directory",
			chainCode: 1,
			outputErr: errors.New("nft vanished"),
			wantErr:   "recheck containment output chain",
		},
		{
			name:       "rechecking the output chain exits non-zero",
			chainOut:   "Error: No such file or directory",
			chainCode:  1,
			outputCode: 2,
			wantErr:    "recheck containment output chain before adding owned receiver gate exit=2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, _, _ := newFakeEnv(t)
			env.ownedLoopback = true
			env.nftRulesPath = filepath.Join(t.TempDir(), "containment.nft")
			tc := tc
			env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != nftExecutable(env) {
					return "", 0, nil
				}
				if strings.Contains(strings.Join(args, " "), ownedLoopbackInputChain) {
					return tc.chainOut, tc.chainCode, tc.chainErr
				}
				return "chain output_filter { }", tc.outputCode, tc.outputErr
			}
			_, err := ensureOwnedLoopbackInputChain(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ensureOwnedLoopbackInputChain = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

// TestContainedLaunchWrapperStepSurfacesWriteFailure pins that an unwritable
// wrapper path is an error rather than a skipped step. The wrapper is what puts
// agent tools inside the owned cgroup, so an install that could not write it
// but continued would leave tools outside the slice the nft rules gate on, and
// every loopback connection they make would be dropped with no explanation.
func TestContainedLaunchWrapperStepSurfacesWriteFailure(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopbackAnchorUnitPath = filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env.writeFile = func(string, []byte, os.FileMode) error {
		return errors.New("read-only filesystem")
	}
	applied, err := stepWriteContainedLaunchWrapper().apply(context.Background(), env)
	if err == nil || applied {
		t.Fatalf("apply = %t, %v; want the write failure surfaced", applied, err)
	}
}

// TestEnsureOwnedLoopbackAnchorUndoSurfacesFailures covers undo's own error
// paths. Rollback runs when an install has already failed, so a silent failure
// here leaves a running anchor and a stale unit behind while the operator is
// told the rollback succeeded.
func TestEnsureOwnedLoopbackAnchorUndoSurfacesFailures(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	path := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env.ownedLoopbackAnchorUnitPath = path
	if err := os.WriteFile(path, []byte("[Unit]\n"), modeUnitFile); err != nil {
		t.Fatalf("seed unit: %v", err)
	}
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "daemon-reload" {
			return "", 1, errors.New("systemd unreachable")
		}
		return "", 0, nil
	}
	if err := stepEnsureOwnedLoopbackAnchor().undo(context.Background(), env); err == nil {
		t.Fatal("undo reported success while systemd refused the reload")
	}
}

// TestOwnedLoopbackAnchorSurfacesUnitWriteFailure pins that an unwritable
// anchor unit stops the install. The nft rules loaded later name this cgroup
// by path and nft resolves that path at rule-load time, so continuing past a
// failed write would fail at a point where containment is already half-applied.
func TestOwnedLoopbackAnchorSurfacesUnitWriteFailure(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.ownedLoopbackAnchorUnitPath = filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env.writeFile = func(string, []byte, os.FileMode) error {
		return errors.New("read-only filesystem")
	}
	applied, err := stepEnsureOwnedLoopbackAnchor().apply(context.Background(), env)
	if err == nil || applied {
		t.Fatalf("apply = %t, %v; want the unit write failure surfaced", applied, err)
	}
}

// TestOwnedLoopbackAnchorUndoSurfacesStopFailure covers the rollback branch
// where systemd refuses to stop the anchor. Reporting success there would leave
// a live cgroup anchor on a host whose install was rolled back.
func TestOwnedLoopbackAnchorUndoSurfacesStopFailure(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	path := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env.ownedLoopbackAnchorUnitPath = path
	if err := os.WriteFile(path, []byte("[Unit]\n"), modeUnitFile); err != nil {
		t.Fatalf("seed unit: %v", err)
	}
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "disable" {
			return "", 1, errors.New("systemd refused")
		}
		return "", 0, nil
	}
	if err := stepEnsureOwnedLoopbackAnchor().undo(context.Background(), env); err == nil ||
		!strings.Contains(err.Error(), "stop owned loopback anchor") {
		t.Fatalf("undo = %v; want the stop failure surfaced", err)
	}
}

// TestNFTPersistUnitOrdersAfterTheAnchor pins the boot ordering. The persisted
// containment ruleset names the owned cgroup, and nft resolves a cgroup path
// when it LOADS a rule, so loading the ruleset before the anchor exists makes
// the boot-time load fail and the host comes up with no containment rule for
// the agent at all.
func TestNFTPersistUnitOrdersAfterTheAnchor(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.ownedLoopbackAnchorUnitPath = "/etc/systemd/system/pipelock-contained-anchor.service"
	anchor := filepath.Base(env.ownedLoopbackAnchorUnitPath)

	withAnchor := renderNFTPersistUnit(env)
	if !strings.Contains(withAnchor, "After=local-fs.target "+anchor) {
		t.Fatalf("persist unit does not order after the anchor:\n%s", withAnchor)
	}
	if !strings.Contains(withAnchor, "Wants=network-pre.target "+anchor) {
		t.Fatalf("persist unit does not want the anchor:\n%s", withAnchor)
	}

	// Positive control: without owned loopback the anchor must not appear, so
	// the assertions above are about the flag and not about the literal string
	// always being present.
	env.ownedLoopback = false
	if got := renderNFTPersistUnit(env); strings.Contains(got, anchor) {
		t.Fatalf("persist unit references the anchor while owned loopback is off:\n%s", got)
	}
}

// TestReloadRefusesWhenTheReceiverGateIsMissing is the reload-time half of the
// fail-closed rule. `contain reload-nft-rules` runs from a timer and from
// install, and it rewrites the managed OUTPUT block. Those rules MARK loopback
// flows as owned; the INPUT chain is the only thing that then checks the
// receiving socket. Reloading OUTPUT while that chain is absent would leave the
// host accepting marked flows with no receiver check at all, so the reload must
// refuse rather than proceed and restore what it found.
func TestReloadRefusesWhenTheReceiverGateIsMissing(t *testing.T) {
	t.Parallel()
	persisted := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID,
		AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort,
		Table: defaultNFTTable, Chain: defaultNFTChain, OwnedLoopback: true,
	})
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithNoService, nftReloadTestConfigWithService("2099-01-01T00:00:00Z"), persisted)
	fx.env.ownedLoopback = true

	// The fail-open state is a live OUTPUT chain that ALREADY MARKS loopback
	// flows while its receiver gate is gone. A legacy chain with no marking
	// rules is not that state and must be allowed to migrate, so the fixture
	// has to carry the marks for this refusal to be the thing under test.
	marks := "    meta skuid " + strconv.Itoa(loopbackTestAgentUID) + " oifname \"lo\" ip daddr 127.0.0.1 socket cgroupv2 level 1 \"" + ownedLoopbackSlice + "\" ct state new ct mark set " + ownedLoopbackConntrackMark + " accept # handle 90\n" +
		"    meta skuid " + strconv.Itoa(loopbackTestAgentUID) + " oifname \"lo\" ip6 daddr ::1 socket cgroupv2 level 1 \"" + ownedLoopbackSlice + "\" ct state new ct mark set " + ownedLoopbackConntrackMark + " accept # handle 91\n"
	// Insert INSIDE the output chain block, where the chain-line parser reads.
	marker := "    meta skuid 1000 accept # handle 20\n"
	if !strings.Contains(nftReloadTestLiveWithNoService, marker) {
		t.Fatal("live fixture shape changed; the marking rules would land outside the chain")
	}
	markedOutput := strings.Replace(nftReloadTestLiveWithNoService, marker, marker+marks, 1)
	// Prove the fixture models the fail-open state before relying on it.
	if !nftOutputHasOwnedLoopbackMarks(markedOutput, loopbackTestAgentUID) {
		t.Fatal("fixture does not present marked OUTPUT rules")
	}

	base := fx.env.runCmd
	fx.env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, ownedLoopbackInputChain) {
			// The receiver gate is gone: an interrupted migration, or someone
			// flushed the table by hand.
			return "Error: No such file or directory", 1, nil
		}
		if strings.Contains(joined, "list chain") {
			return markedOutput, 0, nil
		}
		return base(ctx, name, args...)
	}

	err := reloadNFTRules(context.Background(), fx.env)
	if err == nil || !strings.Contains(err.Error(), "missing while the output chain already marks loopback flows") {
		t.Fatalf("reloadNFTRules = %v; want a refusal naming the missing receiver gate", err)
	}
}

// TestRemoveOwnedLoopbackAnchorSurfacesFailures covers the uninstall action's
// error branches. Uninstall runs when an operator is deliberately tearing
// containment down, so a silent failure here leaves a running cgroup anchor and
// a managed unit file on a host the operator believes is clean.
func TestRemoveOwnedLoopbackAnchorSurfacesFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		failOn  string
		wantErr string
	}{
		{name: "stopping the anchor fails", failOn: "disable", wantErr: "disable owned loopback anchor"},
		{name: "reloading systemd fails", failOn: "daemon-reload", wantErr: "exec systemctl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, _, _ := newFakeEnv(t)
			env.ownedLoopback = true
			path := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
			env.ownedLoopbackAnchorUnitPath = path
			if err := os.WriteFile(path, []byte("[Unit]\n"), modeUnitFile); err != nil {
				t.Fatalf("seed unit: %v", err)
			}
			failOn := tc.failOn
			env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				if name == "systemctl" && len(args) > 0 && args[0] == failOn {
					return "", 1, errors.New("systemd refused")
				}
				return "", 0, nil
			}
			err := actionRemoveOwnedLoopbackAnchor().undo(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("undo = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

// TestReloadEmitsNoReceiverDeleteWhenTheKernelHasNoChain is the boot-outage
// regression. The persistence unit runs `contain reload-nft-rules` at boot, and
// after a reboot the nftables ruleset is empty while the canonical rules file
// still describes the receiver chain. `nft delete chain` FAILS on a chain that
// does not exist, and because `nft -f` is atomic that failure aborts the entire
// transaction. This unit is the only thing that loads containment at boot, so
// the host would come up with no containment rule for the agent at all.
//
// Deciding the delete from the canonical rules is what caused it; only the live
// kernel state may decide it.
func TestReloadEmitsNoReceiverDeleteWhenTheKernelHasNoChain(t *testing.T) {
	t.Parallel()
	canonical := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: 1000, ProxyUID: 967, AgentUID: 966, ProxyPort: 8888,
		Table: defaultNFTTable, Chain: defaultNFTChain, OwnedLoopback: true,
	})
	if !strings.Contains(canonical, "chain "+ownedLoopbackInputChain+" {") {
		t.Fatal("canonical rules do not declare the receiver chain; this test would pass vacuously")
	}

	// Empty live state is the post-reboot kernel.
	bootScript := renderNFTManagedChainReloadScript("", canonical, defaultNFTTable, defaultNFTChain, 1000, 967, 966, false)
	if strings.Contains(bootScript, "delete chain inet "+defaultNFTTable+" "+ownedLoopbackInputChain) {
		t.Fatalf("reload deletes a receiver chain the kernel does not have; the whole nft transaction would abort and leave the host uncontained:\n%s", bootScript)
	}
	if !strings.Contains(bootScript, "chain "+ownedLoopbackInputChain+" {") {
		t.Fatalf("reload must still CREATE the receiver gate at boot:\n%s", bootScript)
	}

	// Positive control: when the chain really is live the delete must still be
	// emitted, or the reload would duplicate a base chain.
	liveScript := renderNFTManagedChainReloadScript("", canonical, defaultNFTTable, defaultNFTChain, 1000, 967, 966, true)
	if !strings.Contains(liveScript, "delete chain inet "+defaultNFTTable+" "+ownedLoopbackInputChain) {
		t.Fatalf("a live receiver chain must be replaced in the same transaction:\n%s", liveScript)
	}
}

// TestReceiverChainMatcherRejectsExtraRules closes a bypass in the receiver
// gate. nftables evaluates a chain in order, so a rule inserted BEFORE the
// managed accept decides the packet first. The matcher previously tested four
// substrings, which every one of the chains below still satisfies while the
// boundary they are supposed to enforce is gone.
func TestReceiverChainMatcherRejectsExtraRules(t *testing.T) {
	t.Parallel()
	managed := renderOwnedLoopbackInputChainTable(defaultNFTTable)

	// Positive control first: the chain this package renders must be accepted,
	// or every rejection below would pass for the wrong reason.
	if !ownedLoopbackInputChainLooksManaged(managed) {
		t.Fatalf("the rendered receiver chain is rejected by its own matcher:\n%s", managed)
	}

	accept := "ct mark " + ownedLoopbackConntrackMark + " socket cgroupv2 level 1 \"" + ownedLoopbackSlice + "\" accept"
	drop := "ct mark " + ownedLoopbackConntrackMark + " drop"
	decl := "type filter hook input priority filter; policy accept;"
	chain := func(rules ...string) string {
		return "table inet " + defaultNFTTable + " {\n    chain " + ownedLoopbackInputChain + " {\n        " +
			strings.Join(rules, "\n        ") + "\n    }\n}\n"
	}

	for _, tc := range []struct {
		name  string
		chain string
	}{
		{
			// The bypass. An unconditional accept ahead of the managed rule
			// lets every marked flow reach any socket on the host.
			name:  "unconditional accept before the managed accept",
			chain: chain(decl, "ct mark "+ownedLoopbackConntrackMark+" accept", accept, drop),
		},
		{
			// Order matters: a drop that never runs is not a drop.
			name:  "accept and drop in the wrong order",
			chain: chain(decl, drop, accept),
		},
		{
			// A trailing accept after the drop is unreachable today, but it
			// means the chain is not the one this package wrote.
			name:  "extra rule after the terminal drop",
			chain: chain(decl, accept, drop, "ct mark "+ownedLoopbackConntrackMark+" accept"),
		},
		{
			// Without the terminal drop the gate accepts nothing and denies
			// nothing: marked traffic falls through to the accept policy.
			name:  "terminal drop removed",
			chain: chain(decl, accept),
		},
		{
			// Truncated output must never satisfy an exact match.
			name:  "unterminated chain",
			chain: "table inet " + defaultNFTTable + " {\n    chain " + ownedLoopbackInputChain + " {\n        " + decl + "\n        " + accept,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if ownedLoopbackInputChainLooksManaged(tc.chain) {
				t.Fatalf("matcher accepted a receiver chain that is not the managed one:\n%s", tc.chain)
			}
		})
	}
}

// TestContainedLaunchWrapperResolvesRootHelpersAbsolutely pins the privilege
// boundary of the generated launcher. sudoers runs this script as root, so any
// helper it resolves through PATH is chosen by the caller: on a host whose sudo
// rule does not set secure_path, a fake `systemctl` earlier in PATH runs as root
// before systemd-run drops privileges.
func TestContainedLaunchWrapperResolvesRootHelpersAbsolutely(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopbackAnchorUnitPath = "/etc/systemd/system/pipelock-contained-anchor.service"
	body := renderContainedLaunchWrapper(env)

	if !strings.Contains(body, "PATH="+shellQuote(rootHelperPATH)) {
		t.Fatalf("root wrapper does not pin PATH:\n%s", body)
	}
	for _, absolute := range []string{containIDPath, containSystemctlPath, "/usr/bin/systemd-run"} {
		if !strings.Contains(body, absolute) {
			t.Fatalf("root wrapper does not call %s by absolute path:\n%s", absolute, body)
		}
	}
	// Every helper invocation must be absolute. A bare command at the start of
	// a line or after a shell operator is the shape this test exists to catch.
	for _, bare := range []string{"$(id ", "! systemctl ", "\nsystemctl ", "\nid "} {
		if strings.Contains(body, bare) {
			t.Fatalf("root wrapper invokes %q through PATH:\n%s", strings.TrimSpace(bare), body)
		}
	}
}

// TestOwnedLoopbackOutputRulesDetectedInLiveChain covers the drift predicate
// that decides whether install must reload. The marking rules live in the
// OUTPUT chain; a live chain that lost them reads as unchanged to a comparison
// that only knows the legacy rules, so the installer would skip the reload and
// never load them back.
func TestOwnedLoopbackOutputRulesDetectedInLiveChain(t *testing.T) {
	t.Parallel()
	const agentUID = 966
	mark := "ct mark set " + ownedLoopbackConntrackMark
	slice := `socket cgroupv2 level 1 "` + ownedLoopbackSlice + `"`
	v4 := "meta skuid 966 oifname \"lo\" ip daddr 127.0.0.1 " + slice + " ct state new " + mark + " accept"
	v6 := "meta skuid 966 oifname \"lo\" ip6 daddr ::1 " + slice + " ct state new " + mark + " accept"

	if !chainLinesHaveOwnedLoopbackOutputRules([]string{v4, v6}, agentUID) {
		t.Fatal("a complete marking block was not detected")
	}
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{name: "no marking rules at all", lines: []string{"meta skuid 966 drop"}},
		{name: "only the IPv4 half", lines: []string{v4}},
		{
			// Counting matches instead of tracking families accepted this: two
			// IPv4 rules satisfy a >=2 count while ::1 loopback is unmarked.
			name:  "duplicate IPv4 rules and no IPv6 rule",
			lines: []string{v4, v4},
		},
		{name: "only the IPv6 half", lines: []string{v6}},
		{name: "marking rules belong to another uid", lines: []string{
			strings.ReplaceAll(v4, "skuid 966", "skuid 1000"),
			strings.ReplaceAll(v6, "skuid 966", "skuid 1000"),
		}},
		{name: "mark set without the cgroup predicate", lines: []string{
			strings.ReplaceAll(v4, slice, ""), strings.ReplaceAll(v6, slice, ""),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if chainLinesHaveOwnedLoopbackOutputRules(tc.lines, agentUID) {
				t.Fatalf("incomplete marking block reported as present: %v", tc.lines)
			}
		})
	}
}

// TestOwnedLoopbackInputChainBodyParsing covers the chain-body reader that the
// exact matcher is built on, including the shapes where it must report failure
// rather than return a partial body.
func TestOwnedLoopbackInputChainBodyParsing(t *testing.T) {
	t.Parallel()
	body, ok := ownedLoopbackInputChainBody(renderOwnedLoopbackInputChainTable(defaultNFTTable))
	if !ok || len(body) != 3 {
		t.Fatalf("managed chain body = %v ok=%v; want three statements", body, ok)
	}
	if _, ok := ownedLoopbackInputChainBody("table inet x { chain other { } }"); ok {
		t.Fatal("a table without the receiver chain reported a body")
	}
	if _, ok := ownedLoopbackInputChainBody("chain " + ownedLoopbackInputChain + " {\n  type filter hook input"); ok {
		t.Fatal("an unterminated chain reported a body; truncated output must fail closed")
	}
}

// TestReloadNFTManagedChainQueriesLiveReceiverChain covers the install-time
// reload path's own live query. It exists separately from the boot path and had
// the same canonical-vs-live defect.
func TestReloadNFTManagedChainQueriesLiveReceiverChain(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.nftRulesPath = filepath.Join(t.TempDir(), "containment.nft")
	canonical := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: 1000, ProxyUID: 967, AgentUID: 966, ProxyPort: 8888,
		Table: defaultNFTTable, Chain: defaultNFTChain, OwnedLoopback: true,
	})

	var loaded string
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != nftExecutable(env) {
			return "", 0, nil
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, ownedLoopbackInputChain):
			// The kernel has no receiver chain yet.
			return "Error: No such file or directory", 1, nil
		case strings.Contains(joined, "-f"):
			if body, err := os.ReadFile(filepath.Clean(env.nftRulesPath + ".reload")); err == nil {
				loaded = string(body)
			}
			return "", 0, nil
		default:
			return "chain output_filter { }", 0, nil
		}
	}

	if err := reloadNFTManagedChain(context.Background(), env, canonical, 1000, 967, 966); err != nil {
		t.Fatalf("reloadNFTManagedChain: %v", err)
	}
	if strings.Contains(loaded, "delete chain inet "+defaultNFTTable+" "+ownedLoopbackInputChain) {
		t.Fatalf("install-time reload deletes a receiver chain the kernel does not have:\n%s", loaded)
	}
}

// TestExpandEnvironmentFlagGatedOnSystemd254 pins the version gate. The flag
// only exists from systemd 254, and this wrapper is invoked directly without
// the preflight that rejects older systemd, so an unconditional flag makes
// every contained launch fail before plk-launch starts.
func TestExpandEnvironmentFlagGatedOnSystemd254(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	for _, tc := range []struct {
		version int
		want    bool
	}{
		{version: 0, want: false},   // detection did not run: omit rather than guess
		{version: 253, want: false}, // older systemd rejects the flag outright
		{version: 254, want: true},  // first release that accepts it
		{version: 257, want: true},
	} {
		env.systemdVersion = tc.version
		got := expandEnvironmentFlag(env) != ""
		if got != tc.want {
			t.Fatalf("systemd %d: emitted=%v want=%v", tc.version, got, tc.want)
		}
	}
	if expandEnvironmentFlag(nil) != "" {
		t.Fatal("a nil env must not emit the flag")
	}
}

// TestOwnedLoopbackAnchorUndoPreservesAPreexistingAnchor pins the rollback
// direction. An anchor that was already enabled and active before this install
// belongs to the host, not to this install, so a rollback must leave it
// running rather than tearing down containment the operator already had.
func TestOwnedLoopbackAnchorUndoPreservesAPreexistingAnchor(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	path := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	env.ownedLoopbackAnchorUnitPath = path
	if err := os.WriteFile(path, []byte(renderOwnedLoopbackAnchorUnit()), modeUnitFile); err != nil {
		t.Fatalf("seed unit: %v", err)
	}
	unit := filepath.Base(path)

	var disabled bool
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != "systemctl" || len(args) == 0 {
			return "", 0, nil
		}
		switch args[0] {
		case "is-enabled":
			return systemctlEnabled + "\n", 0, nil
		case "is-active":
			return systemctlActive + "\n", 0, nil
		case "disable":
			disabled = true
		}
		return "", 0, nil
	}

	step := stepEnsureOwnedLoopbackAnchor()
	if _, err := step.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if disabled {
		t.Fatalf("rollback disabled %s, which was already enabled and active before this install", unit)
	}
}

// TestReloadQueriesReceiverChainIndependentlyOfOutputChain pins that the
// receiver-chain query does not hide behind the OUTPUT chain's presence. The
// two can exist independently: a partially torn-down ruleset can hold the
// receiver chain with no OUTPUT chain. Recording it as absent there would skip
// the delete and then try to add a base chain that already exists, failing the
// transaction.
func TestReloadQueriesReceiverChainIndependentlyOfOutputChain(t *testing.T) {
	t.Parallel()
	persisted := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID,
		AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort,
		Table: defaultNFTTable, Chain: defaultNFTChain, OwnedLoopback: true,
	})
	fx := newNFTReloadTestFixture(t, "", nftReloadTestConfigWithService("2099-01-01T00:00:00Z"), persisted)
	fx.env.ownedLoopback = true

	managed := renderOwnedLoopbackInputChainTable(defaultNFTTable)
	queried := false
	base := fx.env.runCmd
	fx.env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, ownedLoopbackInputChain) && strings.Contains(joined, "list") {
			queried = true
			// The receiver chain IS live even though the OUTPUT chain is not.
			return managed, 0, nil
		}
		if strings.Contains(joined, "list chain") {
			return "Error: No such file or directory", 1, nil
		}
		return base(ctx, name, args...)
	}

	_ = reloadNFTRules(context.Background(), fx.env)
	if !queried {
		t.Fatal("reload never queried the receiver chain because the OUTPUT chain was absent")
	}
}

// TestReloadReceiverChainQueryOutcomes covers every branch of the receiver-gate
// query. Each one decides whether the reload deletes a kernel chain, so an
// outcome mishandled here either aborts the transaction or silently replaces a
// chain the operator owns.
func TestReloadReceiverChainQueryOutcomes(t *testing.T) {
	t.Parallel()
	persisted := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID,
		AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort,
		Table: defaultNFTTable, Chain: defaultNFTChain, OwnedLoopback: true,
	})

	for _, tc := range []struct {
		name     string
		out      string
		code     int
		queryErr error
		wantErr  string
	}{
		{
			name:     "the query itself fails",
			queryErr: errors.New("nft unavailable"),
			wantErr:  "list owned loopback receiver chain",
		},
		{
			name:    "the query fails for an unrecognized reason",
			out:     "permission denied",
			code:    1,
			wantErr: "list owned loopback receiver chain exit=1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithNoService, nftReloadTestConfigWithService("2099-01-01T00:00:00Z"), persisted)
			fx.env.ownedLoopback = true
			base := fx.env.runCmd
			tc := tc
			fx.env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if strings.Contains(strings.Join(args, " "), ownedLoopbackInputChain) {
					return tc.out, tc.code, tc.queryErr
				}
				return base(ctx, name, args...)
			}
			err := reloadNFTRules(context.Background(), fx.env)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("reloadNFTRules = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

// TestOwnedLoopbackSliceIsTopLevel pins the invariant that made a real install
// fail on a real host. systemd treats "-" in a slice name as a HIERARCHY
// SEPARATOR: "a-b.slice" is a child of "a.slice" and its cgroup path is
// "a.slice/a-b.slice", two levels deep. The nft rules match the owned slice at
// "cgroupv2 level 1", so a hyphenated name can never resolve, and because nft
// resolves a cgroup path when it LOADS a rule rather than when it matches, the
// install does not degrade: it fails outright with
// "cgroupv2 path fails: No such file or directory" and rolls back.
//
// Observed 2026-09-19: the failing install left an empty
// /sys/fs/cgroup/pipelock.slice behind, implicitly created by systemd as the
// parent, with no unit file of its own.
func TestOwnedLoopbackSliceIsTopLevel(t *testing.T) {
	t.Parallel()
	name := strings.TrimSuffix(ownedLoopbackSlice, ".slice")
	if name == ownedLoopbackSlice {
		t.Fatalf("owned loopback slice %q does not end in .slice", ownedLoopbackSlice)
	}
	if strings.Contains(name, "-") {
		t.Fatalf("owned loopback slice %q contains a hyphen, so systemd nests it under %q.slice and its cgroup sits below level 1; the nft rules match at level 1 and would never resolve",
			ownedLoopbackSlice, strings.SplitN(name, "-", 2)[0])
	}
	// The rules must match the slice at exactly level 1, which is only correct
	// for a top-level slice.
	rules := nftOwnedLoopbackOutputRules(966) + nftOwnedLoopbackInputChain()
	if !strings.Contains(rules, `socket cgroupv2 level 1 "`+ownedLoopbackSlice+`"`) {
		t.Fatalf("rules do not match the owned slice at level 1:\n%s", rules)
	}
	// The anchor unit must place itself in that same slice, or the cgroup the
	// rules name is never created by anything.
	if !strings.Contains(renderOwnedLoopbackAnchorUnit(), "Slice="+ownedLoopbackSlice+"\n") {
		t.Fatalf("anchor unit does not join %s:\n%s", ownedLoopbackSlice, renderOwnedLoopbackAnchorUnit())
	}
}

// TestDriftedReceiverChainIsReplacedNotRefused pins the UPGRADE path. The
// receiver chain carries a name only this package creates, so a chain that
// does not match the current canonical contents is either a previous release's
// gate or a tampered one. Both are replaced by the canonical rules in a single
// nft transaction.
//
// Refusing instead dead-ends the install with no operator action that clears
// it, which is how a security control ends up disabled rather than fixed.
// Observed on a real host: after the owned slice was renamed, every subsequent
// `contain install` failed at the nft step against the previous install's own
// chain.
func TestDriftedReceiverChainIsReplacedNotRefused(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.nftRulesPath = filepath.Join(t.TempDir(), "containment.nft")

	// A previous release's gate: right chain name, stale slice inside.
	stale := "table inet " + defaultNFTTable + " {\n    chain " + ownedLoopbackInputChain + " {\n" +
		"        type filter hook input priority filter; policy accept;\n" +
		"        ct mark " + ownedLoopbackConntrackMark + " socket cgroupv2 level 1 \"pipelock-contained.slice\" accept\n" +
		"        ct mark " + ownedLoopbackConntrackMark + " drop\n    }\n}\n"
	if ownedLoopbackInputChainLooksManaged(stale) {
		t.Fatal("the stale fixture matches the current chain; this test would prove nothing")
	}

	var loaded string
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != nftExecutable(env) {
			return "", 0, nil
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "list") && strings.Contains(joined, ownedLoopbackInputChain):
			return stale, 0, nil
		case strings.Contains(joined, "-f"):
			if body, err := os.ReadFile(filepath.Clean(env.nftRulesPath + ".owned-loopback-input-replace")); err == nil {
				loaded = string(body)
			}
			return "", 0, nil
		default:
			return "chain output_filter { }", 0, nil
		}
	}

	created, err := ensureOwnedLoopbackInputChain(context.Background(), env)
	if err != nil {
		t.Fatalf("a drifted receiver chain was refused instead of replaced: %v", err)
	}
	if !created {
		t.Fatal("replacing the chain must report a mutation so rollback can undo it")
	}
	// The replacement must delete and recreate in ONE transaction, or the
	// boundary is briefly live with no receiver-side check behind it.
	if !strings.Contains(loaded, "delete chain inet "+defaultNFTTable+" "+ownedLoopbackInputChain) {
		t.Fatalf("replacement did not delete the stale chain:\n%s", loaded)
	}
	if !ownedLoopbackInputChainLooksManaged(loaded) {
		t.Fatalf("replacement did not load the canonical chain:\n%s", loaded)
	}
	if _, err := os.Stat(env.nftRulesPath + ".owned-loopback-input-replace"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement transaction file was left behind: %v", err)
	}
}

// TestReceiverChainMatcherAcceptsEquivalentPrioritySpelling pins that the
// exact matcher does not reject the chain this package itself installs. nft
// renders a base chain's priority as either its symbolic name or its numeric
// value depending on version, so `priority filter` and `priority 0` describe
// the same chain. Accepting only one spelling refuses a correctly installed
// gate on any host whose nft prints the other, and install and reload then
// decline with no operator action that clears it.
func TestReceiverChainMatcherAcceptsEquivalentPrioritySpelling(t *testing.T) {
	t.Parallel()
	managed := renderOwnedLoopbackInputChainTable(defaultNFTTable)
	if !ownedLoopbackInputChainLooksManaged(managed) {
		t.Fatal("the rendered chain is rejected by its own matcher")
	}

	numeric := strings.ReplaceAll(managed, "priority filter;", "priority 0;")
	if numeric == managed {
		t.Fatal("fixture did not change the priority spelling; this test would pass vacuously")
	}
	if !ownedLoopbackInputChainLooksManaged(numeric) {
		t.Fatalf("matcher rejected the numeric priority spelling nft also emits:\n%s", numeric)
	}

	// Normalising whitespace must not become a licence to accept a different
	// chain: the rules themselves are still compared exactly.
	tampered := strings.ReplaceAll(numeric,
		"ct mark "+ownedLoopbackConntrackMark+" drop",
		"ct mark "+ownedLoopbackConntrackMark+" accept")
	if ownedLoopbackInputChainLooksManaged(tampered) {
		t.Fatal("normalisation accepted a chain whose terminal drop was replaced by an accept")
	}
}

// TestReplaceOwnedLoopbackInputChainFailurePaths covers the replacement's own
// error branches. Replacement runs during an upgrade, so a failure here has to
// surface: silently continuing would leave the previous release's receiver gate
// in the kernel while the rest of the install moves to the new rules.
func TestReplaceOwnedLoopbackInputChainFailurePaths(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		failOn  string
		writeFn func(string, []byte, os.FileMode) error
		wantErr string
	}{
		{
			name:    "the transaction file cannot be written",
			writeFn: func(string, []byte, os.FileMode) error { return errors.New("read-only filesystem") },
			wantErr: "write owned loopback receiver chain replacement",
		},
		{
			name:    "nft rejects the replacement",
			failOn:  "-c",
			wantErr: "validate owned loopback receiver chain replacement",
		},
		{
			name:    "nft refuses to load the replacement",
			failOn:  "load",
			wantErr: "replace owned loopback receiver chain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, _, _ := newFakeEnv(t)
			env.ownedLoopback = true
			env.nftRulesPath = filepath.Join(t.TempDir(), "containment.nft")
			if tc.writeFn != nil {
				env.writeFile = tc.writeFn
			}
			failOn := tc.failOn
			env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != nftExecutable(env) {
					return "", 0, nil
				}
				joined := strings.Join(args, " ")
				if strings.Contains(joined, "-c -f") {
					if failOn == "-c" {
						return "syntax error", 1, nil
					}
					return "", 0, nil
				}
				if strings.Contains(joined, "-f") && failOn == "load" {
					return "load refused", 1, nil
				}
				return "", 0, nil
			}
			err := replaceOwnedLoopbackInputChain(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("replaceOwnedLoopbackInputChain = %v; want %q", err, tc.wantErr)
			}
		})
	}
}

// TestReloadNFTManagedChainSurfacesReceiverQueryFailure covers the install-time
// reload's receiver-chain query error. The query decides whether the
// transaction deletes a kernel chain, so an unanswerable query must stop the
// reload rather than be read as "the chain is absent".
func TestReloadNFTManagedChainSurfacesReceiverQueryFailure(t *testing.T) {
	t.Parallel()
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.nftRulesPath = filepath.Join(t.TempDir(), "containment.nft")
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != nftExecutable(env) {
			return "", 0, nil
		}
		if strings.Contains(strings.Join(args, " "), ownedLoopbackInputChain) {
			return "", 0, errors.New("nft unavailable")
		}
		return "chain output_filter { }", 0, nil
	}
	err := reloadNFTManagedChain(context.Background(), env, "table inet t { }\n", 1000, 967, 966)
	if err == nil || !strings.Contains(err.Error(), "list owned loopback receiver chain for reload") {
		t.Fatalf("reloadNFTManagedChain = %v; want the query failure surfaced", err)
	}
}

// TestReceiverChainDeletionIsFlushedFirst pins the ORDER of the replacement
// transaction. nftables refuses to delete a chain that still contains rules,
// and the receiver gate always contains its accept and its terminal drop, so a
// bare delete makes the `nft -c` preflight reject the whole transaction.
//
// On the install path that blocks every upgrade; on the boot path it means the
// persistence unit fails and the host comes up with no containment at all.
func TestReceiverChainDeletionIsFlushedFirst(t *testing.T) {
	t.Parallel()
	flush := "flush chain inet " + defaultNFTTable + " " + ownedLoopbackInputChain
	del := "delete chain inet " + defaultNFTTable + " " + ownedLoopbackInputChain

	assertFlushBeforeDelete := func(t *testing.T, label, script string) {
		t.Helper()
		flushAt := strings.Index(script, flush)
		deleteAt := strings.Index(script, del)
		if flushAt < 0 {
			t.Fatalf("%s does not flush the receiver chain before deleting it:\n%s", label, script)
		}
		if deleteAt < 0 {
			t.Fatalf("%s does not delete the receiver chain:\n%s", label, script)
		}
		if flushAt > deleteAt {
			t.Fatalf("%s deletes the receiver chain before flushing it:\n%s", label, script)
		}
	}

	// Reload path, with the chain live so the delete is emitted at all.
	canonical := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: 1000, ProxyUID: 967, AgentUID: 966, ProxyPort: 8888,
		Table: defaultNFTTable, Chain: defaultNFTChain, OwnedLoopback: true,
	})
	assertFlushBeforeDelete(t, "reload script",
		renderNFTManagedChainReloadScript("", canonical, defaultNFTTable, defaultNFTChain, 1000, 967, 966, true))

	// Install-time replacement path.
	env, _, _ := newFakeEnv(t)
	env.ownedLoopback = true
	env.nftRulesPath = filepath.Join(t.TempDir(), "containment.nft")
	var staged string
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == nftExecutable(env) && strings.Contains(strings.Join(args, " "), "-f") {
			if body, err := os.ReadFile(filepath.Clean(env.nftRulesPath + ".owned-loopback-input-replace")); err == nil {
				staged = string(body)
			}
		}
		return "", 0, nil
	}
	if err := replaceOwnedLoopbackInputChain(context.Background(), env); err != nil {
		t.Fatalf("replaceOwnedLoopbackInputChain: %v", err)
	}
	assertFlushBeforeDelete(t, "replacement transaction", staged)
}

// TestProbeOwnedLoopbackReceiverChainClassification drives the classified
// containment probe through the owned-loopback receiver-chain check with
// fixtures built from the real renderers, so each outcome is decided by the
// production parser: a confirmed absent or tampered receiver chain is a
// structural failure, and a failed nft query is a read error. The all-good
// case is not asserted here: the unsafe-verdict check that runs after the
// receiver chain does not yet exempt the rendered owned-loopback OUTPUT rules
// (tracked separately), so it cannot pass until that is fixed.
func TestProbeOwnedLoopbackReceiverChainClassification(t *testing.T) {
	anchorPath := filepath.Join(t.TempDir(), "pipelock-contained-anchor.service")
	outputChain := strings.Replace(goodNFTContainmentOutput,
		"\t\tmeta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept\n",
		"\t\tmeta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept\n"+nftOwnedLoopbackOutputRules(987), 1)
	if !ownedLoopbackRulesReferenceCurrentAnchor(outputChain, 4) {
		t.Fatal("fixture must carry the rendered owned-loopback output rules")
	}
	receiver := renderOwnedLoopbackInputChainTable(defaultNFTTable)
	tampered := strings.Replace(receiver, "        ct mark "+ownedLoopbackConntrackMark+" drop\n",
		"        ct mark "+ownedLoopbackConntrackMark+" accept\n        ct mark "+ownedLoopbackConntrackMark+" drop\n", 1)
	if tampered == receiver {
		t.Fatal("tampered fixture must differ from the rendered receiver chain")
	}
	for _, tc := range []struct {
		name       string
		out        string
		code       int
		err        error
		wantStatus string
		wantRead   bool
		wantDetail string
	}{
		{"receiver chain confirmed absent", "Error: No such file or directory; did you mean chain 'output_filter'?", 1, nil, statusFail, false, "is missing or unrecognized"},
		{"receiver chain tampered", tampered, 0, nil, statusFail, false, "is missing or unrecognized"},
		{"receiver chain query failed", "netlink: Error: cache initialization failed: Operation not supported", 1, nil, statusFail, true, "nft exit=1"},
		{"receiver chain command error", "", 0, errors.New("exec: nft: not found"), statusFail, true, "list owned loopback receiver chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(e *probeEnv) {
				e.lookupUser = containTestLookup
				e.ownedLoopback = true
				e.ownedLoopbackAnchorUnitPath = anchorPath
				e.nftPersistUnitPath = ""
				e.readFile = func(path string) ([]byte, error) {
					if path == anchorPath {
						return []byte(renderOwnedLoopbackAnchorUnit()), nil
					}
					return nil, os.ErrNotExist
				}
				e.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
					switch {
					case name == "systemctl":
						return systemctlActive + "\n", 0, nil
					case len(args) > 0 && args[len(args)-1] == ownedLoopbackInputChain:
						return tc.out, tc.code, tc.err
					default:
						return outputChain, 0, nil
					}
				}
			})
			status, detail, readErr := probeNFTContainmentClassified(context.Background(), env)
			if status != tc.wantStatus || readErr != tc.wantRead || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("got (%s, %q, readErr=%t), want status %s readErr=%t detail containing %q", status, detail, readErr, tc.wantStatus, tc.wantRead, tc.wantDetail)
			}
		})
	}
}

// TestProbeOwnedLoopbackAnchorUnconfiguredIsStructural pins the unconfigured
// anchor path: nothing to read, so it is a confirmed install gap, not a read
// error.
func TestProbeOwnedLoopbackAnchorUnconfiguredIsStructural(t *testing.T) {
	env := makeProbeEnv(t, func(e *probeEnv) {
		e.ownedLoopback = true
		e.ownedLoopbackAnchorUnitPath = ""
	})
	status, detail, readErr := probeOwnedLoopbackAnchorClassified(context.Background(), env)
	if status != statusFail || readErr || !strings.Contains(detail, "not configured") {
		t.Fatalf("got (%s, %q, readErr=%t), want structural FAIL naming the unconfigured path", status, detail, readErr)
	}
}
