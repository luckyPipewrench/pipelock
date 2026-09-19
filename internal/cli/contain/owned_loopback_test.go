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
	script := renderNFTManagedChainReloadScript("", body, defaultNFTTable, defaultNFTChain, 1000, 967, 966)
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
	if !ownedLoopbackRulesReferenceCurrentAnchor(`socket cgroupv2 level 1 "pipelock-contained.slice"`, 1) {
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
		{
			name:      "receiver chain present but unrecognizable",
			chainOut:  "chain " + ownedLoopbackInputChain + " { type filter hook input priority filter; policy accept; }",
			chainCode: 0,
			wantErr:   "not recognizable",
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

			err := ensureOwnedLoopbackInputChain(context.Background(), env)
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
	if err := ensureOwnedLoopbackInputChain(context.Background(), env); err != nil {
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

	if err := ensureOwnedLoopbackInputChain(context.Background(), env); err != nil {
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
			err := ensureOwnedLoopbackInputChain(context.Background(), env)
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
			err := ensureOwnedLoopbackInputChain(context.Background(), env)
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

	base := fx.env.runCmd
	fx.env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if strings.Contains(strings.Join(args, " "), ownedLoopbackInputChain) {
			// The receiver gate is gone: an interrupted migration, or someone
			// flushed the table by hand.
			return "Error: No such file or directory", 1, nil
		}
		return base(ctx, name, args...)
	}

	err := reloadNFTRules(context.Background(), fx.env)
	if err == nil || !strings.Contains(err.Error(), "missing or unrecognized") {
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
