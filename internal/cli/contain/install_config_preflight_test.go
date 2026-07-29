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

func TestRunInstall_ConfigPreflightRefusesBeforeServiceMutation(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		failureOut string
		want       []string
	}{
		{
			name: "removed budget field parse failure",
			body: "agents:\n  _default:\n    budget:\n      max_retries_per_endpoint: 2\n",
			failureOut: "Config validation FAILED: parsing config CONFIG: max_retries_per_endpoint was removed because it was not enforced; " +
				"remove it from the config: yaml: unmarshal errors: field max_retries_per_endpoint not found in type config.BudgetConfig\n",
			want: []string{"max_retries_per_endpoint", "removed because it was not enforced", "remove it from the config"},
		},
		{
			name: "reserved concurrent tool limit validation failure",
			body: "agents:\n  _default:\n    budget:\n      max_concurrent_tool_calls: 3\n",
			failureOut: "Config validation FAILED: invalid config: agents._default.budget: " +
				"max_concurrent_tool_calls is not yet enforced; it is reserved for future lease-based concurrency control. Unset it\n",
			want: []string{"max_concurrent_tool_calls", "not yet enforced", "Unset it"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, runner, _ := newPreflightInstallEnv(t)
			src := writePreflightConfig(t, "source.yaml", tt.body)
			target := managedPipelockConfigPath(env)
			// The candidate is checked at its staging path; the binary reports
			// the path it was handed, and the installer rewrites it back to the
			// managed path before the operator sees it.
			staged := stagedPipelockConfigPath(env)
			runner.on(argvFor(env.pipelockBinary, "check", "--config", staged), strings.ReplaceAll(tt.failureOut, "CONFIG", staged), 1, nil)

			err := runInstall(context.Background(), env, installOpts{configSource: src})
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
			if err == nil {
				t.Fatal("runInstall succeeded, want config preflight failure")
			}
			for _, want := range append([]string{target, "selected binary", env.pipelockBinary}, tt.want...) {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want substring %q", err, want)
				}
			}
			if strings.Contains(err.Error(), staged) {
				t.Fatalf("staging path leaked into the operator-facing error: %q", err)
			}
			if _, statErr := os.Stat(env.pipelockTarget); !os.IsNotExist(statErr) {
				t.Fatalf("installed binary changed before preflight refusal: stat err=%v", statErr)
			}
		})
	}
}

func TestRunInstall_ConfigPreflightRefusesMissingManagedConfigBeforeServiceMutation(t *testing.T) {
	env, runner, _ := newPreflightInstallEnv(t)
	if err := os.WriteFile(env.caExportPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatalf("write ca export: %v", err)
	}
	target := managedPipelockConfigPath(env)

	err := runInstall(context.Background(), env, installOpts{})
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
	if err == nil {
		t.Fatal("runInstall succeeded, want missing managed config preflight failure")
	}
	for _, want := range []string{
		target,
		"--config is required if the managed config is not already in place",
		"No --config was given and no config exists at the managed path",
		"service would start with no configuration",
		"Pass --config",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err, want)
		}
	}
	if _, statErr := os.Stat(env.pipelockTarget); !os.IsNotExist(statErr) {
		t.Fatalf("installed binary changed before preflight refusal: stat err=%v", statErr)
	}
}

func TestRunInstall_ConfigPreflightCoversUpgradeWithoutConfigFlag(t *testing.T) {
	env, runner, _ := newPreflightInstallEnv(t)
	target := managedPipelockConfigPath(env)
	if err := os.WriteFile(target, []byte("agents:\n  _default:\n    budget:\n      fan_out_limit: 4\n"), 0o600); err != nil {
		t.Fatalf("write existing config: %v", err)
	}
	runner.on(argvFor(env.pipelockBinary, "check", "--config", target),
		"Config validation FAILED: parsing config "+target+": fan_out_limit was removed because it was not enforced; remove it from the config\n",
		1, nil)

	err := runInstall(context.Background(), env, installOpts{})
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
	if err == nil {
		t.Fatal("runInstall succeeded, want config preflight failure")
	}
	for _, want := range []string{target, "fan_out_limit", "remove it from the config"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "No --config was given and no config exists") {
		t.Fatalf("invalid existing config used missing-config refusal: %v", err)
	}
}

func TestRunInstall_ConfigPreflightDryRunReportsMissingManagedConfig(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	target := managedPipelockConfigPath(env)

	err := runInstall(context.Background(), env, installOpts{dryRun: true})
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
	if err == nil {
		t.Fatal("dry-run succeeded, want missing managed config preflight failure")
	}
	for _, want := range []string{
		target,
		"--config is required if the managed config is not already in place",
		"No --config was given and no config exists at the managed path",
		"service would start with no configuration",
		"Pass --config",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err, want)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("dry-run missing-config preflight shelled out: %+v", runner.calls)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("dry-run wrote managed config: stat err=%v", statErr)
	}
}

func TestRunInstall_ConfigPreflightDryRunReportsWithoutMutation(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	src := writePreflightConfig(t, "dry-source.yaml", "agents:\n  _default:\n    budget:\n      max_retries_per_endpoint: 2\n")
	target := managedPipelockConfigPath(env)
	runner.on(argvFor(env.pipelockBinary, "check", "--config", src),
		"Config validation FAILED: parsing config "+src+": max_retries_per_endpoint was removed because it was not enforced; remove it from the config\n",
		1, nil)

	err := runInstall(context.Background(), env, installOpts{dryRun: true, configSource: src})
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
	if err == nil {
		t.Fatal("dry-run succeeded, want config preflight failure")
	}
	for _, want := range []string{target, "max_retries_per_endpoint", "remove it from the config"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err, want)
		}
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("dry-run wrote managed config: stat err=%v", statErr)
	}
}

func TestRunInstall_ConfigPreflightAllowsCleanConfig(t *testing.T) {
	env, runner, buf := newPreflightInstallEnv(t)
	if err := os.WriteFile(env.caExportPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatalf("write ca export: %v", err)
	}
	src := writePreflightConfig(t, "clean.yaml", "mode: balanced\n")
	if _, statErr := os.Stat(managedPipelockConfigPath(env)); !os.IsNotExist(statErr) {
		t.Fatalf("managed config exists before fresh install: stat err=%v", statErr)
	}

	if err := runInstall(context.Background(), env, installOpts{configSource: src}); err != nil {
		t.Fatalf("runInstall: %v\noutput:\n%s\ncalls:%+v", err, buf.String(), runner.calls)
	}
	assertSawCall(t, runner, env.pipelockBinary, "check", "--config", stagedPipelockConfigPath(env))
	assertSawCall(t, runner, testSystemctl, "enable", "--now", "pipelock")
	// The staged candidate is promoted to the managed path and the staging file
	// is discarded, so a successful install leaves no residue behind.
	if _, statErr := os.Stat(stagedPipelockConfigPath(env)); !os.IsNotExist(statErr) {
		t.Fatalf("staged config survived a successful install: stat err=%v", statErr)
	}
	got, err := os.ReadFile(filepath.Clean(managedPipelockConfigPath(env)))
	if err != nil {
		t.Fatalf("read managed config: %v", err)
	}
	if string(got) != "mode: balanced\n" {
		t.Fatalf("managed config = %q, want the promoted candidate", got)
	}
}

// TestRunInstall_ConfigPreflightNeverMakesTheCandidateLive pins the guarantee
// staging exists for, by observing the managed path at the one moment that
// distinguishes staging from the previous ordering: while preflight is running.
//
// An end-state assertion cannot prove this. The step runner rolls back a failed
// install, so under the previous ordering the managed config was written, found
// unacceptable, and restored, ending exactly where it started. What changed is
// the window in between, during which a crash or a concurrent reload would have
// observed a config the binary had already refused. The probe therefore reads
// the managed path from inside the check invocation itself.
func TestRunInstall_ConfigPreflightNeverMakesTheCandidateLive(t *testing.T) {
	env, runner, _ := newPreflightInstallEnv(t)
	target := seedManagedConfig(t, env)
	good, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatalf("read seeded config: %v", err)
	}
	const badBody = "agents:\n  _default:\n    budget:\n      max_retries_per_endpoint: 2\n"
	src := writePreflightConfig(t, "bad.yaml", badBody)
	staged := stagedPipelockConfigPath(env)
	runner.on(argvFor(env.pipelockBinary, "check", "--config", staged), "Config validation FAILED\n", 1, nil)

	var liveDuringPreflight string
	var sawCheck bool
	origRun := env.runCmd
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockBinary && len(args) > 0 && args[0] == "check" {
			sawCheck = true
			if b, readErr := os.ReadFile(filepath.Clean(target)); readErr == nil {
				liveDuringPreflight = string(b)
			} else {
				liveDuringPreflight = "<missing>"
			}
		}
		return origRun(ctx, name, args...)
	}

	if err := runInstall(context.Background(), env, installOpts{configSource: src}); err == nil {
		t.Fatal("runInstall succeeded, want config preflight failure")
	}
	if !sawCheck {
		t.Fatal("config preflight never ran; the probe observed nothing")
	}
	if liveDuringPreflight != string(good) {
		t.Fatalf("managed config during preflight = %q, want the untouched pre-install content %q", liveDuringPreflight, good)
	}
	if _, statErr := os.Stat(staged); !os.IsNotExist(statErr) {
		t.Fatalf("staged candidate survived the refusal: stat err=%v", statErr)
	}
	after, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatalf("managed config missing after refusal: %v", err)
	}
	if string(after) != string(good) {
		t.Fatalf("managed config after refusal = %q, want %q", after, good)
	}
}

func TestRunInstall_ConfigPreflightRefusesBinaryChangedBeforeInstall(t *testing.T) {
	env, runner, _ := newPreflightInstallEnv(t)
	if err := os.WriteFile(env.caExportPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatalf("write ca export: %v", err)
	}
	src := writePreflightConfig(t, "clean.yaml", "mode: balanced\n")

	origChown := env.chown
	mutated := false
	env.chown = func(path string, uid, gid int) error {
		if !mutated {
			mutated = true
			if err := os.WriteFile(env.pipelockBinary, []byte("unchecked replacement binary"), 0o600); err != nil {
				t.Fatalf("mutate source binary: %v", err)
			}
		}
		return origChown(path, uid, gid)
	}

	err := runInstall(context.Background(), env, installOpts{configSource: src})
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
	if err == nil {
		t.Fatal("runInstall succeeded, want binary TOCTOU failure")
	}
	for _, want := range []string{
		"source binary",
		env.pipelockBinary,
		"changed after config preflight",
		"refusing to install an unvalidated binary",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err, want)
		}
	}
	if _, statErr := os.Stat(env.pipelockTarget); !os.IsNotExist(statErr) {
		t.Fatalf("installed binary changed despite preflight race refusal: stat err=%v", statErr)
	}
}

func TestRunInstall_ConfigPreflightAllowsValidExistingManagedConfigWithoutConfigFlag(t *testing.T) {
	env, runner, buf := newPreflightInstallEnv(t)
	if err := os.WriteFile(env.caExportPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatalf("write ca export: %v", err)
	}
	target := seedManagedConfig(t, env)

	if err := runInstall(context.Background(), env, installOpts{}); err != nil {
		t.Fatalf("runInstall: %v\noutput:\n%s\ncalls:%+v", err, buf.String(), runner.calls)
	}
	assertSawCall(t, runner, env.pipelockBinary, "check", "--config", target)
	assertSawCall(t, runner, testSystemctl, "enable", "--now", "pipelock")
}

func TestPreflightPipelockConfigReportsHelperFailures(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *installEnv, *fakeRunner) error
		want string
	}{
		{
			name: "selected binary command error",
			run: func(t *testing.T, env *installEnv, runner *fakeRunner) error {
				t.Helper()
				target := seedManagedConfig(t, env)
				runner.on(argvFor(env.pipelockBinary, "check", "--config", target), "", -1, errors.New("exec failed"))
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "exec failed",
		},
		{
			name: "selected binary nonzero with empty output",
			run: func(t *testing.T, env *installEnv, runner *fakeRunner) error {
				t.Helper()
				target := seedManagedConfig(t, env)
				runner.on(argvFor(env.pipelockBinary, "check", "--config", target), "", 2, nil)
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "pipelock check exited 2",
		},
		{
			name: "selected binary hash before check fails",
			run: func(t *testing.T, env *installEnv, _ *fakeRunner) error {
				t.Helper()
				seedManagedConfig(t, env)
				env.hashFile = func(string) (string, error) {
					return "", errors.New("hash before failed")
				}
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "hash selected binary before check: hash before failed",
		},
		{
			name: "selected binary hash after check fails",
			run: func(t *testing.T, env *installEnv, _ *fakeRunner) error {
				t.Helper()
				seedManagedConfig(t, env)
				origHash := env.hashFile
				calls := 0
				env.hashFile = func(path string) (string, error) {
					calls++
					if calls == 2 {
						return "", errors.New("hash after failed")
					}
					return origHash(path)
				}
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "hash selected binary after check: hash after failed",
		},
		{
			name: "selected binary changes during check",
			run: func(t *testing.T, env *installEnv, runner *fakeRunner) error {
				t.Helper()
				target := seedManagedConfig(t, env)
				runner.on(argvFor(env.pipelockBinary, "check", "--config", target), "", 0, nil)
				origRun := env.runCmd
				env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
					out, code, err := origRun(ctx, name, args...)
					if err := os.WriteFile(env.pipelockBinary, []byte("replacement during check"), 0o600); err != nil {
						t.Fatalf("mutate source binary: %v", err)
					}
					return out, code, err
				}
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "selected binary changed during config check",
		},
		{
			name: "managed config stat error",
			run: func(_ *testing.T, env *installEnv, _ *fakeRunner) error {
				env.stat = func(string) (os.FileInfo, error) {
					return nil, errors.New("stat failed")
				}
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "stat managed config",
		},
		{
			name: "managed config is directory",
			run: func(t *testing.T, env *installEnv, _ *fakeRunner) error {
				t.Helper()
				target := managedPipelockConfigPath(env)
				if err := os.MkdirAll(target, 0o750); err != nil {
					t.Fatalf("mkdir config path: %v", err)
				}
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "is a directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			err := tt.run(t, env, runner)
			if err == nil {
				t.Fatal("preflight succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestStepInstallPipelockBinaryRefusesSourceChangedWhileReading(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.preflightBinaryHash = mustHashFile(t, env, env.pipelockBinary)
	origReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		data, err := origReadFile(path)
		if err != nil {
			return nil, err
		}
		if path == env.pipelockBinary {
			return append([]byte(nil), append(data, []byte("unchecked suffix")...)...), nil
		}
		return data, nil
	}

	changed, err := stepInstallPipelockBinary().apply(context.Background(), env)
	if err == nil {
		t.Fatal("stepInstallPipelockBinary succeeded, want source changed while reading failure")
	}
	if changed {
		t.Fatal("stepInstallPipelockBinary reported change despite refusing source changed while reading")
	}
	for _, want := range []string{
		"source binary",
		env.pipelockBinary,
		"changed while reading after config preflight",
		"refusing to install an unvalidated binary",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err, want)
		}
	}
	if _, statErr := os.Stat(env.pipelockTarget); !os.IsNotExist(statErr) {
		t.Fatalf("installed binary changed despite read-race refusal: stat err=%v", statErr)
	}
}

func mustHashFile(t *testing.T, env *installEnv, path string) string {
	t.Helper()
	hash, err := env.hashFile(path)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hash
}

func newPreflightInstallEnv(t *testing.T) (*installEnv, *fakeRunner, *strings.Builder) {
	t.Helper()
	env, runner, buf := newFakeEnv(t)
	binDir := installContainCommandFixtures(t)
	env.nftPath = filepath.Join(binDir, "nft")
	origStat := env.stat
	env.stat = func(path string) (os.FileInfo, error) {
		if path == env.nftPath {
			return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
		}
		if path == "/usr/local/bin/claude" {
			return origStat(env.pipelockBinary)
		}
		return origStat(path)
	}
	var out strings.Builder
	out.WriteString(buf.String())
	env.out = &out
	env.errOut = &out
	return env, runner, &out
}

func writePreflightConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func seedManagedConfig(t *testing.T, env *installEnv) string {
	t.Helper()
	target := managedPipelockConfigPath(env)
	if err := os.WriteFile(target, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("write managed config: %v", err)
	}
	return target
}

func assertNoServiceOrNFTMutationAfterPreflightFailure(t *testing.T, runner *fakeRunner) {
	t.Helper()
	for _, call := range runner.calls {
		if call.name == testSystemctl && containsArg(call.args, "stop") {
			t.Fatalf("systemctl stop reached after config preflight failure: %+v", runner.calls)
		}
		if call.name == testSystemctl && containsArg(call.args, "enable") && containsArg(call.args, "--now") {
			t.Fatalf("systemctl enable --now reached after config preflight failure: %+v", runner.calls)
		}
		if call.name == testNFT && containsArg(call.args, "-f") {
			t.Fatalf("nft load/validate reached after config preflight failure: %+v", runner.calls)
		}
	}
}

func assertSawCall(t *testing.T, runner *fakeRunner, name string, args ...string) {
	t.Helper()
	for _, call := range runner.calls {
		if call.name != name || len(call.args) != len(args) {
			continue
		}
		match := true
		for i := range args {
			if call.args[i] != args[i] {
				match = false
				break
			}
		}
		if match {
			return
		}
	}
	t.Fatalf("missing call %s %s in %+v", name, strings.Join(args, " "), runner.calls)
}
