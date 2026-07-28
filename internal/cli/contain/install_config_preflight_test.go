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
			runner.on(argvFor(env.pipelockBinary, "check", "--config", target), strings.ReplaceAll(tt.failureOut, "CONFIG", target), 1, nil)

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
			if _, statErr := os.Stat(env.pipelockTarget); !os.IsNotExist(statErr) {
				t.Fatalf("installed binary changed before preflight refusal: stat err=%v", statErr)
			}
		})
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

	if err := runInstall(context.Background(), env, installOpts{configSource: src}); err != nil {
		t.Fatalf("runInstall: %v\noutput:\n%s\ncalls:%+v", err, buf.String(), runner.calls)
	}
	assertSawCall(t, runner, env.pipelockBinary, "check", "--config", managedPipelockConfigPath(env))
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
				target := seedManagedConfig(t, env, "mode: balanced\n")
				runner.on(argvFor(env.pipelockBinary, "check", "--config", target), "", -1, errors.New("exec failed"))
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "exec failed",
		},
		{
			name: "selected binary nonzero with empty output",
			run: func(t *testing.T, env *installEnv, runner *fakeRunner) error {
				t.Helper()
				target := seedManagedConfig(t, env, "mode: balanced\n")
				runner.on(argvFor(env.pipelockBinary, "check", "--config", target), "", 2, nil)
				return preflightPipelockConfig(context.Background(), env, installOpts{}, false)
			},
			want: "pipelock check exited 2",
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

func seedManagedConfig(t *testing.T, env *installEnv, body string) string {
	t.Helper()
	target := managedPipelockConfigPath(env)
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
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
