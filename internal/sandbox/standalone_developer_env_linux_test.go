// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestStandaloneInitControlEnvDoesNotContainDeveloperEnvironment(t *testing.T) {
	token := "test-" + strings.ReplaceAll(t.Name(), "/", "-")
	cfg := StandaloneLaunchConfig{
		Command:                 []string{"sh", "-c", "true"},
		Workspace:               "/workspace",
		UseDeveloperEnvironment: true,
		DeveloperEnvironment: []string{
			"API_TOKEN=" + token,
			"LD_PRELOAD=/developer/lib/instrument.so",
			"NODE_OPTIONS=--require=/developer/hook.js",
		},
	}
	controlEnv := standaloneInitControlEnv(cfg, "/tmp/pipelock-sandbox-test/proxy.sock", []string{
		"GOCOVERDIR=/tmp/pipelock-covdata-" + token,
		"PIPELOCK_SUBPROCESS_COVERAGE=1",
	}, `{"workspace":"/workspace"}`, true, nil, 0)

	for _, entry := range controlEnv {
		if strings.Contains(entry, token) || strings.Contains(entry, "LD_PRELOAD") || strings.Contains(entry, "NODE_OPTIONS") {
			t.Fatalf("developer value leaked into re-exec control environment: %q", entry)
		}
	}
	// The re-exec argv is only the self-executable path (LaunchStandalone runs
	// exec.CommandContext(ctx, selfExe) with no arguments), so there is no argv
	// for a developer value to leak into; the control-environment check above is
	// the meaningful assertion here.
	if got := envValue(controlEnv, developerEnvironmentControlEnv); got != "3" {
		t.Fatalf("developer environment descriptor = %q, want 3", got)
	}
}

func TestStandaloneCommandJSONPreservesLegacyDelimiterInArgument(t *testing.T) {
	want := []string{"tool", "left\x1fright", "line one\nline two"}
	controlEnv := standaloneInitControlEnv(StandaloneLaunchConfig{
		Command: want, Workspace: "/workspace",
	}, "/tmp/pipelock-sandbox-test/proxy.sock", nil, `{"workspace":"/workspace"}`, true, nil, 0)
	got, err := decodeStandaloneCommand(envValue(controlEnv, standaloneCommandJSONEnv), "")
	if err != nil {
		t.Fatalf("decodeStandaloneCommand: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("command = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := decodeStandaloneCommand("", ""); err == nil || !strings.Contains(err.Error(), "missing command") {
		t.Fatalf("missing legacy command error = %v", err)
	}
	if _, err := decodeStandaloneCommand("", "\x1farg"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("legacy empty command error = %v", err)
	}
}

func TestLaunchStandaloneDeveloperEnvironmentReachesOnlyFinalCommand(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()
	token := "test-" + strings.ReplaceAll(t.Name(), "/", "-")

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"sh", "-c", "test \"$API_TOKEN\" = \"$EXPECTED_TOKEN\" && test -n \"$HTTP_PROXY\" && test -n \"$HTTPS_PROXY\" && test -z \"$NO_PROXY\" && test -z \"$no_proxy\" && test -z \"$Http_Proxy\" && test -z \"$ALL_proxy\" && test ! -e /proc/self/fd/3 && { test ! -e /proc/$PPID/fd/3 || ! readlink /proc/$PPID/fd/3 | grep -q '^pipe:'; } && ! tr '\\000' '\\n' < \"/proc/$PPID/environ\" | grep -F -q -- \"$EXPECTED_TOKEN\""},
		Workspace: workspace,
		DeveloperEnvironment: []string{
			"PATH=" + os.Getenv("PATH"),
			"API_TOKEN=" + token,
			"EXPECTED_TOKEN=" + token,
			"Http_Proxy=http://api.vendor.example",
			"ALL_proxy=socks5://api.vendor.example",
			"NO_proxy=*",
		},
		UseDeveloperEnvironment: true,
	})
	if err != nil {
		t.Fatalf("LaunchStandalone: %v", err)
	}
}

func TestLaunchStandaloneGuardAppliesOnlyToFinalCommand(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o750); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("must stay unreadable"), 0o600); err != nil {
		t.Fatalf("write outside fixture: %v", err)
	}

	developerEnvironment := forceEnvValue(os.Environ(), "PWD", root)
	developerEnvironment = forceEnvValue(developerEnvironment, "TMPDIR", "/tmp")
	developerEnvironment = forceEnvValue(developerEnvironment, "EXPECTED_WORKSPACE", workspace)
	developerEnvironment = forceEnvValue(developerEnvironment, "OUTSIDE_PATH", outside)
	declaration := config.Guard{}
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:                 []string{"sh", "-c", `test -z "$__PIPELOCK_GUARD_EXEC$__PIPELOCK_GUARD_DECLARATION$__PIPELOCK_SANDBOX_POLICY" && test "$PWD" = "$EXPECTED_WORKSPACE" && test "$TMPDIR" != /tmp && : > "$TMPDIR/temp-ok" && printf guarded > result.txt && ! cat "$OUTSIDE_PATH" >/dev/null 2>&1`},
		Workspace:               workspace,
		DeveloperEnvironment:    developerEnvironment,
		UseDeveloperEnvironment: true,
		GuardDeclaration:        &declaration,
		GuardPolicyHash:         "test-policy-hash",
	})
	if err != nil {
		t.Fatalf("LaunchStandalone with Guard: %v", err)
	}
	workspaceRoot, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatalf("open workspace root: %v", err)
	}
	defer func() { _ = workspaceRoot.Close() }()
	result, err := workspaceRoot.ReadFile("result.txt")
	if err != nil {
		t.Fatalf("read command result: %v", err)
	}
	if string(result) != "guarded" {
		t.Fatalf("result = %q, want guarded", result)
	}
}

func TestLaunchStandaloneGuardProofFailureCleansChildTempDir(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()
	declaration := config.Guard{}
	var childTempDir string
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:          []string{"sh", "-c", "true"},
		Workspace:        workspace,
		GuardDeclaration: &declaration,
		GuardPolicyHash:  "test-policy-hash",
		GuardAppliedPreExec: func(tempDir string, _ []byte) error {
			childTempDir = tempDir
			return errors.New("reject proof for cleanup test")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "reject proof for cleanup test") {
		t.Fatalf("LaunchStandalone proof error = %v", err)
	}
	if childTempDir == "" {
		t.Fatal("proof callback did not receive the child temporary directory")
	}
	if _, statErr := os.Stat(childTempDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("child temporary directory remained after proof failure: %v", statErr)
	}
	childPID, parseErr := strconv.Atoi(strings.TrimPrefix(filepath.Base(childTempDir), "pipelock-sandbox-"))
	if parseErr != nil {
		t.Fatalf("parse child PID from %q: %v", childTempDir, parseErr)
	}
	if signalErr := syscall.Kill(childPID, 0); !errors.Is(signalErr, syscall.ESRCH) {
		t.Fatalf("child process %d was not reaped after proof failure: %v", childPID, signalErr)
	}
}

func TestStandaloneChildCleanupReapsOnlyInStrictMode(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(strconv.FormatBool(strict), func(t *testing.T) {
			reaped := false
			stopped := false
			cleanup := standaloneChildCleanup(0, strict, func() { stopped = true }, func() { reaped = true })
			cleanup()
			if reaped != strict {
				t.Fatalf("reaped = %t, want %t", reaped, strict)
			}
			if !stopped {
				t.Fatal("cleanup did not stop the proxy")
			}
		})
	}
}

func TestLaunchStandaloneDeveloperEnvironmentSupportsLargeEnvironment(t *testing.T) {
	skipIfStandaloneUnavailable(t)

	const valueLength = 100 * 1024
	value := strings.Repeat("x", valueLength)
	environment := make([]string, 0, 10)
	environment = append(environment, "PATH="+os.Getenv("PATH"))
	for i := range 9 {
		environment = append(environment, "LARGE_"+strconv.Itoa(i)+"="+value)
	}

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:                 []string{"sh", "-c", "test \"${#LARGE_8}\" -eq 102400"},
		Workspace:               t.TempDir(),
		DeveloperEnvironment:    environment,
		UseDeveloperEnvironment: true,
	})
	if err != nil {
		t.Fatalf("LaunchStandalone: %v", err)
	}
}

func TestLaunchStandaloneDeveloperEnvironmentFailsClosedBeforeChildStart(t *testing.T) {
	workspace := t.TempDir()
	// These cases are rejected by LaunchStandalone BEFORE the namespace probe
	// (the nil-environment and ExtraEnv-conflict guards), so they fail closed on
	// any host and can be asserted by exact reason. Duplicate-key rejection
	// happens later, inside newDeveloperEnvironmentPipe after the probe, so a
	// LaunchStandalone-level case there could pass for the wrong reason on a host
	// without namespaces; that path is covered deterministically by
	// TestDeveloperEnvironmentCodecFailsClosed instead.
	for _, testCase := range []struct {
		name    string
		cfg     StandaloneLaunchConfig
		wantErr string
	}{
		{
			name: "nil environment",
			cfg: StandaloneLaunchConfig{
				Command:                 []string{"true"},
				Workspace:               workspace,
				UseDeveloperEnvironment: true,
			},
			wantErr: "developer environment is required",
		},
		{
			name: "extra environment conflict",
			cfg: StandaloneLaunchConfig{
				Command:                 []string{"true"},
				Workspace:               workspace,
				DeveloperEnvironment:    []string{},
				UseDeveloperEnvironment: true,
				ExtraEnv:                []string{"UNSAFE=1"},
			},
			wantErr: "cannot be combined with extra environment",
		},
		{
			name: "best effort not permitted",
			cfg: StandaloneLaunchConfig{
				Command:                 []string{"true"},
				Workspace:               workspace,
				DeveloperEnvironment:    []string{"OPENAI_API_KEY" + "=" + "preserved-developer-value"},
				UseDeveloperEnvironment: true,
				BestEffort:              true,
			},
			wantErr: "best_effort is not permitted",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := LaunchStandalone(testCase.cfg)
			if err == nil {
				t.Fatal("LaunchStandalone accepted unsafe developer environment configuration")
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, testCase.wantErr)
			}
		})
	}
}
