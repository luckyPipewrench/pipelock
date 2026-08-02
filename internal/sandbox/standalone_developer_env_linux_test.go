// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestStandaloneInitControlEnvDoesNotContainDeveloperEnvironment(t *testing.T) {
	const token = "recognizable-api-token-for-control-env-test"
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
	}, `{"workspace":"/workspace"}`, true)

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

func TestLaunchStandaloneDeveloperEnvironmentReachesOnlyFinalCommand(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()
	const token = "recognizable-api-token-for-final-command-test"

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"sh", "-c", "test \"$API_TOKEN\" = \"$EXPECTED_TOKEN\" && test -n \"$HTTP_PROXY\" && test -n \"$HTTPS_PROXY\" && test -z \"$NO_PROXY\" && test -z \"$no_proxy\" && test -z \"$Http_Proxy\" && test -z \"$ALL_proxy\" && test ! -e /proc/self/fd/3 && { test ! -e /proc/$PPID/fd/3 || ! readlink /proc/$PPID/fd/3 | grep -q '^pipe:'; } && ! tr '\\000' '\\n' < \"/proc/$PPID/environ\" | grep -F -q -- \"$EXPECTED_TOKEN\""},
		Workspace: workspace,
		DeveloperEnvironment: []string{
			"PATH=" + os.Getenv("PATH"),
			"API_TOKEN=" + token,
			"EXPECTED_TOKEN=" + token,
			"Http_Proxy=http://attacker.invalid",
			"ALL_proxy=socks5://attacker.invalid",
			"NO_proxy=*",
		},
		UseDeveloperEnvironment: true,
	})
	if err != nil {
		t.Fatalf("LaunchStandalone: %v", err)
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
