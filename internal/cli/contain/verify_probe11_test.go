// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Probe 11 is the post-install self-test: invoke plk-launch with a
// sentinel tool and assert it exits 5 (denied by allow-list). These
// tests verify the probe's classification of every relevant plk-launch
// exit code.

const probe11Sentinel = "pipelock-probe-sentinel-not-a-real-tool"

func TestProbeCCLaunchAllowList_PassOnExit5(t *testing.T) {
	env := makeProbeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return "plk-launch: tool " + probe11Sentinel + " not in pipelock contain allow-list", 5, nil
	}
	status, _ := probeCCLaunchAllowList(context.Background(), env)
	if status != statusPass {
		t.Errorf("status: %s, want pass", status)
	}
}

func TestProbeCCLaunchAllowList_FailOnExit0Bypass(t *testing.T) {
	env := makeProbeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return "executed sentinel — uh oh", 0, nil
	}
	status, detail := probeCCLaunchAllowList(context.Background(), env)
	if status != statusFail {
		t.Errorf("status: %s, want fail", status)
	}
	if !strings.Contains(detail, "bypass") {
		t.Errorf("detail missing bypass hint: %s", detail)
	}
}

func TestProbeCCLaunchAllowList_FailOnExit4ToolsListUnreadable(t *testing.T) {
	env := makeProbeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return "plk-launch: missing allow-list at /etc/pipelock/contain/tools.list", 4, nil
	}
	status, detail := probeCCLaunchAllowList(context.Background(), env)
	if status != statusFail {
		t.Errorf("status: %s, want fail", status)
	}
	if !strings.Contains(detail, "unreadable") {
		t.Errorf("detail: %s", detail)
	}
}

func TestProbeCCLaunchAllowList_SkipOnSudoRefusal(t *testing.T) {
	env := makeProbeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return testSudoNeedsPwd, 1, nil
	}
	status, detail := probeCCLaunchAllowList(context.Background(), env)
	if status != statusSkip {
		t.Errorf("status: %s, want skip", status)
	}
	if !strings.Contains(detail, "NOPASSWD") {
		t.Errorf("detail: %s", detail)
	}
}

func TestProbeCCLaunchAllowList_SkipOnMissingCCAgent(t *testing.T) {
	env := makeProbeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return "sudo: unknown user pipelock-agent", 1, nil
	}
	status, detail := probeCCLaunchAllowList(context.Background(), env)
	if status != statusSkip {
		t.Errorf("status: %s, want skip", status)
	}
	if !strings.Contains(detail, "pipelock-agent user missing") {
		t.Errorf("detail: %s", detail)
	}
}

func TestProbeCCLaunchAllowList_SkipOnMissingLauncher(t *testing.T) {
	env := makeProbeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return "sudo: plk-launch: command not found", 1, nil
	}
	status, detail := probeCCLaunchAllowList(context.Background(), env)
	if status != statusSkip {
		t.Errorf("status: %s, want skip", status)
	}
	if !strings.Contains(detail, "plk-launch missing") {
		t.Errorf("detail: %s", detail)
	}
}

func TestProbeCCLaunchAllowList_FailOnUnexpectedExit(t *testing.T) {
	env := makeProbeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return "plk-launch: target /nope is not executable", 8, nil
	}
	status, detail := probeCCLaunchAllowList(context.Background(), env)
	if status != statusFail {
		t.Errorf("status: %s, want fail", status)
	}
	if !strings.Contains(detail, "exit 8") {
		t.Errorf("detail: %s", detail)
	}
}

func TestProbeCCLaunchAllowList_SkipOnRunErr(t *testing.T) {
	env := makeProbeEnv(t)
	env.runCmd = func(_ context.Context, _ string, _ ...string) (string, int, error) {
		return "", -1, fmt.Errorf("exec failed")
	}
	status, _ := probeCCLaunchAllowList(context.Background(), env)
	if status != statusSkip {
		t.Errorf("status: %s, want skip", status)
	}
}

func TestProbeListedToolTargets_PassWithExplicitTarget(t *testing.T) {
	env := makeProbeEnv(t)
	target := filepath.Join(t.TempDir(), "claude")
	writeFakeWrapper(t, target, 0o755)
	env.readFile = func(path string) ([]byte, error) {
		if path == env.toolsListPath {
			return []byte("claude\t" + target + "\n"), nil
		}
		return nil, fmt.Errorf("unexpected readFile %s", path)
	}
	status, detail := probeListedToolTargets(context.Background(), env)
	if status != statusPass {
		t.Fatalf("status: %s detail=%s", status, detail)
	}
}

func TestProbeListedToolTargets_FailsWhenPathLookupMissing(t *testing.T) {
	env := makeProbeEnv(t)
	env.stat = func(path string) (os.FileInfo, error) {
		if strings.Contains(path, "/claude") {
			return nil, os.ErrNotExist
		}
		return os.Stat(path)
	}
	env.readFile = func(path string) ([]byte, error) {
		if path == env.toolsListPath {
			return []byte("claude\t\n"), nil
		}
		return nil, fmt.Errorf("unexpected readFile %s", path)
	}
	status, detail := probeListedToolTargets(context.Background(), env)
	if status != statusFail {
		t.Fatalf("status: %s detail=%s", status, detail)
	}
	if !strings.Contains(detail, "claude not found in pipelock-agent PATH") {
		t.Fatalf("detail: %s", detail)
	}
}

func TestProbeListedToolTargets_PassWithAgentPathLookup(t *testing.T) {
	env := makeProbeEnv(t)
	agentHomeBin := filepath.Join(t.TempDir(), "home", testAgentUser, ".local", "bin")
	env.agentUserName = testAgentUser
	env.stat = func(path string) (os.FileInfo, error) {
		if path == "/home/"+testAgentUser+"/.local/bin/claude" {
			return os.Stat(filepath.Join(agentHomeBin, "claude"))
		}
		return os.Stat(path)
	}
	if err := os.MkdirAll(agentHomeBin, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFakeWrapper(t, filepath.Join(agentHomeBin, "claude"), 0o755)
	env.readFile = func(path string) ([]byte, error) {
		if path == env.toolsListPath {
			return []byte("claude\t\n"), nil
		}
		return nil, fmt.Errorf("unexpected readFile %s", path)
	}
	status, detail := probeListedToolTargets(context.Background(), env)
	if status != statusPass {
		t.Fatalf("status: %s detail=%s", status, detail)
	}
}
