// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootFilesystemCanary(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("PIPELOCK_TEST_ROOT_CANARY") != "1" {
		t.Skip("requires root and PIPELOCK_TEST_ROOT_CANARY=1")
	}
	agent, err := user.Lookup(defaultAgentUser)
	if err != nil {
		t.Skipf("%s user does not exist: %v", defaultAgentUser, err)
	}
	if strings.TrimSpace(os.Getenv("SUDO_USER")) == "" {
		t.Skip("SUDO_USER is unset; run this test through sudo from the operator account")
	}

	before := filesystemCanaryUnits(t)
	t.Run("pass", func(t *testing.T) {
		env := rootFilesystemCanaryEnv(t, agent)
		status, detail := probeFilesystemConfinement(context.Background(), env)
		t.Logf("filesystem canary: %s: %s", status, detail)
		if status != statusPass {
			t.Fatalf("status=%s detail=%s", status, detail)
		}
	})

	t.Run("omitted properties fail", func(t *testing.T) {
		env := rootFilesystemCanaryEnv(t, agent)
		env.filesystemCanaryOmitProperties = true
		status, detail := probeFilesystemConfinement(context.Background(), env)
		t.Logf("unconfined canary: %s: %s", status, detail)
		if status != statusFail || !filesystemUnconfinedCanaryFailure(detail) {
			t.Fatalf("status=%s detail=%s, want the confined step to see the operator home, write a protected path, or read the secret", status, detail)
		}
	})
	assertNoFilesystemCanaryResidue(t, before)
}

// filesystemUnconfinedCanaryFailure is the omitted-properties result. A baseline
// failure, or a unit that never started, does not exercise that step.
func filesystemUnconfinedCanaryFailure(detail string) bool {
	if strings.Contains(detail, "baseline") || strings.Contains(detail, "not a valid proof") || strings.Contains(detail, "could not start") {
		return false
	}
	return strings.Contains(detail, "operator home canary was visible inside the contained service") ||
		strings.Contains(detail, "contained service could create a file on a filesystem ProtectSystem should keep read-only") ||
		strings.Contains(detail, "hidden secret was readable inside the contained service")
}

func assertNoFilesystemCanaryResidue(t *testing.T, before map[string]struct{}) {
	t.Helper()
	for _, pattern := range []string{
		filesystemOperatorCanaryParent + "/.pipelock-fs-canary-*",
		filesystemStateCanaryParent + "/.pipelock-fs-write-*",
		filesystemStateCanaryParent + "/.pipelock-fs-secret-*",
		filesystemStateCanaryParent + "/.pipelock-fs-canary-*",
		"/tmp/plk-fs-grant-*/.pipelock-fs-workspace-*",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Errorf("filesystem canary residue %s", strings.Join(matches, ", "))
		}
	}
	after := filesystemCanaryUnits(t)
	var leftover []string
	for unit := range after {
		if _, ok := before[unit]; !ok {
			leftover = append(leftover, unit)
		}
	}
	if len(leftover) != 0 {
		t.Errorf("leftover transient units: %s", strings.Join(leftover, ", "))
	}
}

// The canary uses systemd-run without --unit, which names the transient
// service run-*.service and removes it with --collect.
func filesystemCanaryUnits(t *testing.T) map[string]struct{} {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "systemctl", "list-units", "--all", "--no-legend", "--plain", "run-*.service").CombinedOutput()
	if err != nil {
		t.Fatalf("list transient units: %v\n%s", err, out)
	}
	units := map[string]struct{}{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		units[fields[0]] = struct{}{}
	}
	return units
}

func rootFilesystemCanaryEnv(t *testing.T, agent *user.User) *probeEnv {
	t.Helper()
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("containment:\n  filesystem:\n    mode: enforce\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	grant, err := os.MkdirTemp("/tmp", "plk-fs-grant-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(grant) })
	if err := os.Chmod(grant, 0o755); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(configPath, "/etc/pipelock") || strings.Contains(configDir, "/etc/pipelock") || strings.Contains(grant, "/etc/pipelock") {
		t.Fatal("root canary fixture points at the live config")
	}
	env := defaultProbeEnv()
	env.configPath = configPath
	env.configDir = configDir
	env.workspaceInvPath = ""
	env.workspaceGrants = []workspaceGrant{{
		Path:      grant,
		Mode:      workspaceModeReadWrite,
		AgentUser: agent.Username,
		Created:   time.Now().UTC().Format(time.RFC3339),
	}}
	env.agentUserName = agent.Username
	env.agentHome = agent.HomeDir
	env.operatorUser = os.Getenv("SUDO_USER")
	env.display = ""
	env.filesystemProbe = nil
	return env
}
