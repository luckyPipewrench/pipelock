// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"os"
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
		if status != statusFail {
			t.Fatalf("status=%s detail=%s, want the canary to fail without filesystem properties", status, detail)
		}
	})
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
