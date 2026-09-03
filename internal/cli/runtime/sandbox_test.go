// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

func TestSingleConnListener_AcceptOnce(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	l := &singleConnListener{conn: server}

	// First Accept should return the connection.
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if conn != server {
		t.Error("first Accept returned wrong connection")
	}

	// Second Accept should return ErrClosed.
	_, err = l.Accept()
	if err == nil {
		t.Fatal("expected error on second Accept")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("expected net.ErrClosed, got: %v", err)
	}
}

func TestSingleConnListener_Close(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	l := &singleConnListener{conn: server}
	// Close should succeed (it's a no-op).
	if err := l.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestSingleConnListener_Addr(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	l := &singleConnListener{conn: server}
	addr := l.Addr()
	if addr == nil {
		t.Error("Addr() returned nil")
	}
}

func TestSandboxCmdRequiresDashCommand(t *testing.T) {
	t.Parallel()

	cmd := SandboxCmd()
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"echo", "ok"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "usage: pipelock sandbox -- COMMAND") {
		t.Fatalf("SandboxCmd without -- err = %v, want usage error", err)
	}
}

func TestSandboxCmdRejectsStrictBestEffortTogether(t *testing.T) {
	t.Parallel()

	cmd := SandboxCmd()
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--strict", "--best-effort", "--", "echo", "ok"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("SandboxCmd strict+best-effort err = %v, want mutual exclusion", err)
	}
}

func TestSandboxCmdDryRunRejectsInvalidBestEffortOverride(t *testing.T) {
	for _, args := range [][]string{
		{"--dry-run", "--best-effort", "--best-effort-expiry", "1h", "--", "echo", "ok"},
		{"--dry-run", "--best-effort", "--best-effort-reason", "test", "--best-effort-expiry", "0s", "--", "echo", "ok"},
	} {
		cmd := SandboxCmd()
		cmd.SilenceUsage = true
		cmd.SetArgs(args)
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)

		err := cmd.Execute()
		if err == nil {
			t.Fatalf("SandboxCmd(%v) succeeded, want invalid best-effort override rejection", args)
		}
		if bytes.Contains(out.Bytes(), []byte("CAPABILITIES_OK")) {
			t.Fatalf("SandboxCmd(%v) reported launchable capabilities: %s", args, out.String())
		}
	}
}

func TestSandboxCmdDryRunValidatesEnvFlags(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "empty key", args: []string{"--env", "=value"}, wantErr: "non-empty variable name"},
		{name: "dangerous key", args: []string{"--env", "LD_PRELOAD=/tmp/x.so"}, wantErr: "subvert sandbox containment"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := SandboxCmd()
			cmd.SilenceUsage = true
			cmd.SetArgs(append(append([]string{"--dry-run"}, tt.args...), "--", "echo", "ok"))
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("SandboxCmd(%v) error = %v, want %q", tt.args, err, tt.wantErr)
			}
			if bytes.Contains(out.Bytes(), []byte("CAPABILITIES_OK")) {
				t.Fatalf("dry-run reported launchable capabilities despite a rejected --env: %s", out.String())
			}
		})
	}
}

func TestSandboxCmdDryRunAcceptsEnvAndFilesystemPolicy(t *testing.T) {
	t.Setenv("PIPELOCK_SANDBOX_TEST_INHERIT", "inherited")
	workspace := t.TempDir()
	extraRead := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	cfg := "sandbox:\n  filesystem:\n    allow_read:\n      - " + extraRead + "\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cmd := SandboxCmd()
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--dry-run", "--json", "--config", configPath, "--workspace", workspace,
		"--env", "PIPELOCK_SANDBOX_TEST_INHERIT", "--env", "PIPELOCK_SANDBOX_TEST_UNSET", "--env", "FOO=bar",
		"--", "echo", "ok",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	// The preflight verdict depends on the host's namespace support; what this
	// test pins is that valid --env forms and a merged filesystem policy reach
	// the preflight instead of being refused as flag or configuration errors.
	if err != nil && (strings.Contains(err.Error(), "--env") || strings.Contains(err.Error(), "config")) {
		t.Fatalf("dry-run refused valid --env or fs policy: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"status"`)) {
		t.Fatalf("dry-run produced no preflight JSON: %s", out.String())
	}
}

func TestSandboxCmdRejectsMixedBestEffortProvenance(t *testing.T) {
	for _, tt := range []struct {
		name     string
		config   string
		flagArgs []string
	}{
		{
			name:     "command line override with configuration expiry",
			config:   "sandbox:\n  best_effort: false\n  best_effort_reason: configuration reason\n  best_effort_expiry: 2h\n",
			flagArgs: []string{"--best-effort", "--best-effort-reason", "command line reason"},
		},
		{
			name:     "command line override with configuration reason",
			config:   "sandbox:\n  best_effort: false\n  best_effort_reason: configuration reason\n  best_effort_expiry: 2h\n",
			flagArgs: []string{"--best-effort", "--best-effort-expiry", "1h"},
		},
		{
			name:     "configuration override with command line reason",
			config:   "sandbox:\n  best_effort: true\n  best_effort_reason: configuration reason\n  best_effort_expiry: 2h\n",
			flagArgs: []string{"--best-effort-reason", "command line reason"},
		},
		{
			name:     "configuration override with command line expiry",
			config:   "sandbox:\n  best_effort: true\n  best_effort_reason: configuration reason\n  best_effort_expiry: 2h\n",
			flagArgs: []string{"--best-effort-expiry", "1h"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(configPath, []byte(tt.config), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cmd := SandboxCmd()
			cmd.SilenceUsage = true
			args := append([]string{"--dry-run", "--config", configPath}, tt.flagArgs...)
			args = append(args, "--", "echo", "ok")
			cmd.SetArgs(args)
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)

			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "command-line") || !strings.Contains(err.Error(), "configuration") {
				t.Fatalf("SandboxCmd(%v) error = %v, want command-line/configuration refusal", args, err)
			}
			if bytes.Contains(out.Bytes(), []byte("CAPABILITIES_OK")) {
				t.Fatalf("SandboxCmd(%v) reported launchable capabilities: %s", args, out.String())
			}
		})
	}
}

func TestSandboxCmdDryRunJSON(t *testing.T) {
	t.Parallel()

	cmd := SandboxCmd()
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--dry-run", "--json", "--workspace", t.TempDir(), "--", "echo", "ok"})
	var out, stderr bytes.Buffer
	cmd.SetOut(&out)
	// Keep stderr separate: on a runner without user namespaces the sandbox
	// reports "degraded" and the command prints an error to stderr. Mixing it
	// into out corrupts the JSON and flakes the unmarshal below.
	cmd.SetErr(&stderr)

	execErr := cmd.Execute()

	var result sandbox.PreflightResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("dry-run JSON = %q, unmarshal: %v", out.String(), err)
	}
	if result.Status == sandbox.StatusReady && execErr != nil {
		t.Fatalf("ready dry-run returned error: %v", execErr)
	}
	if result.Status != sandbox.StatusReady && execErr == nil {
		t.Fatalf("dry-run status %q returned success", result.Status)
	}
	if len(result.Command) != 2 || filepath.Base(result.Command[0]) != "echo" || result.Command[1] != "ok" {
		t.Fatalf("dry-run command = %v, want echo ok", result.Command)
	}
	if result.Workspace == "" {
		t.Fatal("dry-run result should include workspace")
	}
}

func TestSandboxCmdRejectsDangerousEnvBeforeLaunch(t *testing.T) {
	t.Parallel()

	cmd := SandboxCmd()
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--workspace", t.TempDir(), "--env", "LD_PRELOAD=/tmp/hook.so", "--", "echo", "ok"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD is blocked") {
		t.Fatalf("SandboxCmd dangerous env err = %v, want blocked LD_PRELOAD", err)
	}
}

func TestPrintPreflightText_Ready(t *testing.T) {
	t.Parallel()

	result := sandbox.PreflightResult{
		Status:    sandbox.StatusReady,
		Workspace: "/test/workspace",
		Command:   []string{"python", "agent.py"},
		Mode:      "standard",
		Layers: []sandbox.LayerProbe{
			{Name: "landlock", Available: true, Detail: "v4"},
			{Name: "seccomp", Available: true},
			{Name: "network", Available: true, Detail: "namespace"},
		},
	}

	var buf bytes.Buffer
	printPreflightText(&buf, result)
	got := buf.String()

	checks := []string{
		"CAPABILITIES_OK",
		"3/3 layers available",
		"/test/workspace",
		"python agent.py",
		"landlock",
		"seccomp",
		"network",
		"available",
	}
	for _, check := range checks {
		if !bytes.Contains([]byte(got), []byte(check)) {
			t.Errorf("output missing %q: %s", check, got)
		}
	}
}

func TestPrintPreflightText_Degraded(t *testing.T) {
	t.Parallel()

	result := sandbox.PreflightResult{
		Status: sandbox.StatusDegraded,
		Mode:   "best-effort",
		Layers: []sandbox.LayerProbe{
			{Name: "landlock", Available: true},
			{Name: "seccomp", Available: true},
			{Name: "network", Available: false, Reason: "unprivileged user namespaces disabled"},
		},
		Warnings: []string{"network isolation unavailable, using proxy fallback"},
	}

	var buf bytes.Buffer
	printPreflightText(&buf, result)
	got := buf.String()

	if !bytes.Contains([]byte(got), []byte("DEGRADED")) {
		t.Errorf("expected DEGRADED in output: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte(stateUnavailable)) {
		t.Errorf("expected 'unavailable' in output: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte("WARNING")) {
		t.Errorf("expected WARNING in output: %s", got)
	}
}

func TestPrintPreflightText_WithErrors(t *testing.T) {
	t.Parallel()

	result := sandbox.PreflightResult{
		Status: "error",
		Layers: []sandbox.LayerProbe{},
		Errors: []string{"landlock not supported on this kernel"},
	}

	var buf bytes.Buffer
	printPreflightText(&buf, result)
	got := buf.String()

	if !bytes.Contains([]byte(got), []byte("ERROR")) {
		t.Errorf("expected ERROR in output: %s", got)
	}
}

func TestPrintPreflightText_LayerWithDetail(t *testing.T) {
	t.Parallel()

	result := sandbox.PreflightResult{
		Status: sandbox.StatusReady,
		Mode:   "strict",
		Layers: []sandbox.LayerProbe{
			{Name: "landlock", Available: true, Detail: "v4"},
		},
	}

	var buf bytes.Buffer
	printPreflightText(&buf, result)
	got := buf.String()

	if !bytes.Contains([]byte(got), []byte("(v4)")) {
		t.Errorf("expected detail '(v4)' in output: %s", got)
	}
}

func TestPrintJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	data := map[string]string{"key": "value"}

	if err := printJSON(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("key = %q, want value", result["key"])
	}
}
