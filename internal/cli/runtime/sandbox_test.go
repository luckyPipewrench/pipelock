// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
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

func TestSandboxCmdDryRunJSON(t *testing.T) {
	t.Parallel()

	cmd := SandboxCmd()
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--dry-run", "--json", "--workspace", t.TempDir(), "--", "echo", "ok"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

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
