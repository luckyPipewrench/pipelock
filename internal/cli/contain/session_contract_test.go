// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderSessionContract_ExactText(t *testing.T) {
	var buf bytes.Buffer
	renderSessionContract(&buf, sessionContract{
		Tool:            "claude",
		AgentUser:       "pipelock-agent",
		ProxyURL:        "http://127.0.0.1:8888",
		ProxyPort:       8888,
		PostureCapsule:  "/var/lib/pipelock/contain/posture/proof.json",
		RegisteredTools: []string{"claude", "codex"},
		Workspaces: []contractWorkspace{
			{Path: "/home/dev/proj", Mode: "read-write", Owner: "josh", Created: "2026-01-02T03:04:05Z", Expires: "never", Status: "active"},
		},
		PrivateTmp: false,
	})
	want := strings.Join([]string{
		"pipelock contain run: session contract for claude",
		"  agent user:       pipelock-agent",
		"  proxy egress:     http://127.0.0.1:8888 (loopback proxy only; direct egress denied by nftables)",
		"  posture capsule:  /var/lib/pipelock/contain/posture/proof.json",
		"  agent /tmp:       shared with the operator (not private)",
		"  registered tools: claude, codex",
		"  workspaces:",
		"    /home/dev/proj  read-write  owner=josh  created=2026-01-02T03:04:05Z  expires=never  [active]",
		"",
	}, "\n")
	if got := buf.String(); got != want {
		t.Fatalf("contract text mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderSessionContract_EmptyToolsAndWorkspaces(t *testing.T) {
	var buf bytes.Buffer
	renderSessionContract(&buf, sessionContract{Tool: "claude", AgentUser: "pipelock-agent", ProxyURL: "http://127.0.0.1:8888"})
	out := buf.String()
	if !strings.Contains(out, "registered tools: (none)") {
		t.Errorf("empty tools not rendered: %q", out)
	}
	if !strings.Contains(out, "workspaces:       (none granted)") {
		t.Errorf("empty workspaces not rendered: %q", out)
	}
}

func TestBuildSessionContract_DerivesFromPreflightState(t *testing.T) {
	env := &probeEnv{agentUserName: "pipelock-agent", port: 8888, now: func() time.Time {
		return time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	}}
	tools := []toolsListEntry{{name: "claude"}, {name: "codex", target: "/usr/bin/codex"}}
	grants := []workspaceGrant{
		{Path: "/home/dev/proj", Mode: "read-write", Owner: "josh", Created: "2026-01-01T00:00:00Z", Expires: "2026-02-01T00:00:00Z"},
		{Path: "/legacy/only"}, // legacy: no metadata
	}
	c := buildSessionContract(env, "claude", tools, grants, "/var/lib/pipelock/contain/posture/proof.json")

	if c.Tool != "claude" || c.AgentUser != "pipelock-agent" || c.ProxyURL != "http://127.0.0.1:8888" {
		t.Fatalf("scalar fields wrong: %+v", c)
	}
	if c.PrivateTmp {
		t.Fatal("PrivateTmp must be false until private-tmp isolation ships")
	}
	if strings.Join(c.RegisteredTools, ",") != "claude,codex" {
		t.Fatalf("registered tools = %v, want claude,codex", c.RegisteredTools)
	}
	if len(c.Workspaces) != 2 {
		t.Fatalf("workspaces len = %d, want 2", len(c.Workspaces))
	}
	if c.Workspaces[0].Status != "active" || c.Workspaces[0].Owner != "josh" {
		t.Fatalf("grant 0 = %+v, want active/josh", c.Workspaces[0])
	}
	if c.Workspaces[1].Status != "legacy" || c.Workspaces[1].Owner != "-" || c.Workspaces[1].Expires != "never" {
		t.Fatalf("legacy grant should render as legacy with dashes: %+v", c.Workspaces[1])
	}
}

// TestRunContainRun_DryRunPrintsContractWithoutLaunchOrPosture proves --dry-run
// runs preflight, prints the contract, and neither emits a posture capsule nor
// launches.
func TestRunContainRun_DryRunPrintsContractWithoutLaunchOrPosture(t *testing.T) {
	env := allPassEnv(t)
	var launched, posture bool
	runEnv := containRunEnv{
		probe: env,
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
			launched = true
			return nil
		},
		emitPosture: func(string, string, *probeEnv, []string) (string, error) {
			posture = true
			return "/unused", nil
		},
	}
	var buf bytes.Buffer
	err := runContainRun(context.Background(), nil, &buf, io.Discard, runEnv, containRunOptions{dryRun: true}, []string{"claude"})
	if err != nil {
		t.Fatalf("dry-run err = %v", err)
	}
	if launched {
		t.Fatal("dry-run launched the tool")
	}
	if posture {
		t.Fatal("dry-run emitted a posture capsule")
	}
	if !strings.Contains(buf.String(), "session contract for claude") {
		t.Fatalf("dry-run did not print the contract: %q", buf.String())
	}
}

// TestRunContainRun_ContractReflectsTheToolsTheLauncherAccepts is the
// display/action anti-divergence check: the contract's registered-tools list is
// exactly what the registration check (which the launch relies on) parsed from
// tools.list, from the same read.
func TestRunContainRun_ContractReflectsTheToolsTheLauncherAccepts(t *testing.T) {
	env := allPassEnv(t)
	// Both tools resolve to one real executable so probe 12 (target resolvable)
	// passes; the point of the test is that the contract lists exactly what the
	// registration read parsed.
	toolTarget := filepath.Join(t.TempDir(), "tool")
	writeFakeWrapper(t, toolTarget, 0o755)
	base := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.toolsListPath {
			return []byte("claude\t" + toolTarget + "\ncodex\t" + toolTarget + "\n"), nil
		}
		return base(path)
	}
	var launched bool
	runEnv := containRunEnv{
		probe: env,
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
			launched = true
			return nil
		},
		emitPosture: func(string, string, *probeEnv, []string) (string, error) { return "/unused", nil },
	}
	var buf bytes.Buffer
	if err := runContainRun(context.Background(), nil, &buf, io.Discard, runEnv, containRunOptions{}, []string{"claude"}); err != nil {
		t.Fatalf("run err = %v", err)
	}
	if !launched {
		t.Fatal("launch did not run for a registered tool")
	}
	if !strings.Contains(buf.String(), "registered tools: claude, codex") {
		t.Fatalf("contract tool list did not match the launcher's tools.list read: %q", buf.String())
	}
}
