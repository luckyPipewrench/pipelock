// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os/user"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestFilesystemProfilePropertiesRejectsUnsafeInputs(t *testing.T) {
	t.Run("operator home", func(t *testing.T) {
		in := enforceInput()
		in.OperatorHome = "relative/home"
		if _, err := filesystemProfileProperties(in); err == nil || !strings.Contains(err.Error(), "operator home") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing agent home", func(t *testing.T) {
		in := enforceInput()
		in.AgentHome = " "
		if _, err := filesystemProfileProperties(in); err == nil || !strings.Contains(err.Error(), "agent home is required") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("duplicate grant changes mode", func(t *testing.T) {
		in := enforceInput()
		in.Eval = allowEval("/srv/agent-home", "/srv/workspace")
		in.Grants = []workspaceGrant{
			{Path: "/srv/workspace", Mode: workspaceModeReadWrite, AgentUser: "pipelock-agent"},
			{Path: "/srv/workspace", Mode: workspaceModeReadOnly, AgentUser: "pipelock-agent"},
		}
		if _, err := filesystemProfileProperties(in); err == nil || !strings.Contains(err.Error(), "already bound") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("duplicate grant keeps one bind", func(t *testing.T) {
		in := enforceInput()
		in.Eval = allowEval("/srv/agent-home", "/srv/workspace")
		in.Grants = []workspaceGrant{
			{Path: "/srv/workspace", Mode: workspaceModeReadOnly, AgentUser: "pipelock-agent"},
			{Path: "/srv/workspace", Mode: workspaceModeReadOnly, AgentUser: "pipelock-agent"},
		}
		profile, err := filesystemProfileProperties(in)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, bind := range profile.BindReadOnlyPaths {
			if strings.Contains(bind, "/srv/workspace") {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("workspace binds = %v", profile.BindReadOnlyPaths)
		}
	})
	t.Run("display socket", func(t *testing.T) {
		in := enforceInput()
		in.DisplaySocket = "/tmp/sock:extra"
		if _, err := filesystemProfileProperties(in); err == nil || !strings.Contains(err.Error(), "display socket") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestContainLaunchPropertyLinesRejectsProfileAndUnsafeOffSocket(t *testing.T) {
	in := enforceInput()
	in.OperatorHome = ""
	if _, err := containLaunchPropertyLines(in); err == nil {
		t.Fatal("enforce without an operator home was accepted")
	}
	off := filesystemProfileInput{Mode: config.ContainmentFilesystemModeOff, DisplaySocket: "has:colon"}
	if _, err := containLaunchPropertyLines(off); err == nil || !strings.Contains(err.Error(), "display socket") {
		t.Fatalf("err = %v", err)
	}
	off.DisplaySocket = ""
	lines, err := containLaunchPropertyLines(off)
	if err != nil || lines != nil {
		t.Fatalf("lines=%v err=%v", lines, err)
	}
}

func TestResolveBindDirRejectsFileAndUncleanResult(t *testing.T) {
	in := enforceInput()
	in.Eval = func(string) (string, bool, error) { return "/srv/agent-home", false, nil }
	if _, err := in.resolveBindDir("agent home", "/srv/agent-home"); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("err = %v", err)
	}
	in.Eval = func(string) (string, bool, error) { return "relative", true, nil }
	if _, err := in.resolveBindDir("workspace grant", "/srv/workspace"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v", err)
	}
}

func TestInaccessiblePathsRejectsBadInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*filesystemProfileInput)
		want   string
	}{
		{name: "config dir", mutate: func(in *filesystemProfileInput) { in.ConfigDir = "relative" }, want: "config dir"},
		{name: "data dir", mutate: func(in *filesystemProfileInput) { in.DataDir = "relative" }, want: "data dir"},
		{name: "proof", mutate: func(in *filesystemProfileInput) { in.PostureProofPath = "relative" }, want: "posture proof"},
		{name: "optional secret", mutate: func(in *filesystemProfileInput) { in.OptionalSecretPaths = []string{"relative/secret"} }, want: "secret path"},
		{name: "signing key", mutate: func(in *filesystemProfileInput) { in.RequiredSecretPaths = []string{"relative/key"} }, want: "signing key"},
		{name: "readable", mutate: func(in *filesystemProfileInput) { in.ReadablePaths = []string{"relative/cert"} }, want: "readable path"},
		{name: "stat", mutate: func(in *filesystemProfileInput) {
			in.Exists = func(string) (bool, error) { return false, errors.New("stat denied") }
		}, want: "stat inaccessible path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := enforceInput()
			tt.mutate(&in)
			if _, err := in.inaccessiblePaths(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}

	in := enforceInput()
	in.ConfigDir = ""
	in.DataDir = ""
	in.Exists = func(string) (bool, error) { return false, nil }
	if _, err := in.inaccessiblePaths(); err != nil {
		t.Fatalf("default directories: %v", err)
	}
}

func TestPathHelpersRejectEmptyAndRelative(t *testing.T) {
	if _, err := cleanLinuxPath(" "); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty = %v", err)
	}
	if _, err := cleanLinuxPath("relative"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative = %v", err)
	}
	if linuxPathContains("", "/home/operator") || linuxPathContains("/home", "/home") {
		t.Fatal("empty or equal paths compared as nested")
	}
	if got := absoluteConfiguredPath("", "keys/signing.key"); got == "" || !strings.HasPrefix(got, "/") {
		t.Fatalf("default config dir path = %q", got)
	}
	if got := absoluteConfiguredPath("relative-dir", "keys/signing.key"); got != "" {
		t.Fatalf("relative config dir path = %q", got)
	}
	profile := filesystemProfile{
		Mode:              config.ContainmentFilesystemModeEnforce,
		BindReadOnlyPaths: []string{"/tmp/.X11-unix/X7:/tmp/.X11-unix/X7:rbind"},
	}
	if digest := filesystemBindsDigest(profile); digest == "" {
		t.Fatal("read-only enforce profile has no digest")
	}
}

func TestFilesystemOperatorHomeAndProbeConfigFailClosed(t *testing.T) {
	enforce := config.ContainmentFilesystemModeEnforce
	if _, err := filesystemOperatorHome(&probeEnv{operatorUser: "root"}, enforce); err == nil || !strings.Contains(err.Error(), "operator home is required") {
		t.Fatalf("root = %v", err)
	}
	if home, err := filesystemOperatorHome(&probeEnv{operatorUser: "root"}, config.ContainmentFilesystemModeOff); err != nil || home != "" {
		t.Fatalf("off root = %q %v", home, err)
	}
	env := &probeEnv{operatorUser: "operator", lookupUser: nil}
	if _, err := filesystemOperatorHome(env, enforce); err == nil {
		t.Fatal("enforce without lookup was accepted")
	}
	if _, err := filesystemOperatorHome(env, config.ContainmentFilesystemModeOff); err != nil {
		t.Fatal(err)
	}
	env.lookupUser = func(string) (*user.User, error) { return nil, errors.New("unknown") }
	if _, err := filesystemOperatorHome(env, enforce); err == nil || !strings.Contains(err.Error(), "lookup operator home") {
		t.Fatalf("lookup = %v", err)
	}
	if _, err := filesystemOperatorHome(env, config.ContainmentFilesystemModeOff); err != nil {
		t.Fatal(err)
	}
	env.lookupUser = func(string) (*user.User, error) {
		return &user.User{Username: "operator", HomeDir: " "}, nil
	}
	if _, err := filesystemOperatorHome(env, enforce); err == nil || !strings.Contains(err.Error(), "no home directory") {
		t.Fatalf("blank home = %v", err)
	}

	if _, err := loadProbeConfig(&probeEnv{readFile: func(string) ([]byte, error) {
		return []byte("mode: balanced\n"), nil
	}}); err != nil {
		t.Fatal(err)
	}
	parseEnv := &probeEnv{configPath: "/etc/pipelock/pipelock.yaml", readFile: func(string) ([]byte, error) {
		return []byte("mode: [\n"), nil
	}}
	if _, err := loadProbeConfig(parseEnv); err == nil || !strings.Contains(err.Error(), "parse containment config") {
		t.Fatalf("parse = %v", err)
	}
	parseEnv.readFile = func(string) ([]byte, error) {
		return []byte("containment:\n  filesystem:\n    mode: sideways\n"), nil
	}
	if _, err := loadProbeConfig(parseEnv); err == nil || !strings.Contains(err.Error(), "sideways") {
		t.Fatalf("validate = %v", err)
	}
	if required, optional := configuredSecretPaths(nil, "/etc/pipelock"); required != nil || optional != nil {
		t.Fatalf("nil config secrets = %v %v", required, optional)
	}
}

func TestFilesystemProfileInputForProbeReportsInventoryAndReadableProof(t *testing.T) {
	if _, err := filesystemProfileInputForProbe(nil, "/srv/agent-home"); err == nil || !strings.Contains(err.Error(), "probe environment is missing") {
		t.Fatalf("nil env = %v", err)
	}
	env := &probeEnv{
		configPath:       "/etc/pipelock/pipelock.yaml",
		workspaceInvPath: "/var/lib/pipelock/workspaces.json",
		readFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "workspaces.json") {
				return nil, errors.New("unreadable inventory")
			}
			return []byte("containment:\n  filesystem:\n    mode: off\n"), nil
		},
	}
	if _, err := filesystemProfileInputForProbe(env, "/srv/agent-home"); err == nil || !strings.Contains(err.Error(), "read workspace inventory") {
		t.Fatalf("inventory = %v", err)
	}

	env.workspaceInvPath = ""
	env.postureProofPath = "/var/lib/pipelock/contain/posture/proof.json"
	in, err := filesystemProfileInputForProbe(env, "/srv/agent-home")
	if err != nil {
		t.Fatal(err)
	}
	if in.PostureProofPath != env.postureProofPath || len(in.ReadablePaths) != 1 || in.ReadablePaths[0] != env.postureProofPath {
		t.Fatalf("input = %+v", in)
	}
	status, detail := probeFilesystemConfinement(context.Background(), nil)
	if status != statusFail || !strings.Contains(detail, "probe environment is missing") {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
}

func TestFilesystemCanaryOutcomeNamesEachFailedCheck(t *testing.T) {
	tests := []struct {
		code   int
		output string
		want   string
	}{
		{code: 12, want: "ProtectSystem should keep read-only"},
		{code: 13, want: "read-write workspace"},
		{code: 14, want: "hidden secret was readable"},
		{code: 99, want: "exited 99"},
		{code: 99, output: "boom\n", want: "exited 99: boom"},
	}
	for _, tt := range tests {
		status, detail := filesystemCanaryOutcome(tt.code, tt.output)
		if status != statusFail || !strings.Contains(detail, tt.want) {
			t.Fatalf("code %d output %q => %s %s", tt.code, tt.output, status, detail)
		}
	}
}
