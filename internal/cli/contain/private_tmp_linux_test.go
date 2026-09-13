// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateTmpSystemdRunArgs_ProtectsInteractiveAndPipedLaunches(t *testing.T) {
	for _, tt := range []struct {
		name        string
		interactive bool
		want        string
		dontWant    string
	}{
		{name: "piped", want: "--pipe", dontWant: "--pty"},
		{name: "interactive", interactive: true, want: "--pty", dontWant: "--pipe"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := privateTmpSystemdRunArgs(966, 966, []uint32{966, 1001}, "/home/agent", []string{"HOME=/home/agent"}, []string{defaultLaunchScript, "claude", "$HOME/literal"}, tt.interactive)
			joined := strings.Join(args, " ")
			for _, want := range []string{
				"--expand-environment=no",
				"--property=PrivateTmp=true",
				"--uid=966",
				"--gid=966",
				"--property=SupplementaryGroups=1001",
				"--setenv=HOME=/home/agent",
				"--working-directory=/home/agent",
				"-- " + defaultLaunchScript + " claude $HOME/literal",
				tt.want,
			} {
				if !strings.Contains(joined, want) {
					t.Fatalf("args = %q, missing %q", joined, want)
				}
			}
			if strings.Contains(joined, tt.dontWant) {
				t.Fatalf("args = %q, unexpectedly contains %q", joined, tt.dontWant)
			}
			if got := args[len(args)-1]; got != "$HOME/literal" {
				t.Fatalf("literal tool argument = %q, want $HOME/literal", got)
			}
		})
	}
}

func TestSystemdMainSignal(t *testing.T) {
	for _, output := range []string{
		"Main processes terminated with: code=killed/status=TERM\n",
		"Main process exited, code=killed, status=15/TERM\n",
		"Main process exited, code=dumped, status=11/SEGV\n",
	} {
		signal, ok := systemdMainSignal(output)
		if !ok || signal == 0 {
			t.Fatalf("systemdMainSignal(%q) = %v, %t; want signal", output, signal, ok)
		}
	}
	if _, ok := systemdMainSignal("Main process exited, code=exited, status=0/SUCCESS\n"); ok {
		t.Fatal("ordinary exit was classified as a signal")
	}
}

func TestSupplementaryGroupIDs_DeduplicatesAndOmitsPrimary(t *testing.T) {
	if got, want := strings.Join(supplementaryGroupIDs([]uint32{966, 1001, 1001, 966, 1002}, 966), ","), "1001,1002"; got != want {
		t.Fatalf("supplementary groups = %q, want %q", got, want)
	}
}

func TestProbePrivateTmp_UsesAndRemovesOperatorCanary(t *testing.T) {
	oldRoot := privateTmpCanaryRoot
	privateTmpCanaryRoot = func() bool { return true }
	t.Cleanup(func() { privateTmpCanaryRoot = oldRoot })

	// Point $TMPDIR at a directory that is NOT under /tmp (t.TempDir itself
	// lives under /tmp on most hosts, so it would not exercise this). The /tmp
	// canary must still land in /tmp: this is what fails if the probe regresses
	// to os.CreateTemp's "" default, which honors $TMPDIR and would prove
	// nothing about the isolated /tmp.
	altTmp, err := os.MkdirTemp("/var/tmp", "pipelock-alt-tmpdir-")
	if err != nil {
		t.Fatalf("create alternate TMPDIR: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(altTmp) })
	t.Setenv("TMPDIR", altTmp)

	env := containRunLinuxGuardEnv("966", "966", defaultLaunchScript)
	var canaryPaths []string
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != systemdRunPath {
			t.Fatalf("command = %q, want %q", name, systemdRunPath)
		}
		if len(args) == 1 && args[0] == "--version" {
			return "systemd 258 (258.10)", 0, nil
		}
		joined := strings.Join(args, " ")
		for _, want := range []string{"--property=PrivateTmp=true", "--pipe", "/usr/bin/test ! -e "} {
			if !strings.Contains(joined, want) {
				t.Fatalf("args = %q, missing %q", joined, want)
			}
		}
		for i, arg := range args[:len(args)-1] {
			if arg != "-e" {
				continue
			}
			canaryPaths = append(canaryPaths, args[i+1])
		}
		if len(canaryPaths) != 2 {
			t.Fatalf("canary paths = %v, want /tmp and /var/tmp paths", canaryPaths)
		}
		// The canaries must live in the directories PrivateTmp isolates. A
		// regression to os.CreateTemp's "" default honors $TMPDIR and would
		// place the /tmp canary outside /tmp, so the probe would prove nothing
		// about /tmp (or fail spuriously). Guard both exact locations.
		if !strings.HasPrefix(canaryPaths[0], "/tmp/") {
			t.Fatalf("first canary = %q, want a path under /tmp", canaryPaths[0])
		}
		if !strings.HasPrefix(canaryPaths[1], "/var/tmp/") {
			t.Fatalf("second canary = %q, want a path under /var/tmp", canaryPaths[1])
		}
		for _, path := range canaryPaths {
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("operator canary missing before service starts: %v", err)
			}
		}
		return "", 0, nil
	}

	status, detail := probePrivateTmp(context.Background(), env)
	if status != statusPass {
		t.Fatalf("status = %q, want pass (%s)", status, detail)
	}
	for _, path := range canaryPaths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("operator canary remains after probe: %v", err)
		}
	}
}

func TestProbePrivateTmp_FailsWhenAgentCanSeeCanary(t *testing.T) {
	oldRoot := privateTmpCanaryRoot
	privateTmpCanaryRoot = func() bool { return true }
	t.Cleanup(func() { privateTmpCanaryRoot = oldRoot })

	env := containRunLinuxGuardEnv("966", "966", defaultLaunchScript)
	env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
		if len(args) == 1 && args[0] == "--version" {
			return "systemd 258", 0, nil
		}
		return "canary visible", 1, nil
	}
	status, detail := probePrivateTmp(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "could see an operator temporary canary") {
		t.Fatalf("status/detail = %q/%q, want failed visible-canary result", status, detail)
	}
}

func TestProbePrivateTmp_SkipsWithoutRoot(t *testing.T) {
	oldRoot := privateTmpCanaryRoot
	privateTmpCanaryRoot = func() bool { return false }
	t.Cleanup(func() { privateTmpCanaryRoot = oldRoot })

	status, _ := probePrivateTmp(context.Background(), containRunLinuxGuardEnv("966", "966", defaultLaunchScript))
	if status != statusSkip {
		t.Fatalf("status = %q, want skip", status)
	}
}

func TestProbePrivateTmp_RequiresSystemd254(t *testing.T) {
	oldRoot, oldVersion := privateTmpCanaryRoot, privateTmpVersion
	privateTmpCanaryRoot = func() bool { return true }
	t.Cleanup(func() {
		privateTmpCanaryRoot = oldRoot
		privateTmpVersion = oldVersion
	})

	tests := []struct {
		name   string
		output string
		err    error
	}{
		{name: "old release", output: "systemd 253"},
		{name: "unrecognized output", output: "systemd"},
		{name: "command failure", err: errors.New("version unavailable")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateTmpVersion = func(context.Context) (string, error) {
				return tt.output, tt.err
			}
			env := containRunLinuxGuardEnv("966", "966", defaultLaunchScript)
			status, detail := probePrivateTmp(context.Background(), env)
			if status != statusFail || !strings.Contains(detail, "systemd") {
				t.Fatalf("status/detail = %q/%q, want systemd compatibility failure", status, detail)
			}
		})
	}
}

func TestProbePrivateTmp_FailsWhenCanaryCannotBePrepared(t *testing.T) {
	oldRoot, oldCreate := privateTmpCanaryRoot, privateTmpCreateTemp
	privateTmpCanaryRoot = func() bool { return true }
	t.Cleanup(func() {
		privateTmpCanaryRoot = oldRoot
		privateTmpCreateTemp = oldCreate
	})

	t.Run("tmp create", func(t *testing.T) {
		privateTmpCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("no temporary directory") }
		status, detail := probePrivateTmp(context.Background(), containRunLinuxGuardEnv("966", "966", defaultLaunchScript))
		if status != statusFail || !strings.Contains(detail, "create operator /tmp canary") {
			t.Fatalf("status/detail = %q/%q, want /tmp create failure", status, detail)
		}
	})

	t.Run("tmp close", func(t *testing.T) {
		privateTmpCreateTemp = func(dir, pattern string) (*os.File, error) {
			file, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			if err := file.Close(); err != nil {
				return nil, err
			}
			return file, nil
		}
		status, detail := probePrivateTmp(context.Background(), containRunLinuxGuardEnv("966", "966", defaultLaunchScript))
		if status != statusFail || !strings.Contains(detail, "close operator /tmp canary") {
			t.Fatalf("status/detail = %q/%q, want /tmp close failure", status, detail)
		}
	})

	t.Run("var tmp create", func(t *testing.T) {
		calls := 0
		privateTmpCreateTemp = func(dir, pattern string) (*os.File, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("no var tmp")
			}
			return os.CreateTemp(dir, pattern)
		}
		status, detail := probePrivateTmp(context.Background(), containRunLinuxGuardEnv("966", "966", defaultLaunchScript))
		if status != statusFail || !strings.Contains(detail, "create operator /var/tmp canary") {
			t.Fatalf("status/detail = %q/%q, want /var/tmp create failure", status, detail)
		}
	})

	t.Run("var tmp close", func(t *testing.T) {
		calls := 0
		privateTmpCreateTemp = func(dir, pattern string) (*os.File, error) {
			calls++
			file, err := os.CreateTemp(dir, pattern)
			if err != nil || calls == 1 {
				return file, err
			}
			if err := file.Close(); err != nil {
				return nil, err
			}
			return file, nil
		}
		status, detail := probePrivateTmp(context.Background(), containRunLinuxGuardEnv("966", "966", defaultLaunchScript))
		if status != statusFail || !strings.Contains(detail, "close operator /var/tmp canary") {
			t.Fatalf("status/detail = %q/%q, want /var/tmp close failure", status, detail)
		}
	})

	t.Run("identity preparation", func(t *testing.T) {
		privateTmpCreateTemp = oldCreate
		env := containRunLinuxGuardEnv("966", "966", defaultLaunchScript)
		env.lookupUser = func(string) (*user.User, error) { return nil, errors.New("missing agent") }
		status, detail := probePrivateTmp(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "prepare private temporary-directory canary") {
			t.Fatalf("status/detail = %q/%q, want identity preparation failure", status, detail)
		}
	})

	t.Run("service startup", func(t *testing.T) {
		privateTmpCreateTemp = oldCreate
		env := containRunLinuxGuardEnv("966", "966", defaultLaunchScript)
		env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
			if len(args) == 1 && args[0] == "--version" {
				return "systemd 258", 0, nil
			}
			return "", -1, errors.New("systemd unavailable")
		}
		status, detail := probePrivateTmp(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "could not start") {
			t.Fatalf("status/detail = %q/%q, want service-startup failure", status, detail)
		}
	})
}

func TestPrivateTmpSystemdRunArgsForAgent_FailsClosedOnInvalidIdentity(t *testing.T) {
	tests := []struct {
		name string
		env  *probeEnv
		want string
	}{
		{
			name: "lookup",
			env: &probeEnv{agentUserName: testAgentUser, lookupUser: func(string) (*user.User, error) {
				return nil, errors.New("missing")
			}},
			want: "lookup",
		},
		{name: "uid", env: containRunLinuxGuardEnv("invalid", "966", defaultLaunchScript), want: "parse uid"},
		{name: "gid", env: containRunLinuxGuardEnv("966", "invalid", defaultLaunchScript), want: "parse gid"},
		{name: "groups", env: &probeEnv{agentUserName: testAgentUser, lookupUser: func(string) (*user.User, error) {
			return testContainedAgentUser(), nil
		}, groupIDs: func(*user.User) ([]string, error) { return nil, errors.New("groups unavailable") }}, want: "resolve groups"},
		{name: "invalid group", env: &probeEnv{agentUserName: testAgentUser, lookupUser: func(string) (*user.User, error) {
			return testContainedAgentUser(), nil
		}, groupIDs: func(*user.User) ([]string, error) { return []string{"invalid"}, nil }}, want: "group ids"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := privateTmpSystemdRunArgsForAgent(tt.env, []string{"/usr/bin/test"}); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// TestPrivateTmpCanaryExpression_DetectsVisibleCanary runs the exact
// /usr/bin/test argument vector probePrivateTmp hands the transient service and
// proves its direction against the real test(1) binary: it exits 0 only when
// NEITHER canary is visible, and nonzero if EITHER is. Every other test mocks
// runCmd, so nothing else exercises the "! -e A -a ! -e B" semantics; a
// fail-open there (test wrongly reporting an existing canary as absent) would
// make the probe pass while /tmp leaked, and pass unnoticed here otherwise.
func TestPrivateTmpCanaryExpression_DetectsVisibleCanary(t *testing.T) {
	if _, err := os.Stat("/usr/bin/test"); err != nil {
		t.Skipf("/usr/bin/test unavailable: %v", err)
	}
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, nil, 0o600); err != nil {
		t.Fatalf("create present canary: %v", err)
	}
	absentA := filepath.Join(dir, "absentA")
	absentB := filepath.Join(dir, "absentB")

	run := func(a, b string) int {
		cmd := exec.CommandContext(context.Background(), "/usr/bin/test")
		cmd.Args = []string{"/usr/bin/test", "!", "-e", a, "-a", "!", "-e", b}
		err := cmd.Run()
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		t.Fatalf("run test(1): %v", err)
		return -1
	}

	if code := run(absentA, absentB); code != 0 {
		t.Fatalf("both absent: exit=%d, want 0 (isolated -> probe pass)", code)
	}
	for _, tc := range []struct {
		name string
		a, b string
	}{
		{"first visible", present, absentB},
		{"second visible", absentA, present},
		{"both visible", present, present},
	} {
		if code := run(tc.a, tc.b); code == 0 {
			t.Fatalf("%s: exit=0, want nonzero (leak -> probe fail)", tc.name)
		}
	}
}

func TestIsTerminalReader_RejectsPipesAndNonFiles(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = read.Close()
		_ = write.Close()
	})
	if isTerminalReader(read) {
		t.Fatal("pipe must not select a pseudo-terminal launch")
	}
	if isTerminalReader(strings.NewReader("input")) {
		t.Fatal("non-file reader must not select a pseudo-terminal launch")
	}
}
