// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// TestAgentSysProcAttr_DropsCallerGroups locks in the privilege-separation
// invariant for the contained launch: setgroups(2) MUST run (NoSetGroups
// false) so the child drops root's supplementary groups instead of inheriting
// them, and it launches under exactly the agent's resolved group set.
func TestAgentSysProcAttr_DropsCallerGroups(t *testing.T) {
	groups := []uint32{966, 1001}
	attr := agentSysProcAttr(966, 966, groups)

	if attr.Credential == nil {
		t.Fatal("credential must not be nil")
	}
	if attr.Credential.NoSetGroups {
		t.Fatal("NoSetGroups must be false so setgroups(2) drops the launcher's (root's) supplementary groups")
	}
	if attr.Credential.Uid != 966 || attr.Credential.Gid != 966 {
		t.Fatalf("uid/gid = %d/%d, want 966/966", attr.Credential.Uid, attr.Credential.Gid)
	}
	if !equalGIDs(attr.Credential.Groups, groups) {
		t.Fatalf("groups = %v, want %v", attr.Credential.Groups, groups)
	}
	for _, g := range attr.Credential.Groups {
		if g == 0 {
			t.Fatalf("contained launch must not carry root group 0: %v", attr.Credential.Groups)
		}
	}
}

func TestLaunchContainedAgent_RejectsRootUIDOrGID(t *testing.T) {
	tests := []struct {
		name string
		uid  string
		gid  string
	}{
		{name: "root uid", uid: "0", gid: "966"},
		{name: "root gid", uid: "966", gid: "0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := containRunLinuxGuardEnv(tt.uid, tt.gid, defaultLaunchScript)
			err := launchContainedAgent(context.Background(), env, []string{"claude"}, nil, io.Discard, io.Discard)
			if err == nil {
				t.Fatal("expected root uid/gid rejection")
			}
			if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
				t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
			}
			if !strings.Contains(err.Error(), "refusing to launch a contained tool as root") {
				t.Fatalf("error = %v, want root launch refusal", err)
			}
		})
	}
}

func TestLaunchContainedAgent_RejectsUnexpectedLaunchPath(t *testing.T) {
	env := containRunLinuxGuardEnv("966", "966", "/tmp/plk-launch")
	err := launchContainedAgent(context.Background(), env, []string{"claude"}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected unexpected launcher path rejection")
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
		t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
	}
	if !strings.Contains(err.Error(), "does not match expected") {
		t.Fatalf("error = %v, want launcher path mismatch", err)
	}
}

func TestRunCmd_RejectsNonRootAfterPlatformCheck(t *testing.T) {
	if isRoot() {
		t.Skip("root environment cannot exercise the non-root guard")
	}
	cmd := runCmd()
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"claude"})

	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected non-root rejection")
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
		t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
	}
	if !strings.Contains(err.Error(), "must be run as root") {
		t.Fatalf("error = %v, want root guard", err)
	}
}

func TestLaunchContainedAgent_RejectsBadAgentUserRecord(t *testing.T) {
	tests := []struct {
		name string
		env  *probeEnv
		want string
	}{
		{
			name: "lookup failure",
			env: &probeEnv{
				agentUserName: testAgentUser,
				launchPath:    defaultLaunchScript,
				lookupUser: func(string) (*user.User, error) {
					return nil, errors.New("missing user")
				},
			},
			want: "lookup " + testAgentUser,
		},
		{
			name: "bad uid",
			env:  containRunLinuxGuardEnv("not-a-uid", "966", defaultLaunchScript),
			want: "parse uid",
		},
		{
			name: "bad gid",
			env:  containRunLinuxGuardEnv("966", "not-a-gid", defaultLaunchScript),
			want: "parse gid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := launchContainedAgent(context.Background(), tt.env, []string{"claude"}, nil, io.Discard, io.Discard)
			if err == nil {
				t.Fatal("expected bad agent user record rejection")
			}
			if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
				t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLaunchContainedAgent_RunsVerifiedCommandAsAgent(t *testing.T) {
	current := testContainedAgentUser()

	env := &probeEnv{
		agentUserName: current.Username,
		launchPath:    defaultLaunchScript,
		lookupUser: func(name string) (*user.User, error) {
			if name != current.Username {
				t.Fatalf("lookup user = %q, want %q", name, current.Username)
			}
			return current, nil
		},
		groupIDs: func(*user.User) ([]string, error) {
			return []string{current.Gid, "1001"}, nil
		},
	}

	oldRun := runContainedAgentCommand
	defer func() { runContainedAgentCommand = oldRun }()
	var got *exec.Cmd
	runContainedAgentCommand = func(cmd *exec.Cmd) error {
		got = cmd
		return nil
	}

	if err := launchContainedAgent(context.Background(), env, []string{"claude", "--version"}, nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("launchContainedAgent: %v", err)
	}
	if got == nil {
		t.Fatal("runner was not called")
	}
	if got.Path != defaultLaunchScript {
		t.Fatalf("path = %q, want %q", got.Path, defaultLaunchScript)
	}
	if want := defaultLaunchScript + " claude --version"; strings.Join(got.Args, " ") != want {
		t.Fatalf("args = %q, want %q", strings.Join(got.Args, " "), want)
	}
}

func TestLaunchContainedAgent_MapsContainedExitStatus(t *testing.T) {
	current := testContainedAgentUser()

	exitErr := exec.CommandContext(context.Background(), "sh", "-c", "exit 7").Run()
	if exitErr == nil {
		t.Fatal("expected helper command to fail")
	}

	env := &probeEnv{
		agentUserName: current.Username,
		launchPath:    defaultLaunchScript,
		lookupUser: func(string) (*user.User, error) {
			return current, nil
		},
		groupIDs: func(*user.User) ([]string, error) {
			return []string{current.Gid, "1001"}, nil
		},
	}

	oldRun := runContainedAgentCommand
	defer func() { runContainedAgentCommand = oldRun }()
	runContainedAgentCommand = func(*exec.Cmd) error {
		return exitErr
	}

	err := launchContainedAgent(context.Background(), env, []string{"claude"}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected contained exit status")
	}
	if got := cliutil.ExitCodeOf(err); got != 7 {
		t.Fatalf("exit code = %d, want 7", got)
	}
	if !strings.Contains(err.Error(), "contained agent exited with status 7") {
		t.Fatalf("error = %v, want contained exit status context", err)
	}
}

func TestLaunchContainedAgent_MapsSignaledContainedExit(t *testing.T) {
	current := testContainedAgentUser()

	exitErr := exec.CommandContext(context.Background(), "sh", "-c", "kill -TERM $$").Run()
	if exitErr == nil {
		t.Fatal("expected helper command to be terminated by signal")
	}

	env := &probeEnv{
		agentUserName: current.Username,
		launchPath:    defaultLaunchScript,
		lookupUser: func(string) (*user.User, error) {
			return current, nil
		},
		groupIDs: func(*user.User) ([]string, error) {
			return []string{current.Gid, "1001"}, nil
		},
	}

	oldRun := runContainedAgentCommand
	defer func() { runContainedAgentCommand = oldRun }()
	runContainedAgentCommand = func(*exec.Cmd) error {
		return exitErr
	}

	err := launchContainedAgent(context.Background(), env, []string{"claude"}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected contained signal exit")
	}
	wantCode := 128 + int(syscall.SIGTERM)
	if got := cliutil.ExitCodeOf(err); got != wantCode {
		t.Fatalf("exit code = %d, want %d", got, wantCode)
	}
	if !strings.Contains(err.Error(), "contained agent terminated by signal") {
		t.Fatalf("error = %v, want contained signal context", err)
	}
}

func TestLaunchContainedAgent_WrapsStartupFailure(t *testing.T) {
	current := testContainedAgentUser()

	env := &probeEnv{
		agentUserName: current.Username,
		launchPath:    defaultLaunchScript,
		lookupUser: func(string) (*user.User, error) {
			return current, nil
		},
		groupIDs: func(*user.User) ([]string, error) {
			return []string{current.Gid, "1001"}, nil
		},
	}

	oldRun := runContainedAgentCommand
	defer func() { runContainedAgentCommand = oldRun }()
	runContainedAgentCommand = func(*exec.Cmd) error {
		return errors.New("fork failed")
	}

	err := launchContainedAgent(context.Background(), env, []string{"claude"}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected runner error")
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitGeneral {
		t.Fatalf("exit code = %d, want %d", got, cliutil.ExitGeneral)
	}
	if !strings.Contains(err.Error(), "launch contained agent via "+defaultLaunchScript) || !strings.Contains(err.Error(), "fork failed") {
		t.Fatalf("error = %v, want wrapped launcher startup context", err)
	}
}

func TestContainedAgentCommand_UsesFixedLauncherAndAgentIdentity(t *testing.T) {
	stdin := strings.NewReader("input")
	var stdout, stderr bytes.Buffer
	groups := []uint32{966, 1001}

	cmd := containedAgentCommand(containedAgentCommandOptions{
		ctx:           context.Background(),
		agentUserName: testAgentUser,
		homeDir:       "/home/" + testAgentUser,
		proxyPort:     defaultProxyPort,
		uid:           966,
		gid:           966,
		groups:        groups,
		args:          []string{"claude", "--help"},
		stdin:         stdin,
		stdout:        &stdout,
		stderr:        &stderr,
	})

	if cmd.Path != defaultLaunchScript {
		t.Fatalf("path = %q, want %q", cmd.Path, defaultLaunchScript)
	}
	if got, want := strings.Join(cmd.Args, " "), defaultLaunchScript+" claude --help"; got != want {
		t.Fatalf("args = %q, want %q", got, want)
	}
	if cmd.Stdin != stdin || cmd.Stdout != &stdout || cmd.Stderr != &stderr {
		t.Fatal("command stdio was not wired through")
	}
	if cmd.Dir != "/home/"+testAgentUser {
		t.Fatalf("dir = %q, want contained agent home", cmd.Dir)
	}
	wantEnv := containLaunchEnv(testAgentUser, "/home/"+testAgentUser, defaultProxyPort)
	if got, want := strings.Join(cmd.Env, "\n"), strings.Join(wantEnv, "\n"); got != want {
		t.Fatalf("env =\n%s\nwant:\n%s", got, want)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("command missing launch credential")
	}
	cred := cmd.SysProcAttr.Credential
	if cred.Uid != 966 || cred.Gid != 966 {
		t.Fatalf("uid/gid = %d/%d, want 966/966", cred.Uid, cred.Gid)
	}
	if cred.NoSetGroups {
		t.Fatal("NoSetGroups must stay false")
	}
	if !equalGIDs(cred.Groups, groups) {
		t.Fatalf("groups = %v, want %v", cred.Groups, groups)
	}
}

func containRunLinuxGuardEnv(uid, gid, launchPath string) *probeEnv {
	return &probeEnv{
		agentUserName: testAgentUser,
		launchPath:    launchPath,
		lookupUser: func(name string) (*user.User, error) {
			return &user.User{
				Uid:      uid,
				Gid:      gid,
				Username: name,
				HomeDir:  "/home/" + name,
			}, nil
		},
		groupIDs: func(*user.User) ([]string, error) {
			return []string{gid, "1001"}, nil
		},
	}
}

func testContainedAgentUser() *user.User {
	return &user.User{
		Uid:      "966",
		Gid:      "966",
		Username: testAgentUser,
		HomeDir:  "/home/" + testAgentUser,
	}
}
