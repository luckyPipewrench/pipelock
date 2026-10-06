// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/user"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestLaunchPropertiesCommandLooksUpTheRequestedUser(t *testing.T) {
	cmd := launchPropertiesCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--agent-user", "pipelock-no-such-agent"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "lookup") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunLaunchPropertiesUsesTheNamedAccount(t *testing.T) {
	err := runLaunchProperties(context.Background(), io.Discard, io.Discard, "pipelock-no-such-agent")
	if err == nil || !strings.Contains(err.Error(), "pipelock-no-such-agent") {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteLaunchPropertiesReportsLookupHomeAndProfileErrors(t *testing.T) {
	base := func() *probeEnv {
		return &probeEnv{
			configPath:    "/etc/pipelock/pipelock.yaml",
			agentUserName: "pipelock-agent",
			lookupUser: func(name string) (*user.User, error) {
				return &user.User{Username: name, Uid: "966", Gid: "966", HomeDir: "/srv/agent-home"}, nil
			},
			readFile: func(string) ([]byte, error) {
				return []byte("containment:\n  filesystem:\n    mode: off\n"), nil
			},
		}
	}

	env := base()
	env.lookupUser = func(string) (*user.User, error) { return nil, errors.New("unknown account") }
	if err := writeLaunchProperties(context.Background(), io.Discard, env); err == nil || !strings.Contains(err.Error(), "unknown account") {
		t.Fatalf("lookup err = %v", err)
	}

	env = base()
	env.lookupUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "966", Gid: "966", HomeDir: "relative"}, nil
	}
	if err := writeLaunchProperties(context.Background(), io.Discard, env); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("home err = %v", err)
	}

	env = base()
	env.operatorUser = "operator"
	env.lookupUser = func(name string) (*user.User, error) {
		home := "/srv/agent-home"
		if name == "operator" {
			home = "/opt/operator"
		}
		return &user.User{Username: name, Uid: "966", Gid: "966", HomeDir: home}, nil
	}
	env.readFile = func(string) ([]byte, error) {
		return []byte("containment:\n  filesystem:\n    mode: enforce\n"), nil
	}
	if err := writeLaunchProperties(context.Background(), io.Discard, env); err == nil || !strings.Contains(err.Error(), "not hidden by enforce") {
		t.Fatalf("profile err = %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWriteLaunchPropertiesPrintsOffModeAndSurfacesWriteErrors(t *testing.T) {
	env := &probeEnv{
		configPath:    "/etc/pipelock/pipelock.yaml",
		agentUserName: "pipelock-agent",
		display:       ":99",
		lookupUser: func(name string) (*user.User, error) {
			return &user.User{Username: name, Uid: "966", Gid: "966", HomeDir: "/srv/agent-home"}, nil
		},
		readFile: func(string) ([]byte, error) {
			return []byte("containment:\n  filesystem:\n    mode: " + config.ContainmentFilesystemModeOff + "\n"), nil
		},
	}
	var buf bytes.Buffer
	if err := writeLaunchProperties(context.Background(), &buf, env); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "BindReadOnlyPaths=") || !strings.Contains(buf.String(), ".X11-unix") {
		t.Fatalf("printed = %q", buf.String())
	}
	if err := writeLaunchProperties(context.Background(), failWriter{}, env); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("write err = %v", err)
	}
}
