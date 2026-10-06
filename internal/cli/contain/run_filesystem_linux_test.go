// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"io"
	"os/user"
	"strings"
	"testing"
)

func TestLaunchContainedAgentRefusesAnUnreadableFilesystemProfile(t *testing.T) {
	env := &probeEnv{
		agentUserName: "pipelock-agent",
		launchPath:    defaultLaunchScript,
		configPath:    "/etc/pipelock/pipelock.yaml",
		lookupUser: func(name string) (*user.User, error) {
			return &user.User{Username: name, Uid: "966", Gid: "966", HomeDir: "/srv/agent-home"}, nil
		},
		groupIDs: func(*user.User) ([]string, error) { return []string{"966"}, nil },
		readFile: func(string) ([]byte, error) { return nil, errors.New("config unreadable") },
	}
	err := launchContainedAgent(context.Background(), env, []string{"claude"}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "config unreadable") {
		t.Fatalf("err = %v", err)
	}
}
