// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

func TestInsertSystemdPropertiesAppendsWhenThereIsNoSeparator(t *testing.T) {
	args := insertSystemdProperties([]string{"systemd-run", "true"}, []string{"ProtectSystem=strict"})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--property=ProtectSystem=strict") || strings.Contains(joined, "--property=--") {
		t.Fatalf("args = %v", args)
	}
}

func TestPrivateTmpPropertiesFailWhenTheAgentLookupFails(t *testing.T) {
	env := &probeEnv{
		agentUserName: "pipelock-agent",
		lookupUser:    func(string) (*user.User, error) { return nil, errors.New("missing account") },
	}
	_, err := privateTmpSystemdRunArgsForAgentProperties(env, []string{"/bin/true"}, []string{"PrivateTmp=true"})
	if err == nil || !strings.Contains(err.Error(), "missing account") {
		t.Fatalf("err = %v", err)
	}
}
