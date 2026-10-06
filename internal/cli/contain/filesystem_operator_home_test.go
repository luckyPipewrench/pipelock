// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"io/fs"
	"os/user"
	"strings"
	"testing"
)

func TestFilesystemProfileProperties_ResolvedOperatorHome(t *testing.T) {
	tests := []struct {
		name     string
		resolved string
		grant    string
		wantErr  string
	}{
		{name: "unset keeps the lexical check", resolved: ""},
		{name: "same path", resolved: "/home/operator"},
		{name: "resolves under home", resolved: "/home/real-operator"},
		{name: "resolves outside home is refused", resolved: "/srv/homes/operator", wantErr: "resolves to /srv/homes/operator"},
		{name: "grant over the resolved home is refused", resolved: "/home/real-operator", grant: "/home/real-operator", wantErr: "contains operator home /home/real-operator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := enforceInput()
			in.OperatorHomeResolved = tt.resolved
			if tt.grant != "" {
				in.Grants = []workspaceGrant{{Path: tt.grant, Mode: workspaceModeReadOnly, AgentUser: "pipelock-agent"}}
				in.Eval = allowEval("/srv/agent-home", tt.grant)
			}
			_, err := filesystemProfileProperties(in)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("profile: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestFilesystemProfileInputResolvesOperatorHome(t *testing.T) {
	prev := resolveOperatorHome
	t.Cleanup(func() { resolveOperatorHome = prev })
	tests := []struct {
		name    string
		resolve func(string) (string, error)
		want    string
		wantErr string
	}{
		{name: "symlink target recorded", resolve: func(string) (string, error) { return "/srv/homes/operator", nil }, want: "/srv/homes/operator"},
		{name: "missing home keeps the lexical check", resolve: func(string) (string, error) { return "", fs.ErrNotExist }, want: ""},
		{name: "other resolve errors refuse", resolve: func(string) (string, error) { return "", fs.ErrPermission }, wantErr: "resolve operator home"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveOperatorHome = tt.resolve
			env := &probeEnv{
				agentUserName: "pipelock-agent",
				operatorUser:  "operator",
				lookupUser: func(name string) (*user.User, error) {
					return &user.User{Username: name, HomeDir: "/home/" + name}, nil
				},
			}
			env.configPath = "/etc/pipelock/pipelock.yaml"
			env.readFile = func(string) ([]byte, error) {
				return []byte("containment:\n  filesystem:\n    mode: enforce\n"), nil
			}
			in, err := filesystemProfileInputForProbe(env, "/srv/agent-home")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if in.OperatorHomeResolved != tt.want {
				t.Fatalf("resolved = %q, want %q", in.OperatorHomeResolved, tt.want)
			}
		})
	}
}
