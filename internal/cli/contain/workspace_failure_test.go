// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestRunContainRun_InventoryFailureStopsBeforePreflight(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed=%t", malformed), func(t *testing.T) {
			env := allPassEnv(t)
			readFile := env.readFile
			env.readFile = func(path string) ([]byte, error) {
				if path == env.workspaceInvPath {
					if malformed {
						return []byte(`{"workspaces":`), nil
					}
					return nil, os.ErrPermission
				}
				return readFile(path)
			}
			postureCalls, launches := 0, 0
			runEnv := containRunEnv{
				probe: env,
				launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
					launches++
					return nil
				},
				emitPosture: func(string, string, *probeEnv, []string) (string, error) {
					postureCalls++
					return "proof.json", nil
				},
			}
			var out bytes.Buffer
			err := runContainRun(context.Background(), strings.NewReader(""), &out, io.Discard, runEnv, containRunOptions{}, []string{"agent-tool"})
			if cliutil.ExitCodeOf(err) != cliutil.ExitGeneral || err == nil || !strings.Contains(err.Error(), "read workspace inventory") {
				t.Fatalf("run error = %v, want inventory failure with general exit code", err)
			}
			if !malformed && !errors.Is(err, os.ErrPermission) {
				t.Fatalf("read error lost its cause: %v", err)
			}
			if malformed {
				var syntaxErr *json.SyntaxError
				if !errors.As(err, &syntaxErr) {
					t.Fatalf("malformed inventory error lost its cause: %v", err)
				}
			}
			if out.Len() != 0 || postureCalls != 0 || launches != 0 {
				t.Fatalf("unreadable inventory reached preflight/posture/launch: output=%q, posture=%d, launches=%d", out.String(), postureCalls, launches)
			}
		})
	}
}

func TestWorkspacePartialCommandFailurePreservesInventory(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		for _, commandError := range []bool{false, true} {
			t.Run(fmt.Sprintf("revoke=%t/command_error=%t", revoke, commandError), func(t *testing.T) {
				env, runner, out := newFakeEnv(t)
				workspace := filepath.Join(t.TempDir(), "nested", "workspace")
				if err := os.MkdirAll(workspace, 0o750); err != nil {
					t.Fatal(err)
				}
				initial := workspaceInventory{Workspaces: []workspaceGrant{
					{Path: t.TempDir(), Mode: workspaceModeReadOnly, AgentUser: env.agentUserName},
				}}
				commands := workspaceACLCommands(workspace, env.agentUserName, workspaceModeReadOnly)
				if revoke {
					initial.Workspaces = append(initial.Workspaces, workspaceGrant{Path: workspace, Mode: workspaceModeReadOnly, AgentUser: env.agentUserName})
					remaining := workspaceGrantsExcept(initial.Workspaces, workspace, env.agentUserName)
					commands = workspaceRevokeCommands(workspace, env.agentUserName, ancestorsNeededBy(grantsForAgent(remaining, env.agentUserName)), true)
				}
				if len(commands) < 3 {
					t.Fatalf("need a partial application sequence, got %d commands", len(commands))
				}
				if err := writeWorkspaceInventory(env, initial); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(env.workspaceInvPath)
				if err != nil {
					t.Fatal(err)
				}
				wantErr := errors.New("ACL command interrupted")
				failed := commands[1]
				if commandError {
					runner.on(argvFor(failed.name, failed.args...), "", 0, wantErr)
				} else {
					runner.on(argvFor(failed.name, failed.args...), "ACL refused", 1, nil)
				}
				runner.calls = nil
				out.Reset()
				if revoke {
					err = runRevokeWorkspace(context.Background(), env, workspace, workspaceOpts{})
				} else {
					err = runGrantWorkspace(context.Background(), env, workspace, workspaceOpts{})
				}
				if err == nil || cliutil.ExitCodeOf(err) != cliutil.ExitGeneral {
					t.Fatalf("partial ACL application error = %v, want general failure", err)
				}
				if commandError && !errors.Is(err, wantErr) {
					t.Fatalf("command failure lost its cause: %v", err)
				}
				if !commandError && !strings.Contains(err.Error(), "exit 1: ACL refused") {
					t.Fatalf("command exit failure lost its output: %v", err)
				}
				if len(runner.calls) != 2 {
					t.Fatalf("ran %d commands after second command failed: %+v", len(runner.calls), runner.calls)
				}
				for i, call := range runner.calls {
					if argvFor(call.name, call.args...) != argvFor(commands[i].name, commands[i].args...) {
						t.Fatalf("command %d = %+v, want %+v", i, call, commands[i])
					}
				}
				after, err := os.ReadFile(env.workspaceInvPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) || out.Len() != 0 {
					t.Fatalf("failed ACL operation recorded success: before=%s, after=%s, output=%q", before, after, out.String())
				}
			})
		}
	}
}
