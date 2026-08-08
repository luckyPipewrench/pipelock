// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The installer must be able to express only the two operations it needs, with
// every argument a literal, so it never becomes a general command surface.
func TestSystemctlCommandBuildsOnlyPermittedOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		op       systemctlOp
		wantArgs []string
	}{
		{
			name:     "daemon reload",
			op:       systemctlDaemonReload,
			wantArgs: []string{"systemctl", "--user", "daemon-reload"},
		},
		{
			name:     "enable auditor timer",
			op:       systemctlEnableAuditorTimer,
			wantArgs: []string{"systemctl", "--user", "enable", "--now", evidenceCorpusAuditorTimer},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, err := systemctlCommand(t.Context(), tt.op)
			if err != nil {
				t.Fatalf("systemctlCommand(%q): %v", tt.op, err)
			}
			// Element-wise. A joined comparison makes {"enable", "--now"}
			// and {"enable --now"} look identical, which is the difference
			// between two arguments and one.
			if !slices.Equal(cmd.Args, tt.wantArgs) {
				t.Fatalf("args = %q, want %q", cmd.Args, tt.wantArgs)
			}
		})
	}
}

func TestSystemctlCommandRefusesUnknownOperation(t *testing.T) {
	t.Parallel()

	cmd, err := systemctlCommand(t.Context(), systemctlOp("stop pipelock.service"))
	if err == nil {
		t.Fatalf("unknown operation was accepted, built %q", cmd.Args)
	}
	if !strings.Contains(err.Error(), "unsupported systemctl operation") {
		t.Fatalf("error = %v, want an unsupported-operation error", err)
	}
}

// A failing systemctl must surface its combined output, because a silent
// install failure is how an auditor ends up never running.
func TestEvidenceAuditorSystemctlReportsCommandFailure(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })

	sentinel := errors.New("exit status 1")
	var seen []string
	evidenceAuditorRunCommand = func(cmd *exec.Cmd) ([]byte, error) {
		seen = cmd.Args
		return []byte("Failed to enable unit"), sentinel
	}

	err := runSystemctlOp(context.Background(), systemctlEnableAuditorTimer)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the command failure", err)
	}
	if !strings.Contains(err.Error(), "Failed to enable unit") {
		t.Fatalf("error = %v, want the combined output included", err)
	}
	if want := []string{"systemctl", "--user", "enable", "--now", evidenceCorpusAuditorTimer}; !slices.Equal(seen, want) {
		t.Fatalf("ran %q, want %q", seen, want)
	}
}

// A permitted operation that succeeds must report success, which is the path
// every real install takes.
func TestEvidenceAuditorSystemctlSucceedsForPermittedOperation(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })

	var seen []string
	evidenceAuditorRunCommand = func(cmd *exec.Cmd) ([]byte, error) {
		seen = cmd.Args
		return nil, nil
	}

	if err := runSystemctlOp(context.Background(), systemctlDaemonReload); err != nil {
		t.Fatalf("daemon-reload: %v", err)
	}
	if want := []string{"systemctl", "--user", "daemon-reload"}; !slices.Equal(seen, want) {
		t.Fatalf("ran %q, want %q", seen, want)
	}
}

func TestEvidenceAuditorSystemctlRefusesUnknownOperation(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })

	ran := false
	evidenceAuditorRunCommand = func(*exec.Cmd) ([]byte, error) {
		ran = true
		return nil, nil
	}

	if err := runSystemctlOp(context.Background(), systemctlOp("disable pipelock.service")); err == nil {
		t.Fatal("unknown operation was executed")
	}
	if ran {
		t.Fatal("unknown operation reached the process seam")
	}
}
