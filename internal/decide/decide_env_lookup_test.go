// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A shell command is code about to run: an assignment whose whole statement is
// one environment lookup is not a credential, while a literal still is.
func TestDecide_ShellEnvLookupAssignment(t *testing.T) {
	cfg, _, pc := testSetup(t)
	// Shell decisions run on a tool-command scanner, as the Claude and Cursor
	// hook commands build one for shell actions.
	sc, err := scanner.NewWithOptions(cfg, scanner.Options{ToolCommandEnvLookups: true})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(sc.Close)

	kw := "to" + "ken"
	secret := strings.Join([]string{"q7Hx", "2mPv", "9kLw", "4nRt"}, "")
	tests := []struct {
		name    string
		command string
		want    Outcome
	}{
		{
			name:    "environment lookup statement",
			command: `python3 -c 'import os; ` + kw + `=os.environ.get("SLACK_BOT_TOKEN"); assert ` + kw + `'`,
			want:    Allow,
		},
		{
			name:    "literal value",
			command: `python3 -c 'import os; ` + kw + `=` + secret + `; print(1)'`,
			want:    Deny,
		},
		{
			name:    "or default literal",
			command: `python3 -c 'import os; ` + kw + `=os.environ.get("SLACK_BOT_TOKEN") or "` + secret + `"'`,
			want:    Deny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Decide(context.Background(), cfg, sc, pc, Action{
				Source: "cursor",
				Kind:   EventShellExecution,
				Shell:  &ShellPayload{Command: tt.command, CWD: "/tmp"},
			})
			if decision.Outcome != tt.want {
				t.Fatalf("outcome = %s, want %s; evidence = %+v", decision.Outcome, tt.want, decision.Evidence)
			}
		})
	}
}
