// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"encoding/json"
	"testing"
)

func TestSSHPublicKeyDecisionSurfaces(t *testing.T) {
	cfg, sc, pc := testSetup(t)
	for _, tc := range []struct {
		name, input string
		want        Outcome
	}{
		{"public", `{"path":"/home/u/.ssh/id_ed25519.pub"}`, Allow},
		{"private", `{"path":"/home/u/.ssh/id_ed25519"}`, Deny},
		{"separate argument", `{"path":"/home/u/.ssh/id_ed25519.pub","note":"other"}`, Deny},
		{"key DLP", "", Deny},
	} {
		input := tc.input
		if input == "" {
			raw, _ := json.Marshal(map[string]string{"AKIA" + "IOSFODNN7EXAMPLE": "/home/u/.ssh/id_ed25519.pub"})
			input = string(raw)
		}
		for _, kind := range []EventKind{EventMCPExecution, EventToolUse} {
			t.Run(tc.name+"/"+string(kind), func(t *testing.T) {
				action := Action{Kind: kind, MCP: &MCPPayload{ToolName: "read_file", ToolInput: input}, ToolUse: &ToolUsePayload{ToolName: "read_file", ToolInput: input}}
				d := Decide(t.Context(), cfg, sc, pc, action)
				if d.Outcome != tc.want {
					t.Fatalf("got %+v want %s", d, tc.want)
				}
				if tc.name == "key DLP" {
					found := false
					for _, e := range d.Evidence {
						if e.Scanner == "dlp" {
							found = true
						}
					}
					if !found {
						t.Fatal("key was not scanned for DLP")
					}
				}
			})
		}
	}
}
