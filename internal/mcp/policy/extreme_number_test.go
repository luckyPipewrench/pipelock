// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestExtremeNumberKeepsArgumentKeyPolicy(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{
		{Name: "command restriction", ToolPattern: "execute", ArgPattern: `restricted-command`, ArgKey: `^command$`},
	}})
	for _, num := range []string{"1.5", "1e999", "-1e999", "1E+400", "[1e999]", "1e-999"} {
		t.Run(num, func(t *testing.T) {
			for _, command := range []string{"restricted-command", "benign-command"} {
				req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute","arguments":{"command":"` + command + `","n":` + num + `}}}`
				v := pc.CheckRequest([]byte(req))
				want := command == "restricted-command"
				if v.Matched != want || (want && v.Action != config.ActionBlock) {
					t.Fatalf("command %q: matched=%v action=%q, want matched=%v", command, v.Matched, v.Action, want)
				}
			}
		})
	}
}
