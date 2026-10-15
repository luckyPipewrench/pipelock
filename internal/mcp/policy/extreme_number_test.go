// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestExtremeNumberKeepsCredentialKeyInspection(t *testing.T) {
	for _, num := range []string{"1.5", "1e999", "-1e999", "1e-999"} {
		t.Run(num, func(t *testing.T) {
			raw := json.RawMessage(`{"n":` + num + `,"nested":{".ssh/id_rsa":"ordinary"}}`)
			keys, ok := jsonObjectKeys(raw)
			if !ok || !slices.Contains(keys, ".ssh/id_rsa") {
				t.Fatalf("credential key was not inspected: keys=%q ok=%v", keys, ok)
			}
		})
	}
	for _, raw := range []string{`{"n":1e999} {}`, `{"n":1e999} trailing`, `{"n":1e}`} {
		if keys, ok := jsonObjectKeys(json.RawMessage(raw)); ok || len(keys) != 0 {
			t.Fatalf("malformed input reported inspectable: keys=%q ok=%v", keys, ok)
		}
	}
}

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
