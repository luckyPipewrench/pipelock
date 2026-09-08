// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// MCP stdio and MCP HTTP input do not receive a verified upstream authority.
// A provider URL embedded in an input message is agent-controlled content, not
// an authority, so both transports must retain the DLP match and block.
func TestCredentialAudienceHost_DoesNotRelaxMCPStdioOrHTTPInput(t *testing.T) {
	sc := testInputScanner(t)
	tests := []struct {
		name       string
		credential string
		target     string
	}{
		{name: "OpenAI", credential: "sk-" + "proj-" + strings.Repeat("a", 24), target: "https://api.openai.com/v1"},
		{name: "Anthropic", credential: "sk-" + "ant-" + strings.Repeat("a", 24), target: "https://api.anthropic.com/v1/messages"},
		{name: "Discord", credential: "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27), target: "https://discord.com/api/v10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"target":"` + tt.target + `","credential":"` + tt.credential + `"}}}`)
			frame := ParseMCPFrame(msg)

			stdio := EvaluateMCPInputGatesStdio(context.Background(), frame, msg, msg, nil, testOpts(sc), config.ActionBlock, config.ActionBlock)
			if stdio.ContentVerdict.Clean || len(stdio.ContentVerdict.Matches) == 0 {
				t.Fatalf("MCP stdio accepted audience-bound credential: %+v", stdio.ContentVerdict)
			}

			var log bytes.Buffer
			httpBlocked := scanHTTPInput(msg, &log, "session-a", "audit-a", MCPProxyOpts{
				Scanner:  sc,
				InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
			})
			if httpBlocked == nil {
				t.Fatal("MCP HTTP input accepted audience-bound credential")
			}
		})
	}
}
