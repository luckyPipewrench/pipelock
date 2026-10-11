// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestR3EnvelopeInputCfgMatrix(t *testing.T) {
	pol := buildPolicyConfig(config.ActionBlock, []config.ToolPolicyRule{{Name: "deny-write", ToolPattern: `^write_file$`}})
	cfgs := map[string]*InputScanConfig{
		"nil":          nil,
		"disabled":     {Enabled: false},
		"warn+forward": {Enabled: true, Action: config.ActionWarn, OnParseError: "forward"},
		"block+block":  {Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
	}
	raws := []string{
		`{"jsonrpc":2,"id":1,"method":"tools/call","params":{"name":"write_file","Name":"read_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","Name":"read_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"t":"` + string([]byte{0xff}) + `"}}}`,
	}
	for name, ic := range cfgs {
		for i, raw := range raws {
			opts := MCPProxyOpts{Scanner: testInputScanner(t), PolicyCfg: pol, InputCfg: ic}
			h := scanHTTPInputDecision([]byte(raw), &bytes.Buffer{}, "s", "s", opts).Blocked != nil
			var up, logs bytes.Buffer
			onParseError := config.ActionBlock
			if ic != nil && ic.Enabled {
				onParseError = ic.OnParseError
			}
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(raw+"\n")), transport.NewStdioWriter(&up), &logs, config.ActionWarn, onParseError, make(chan BlockedRequest, 1), nil, nil, opts)
			if !h || up.Len() != 0 {
				t.Errorf("cfg=%-12s case=%d httpBlocked=%v stdioForwarded=%v", name, i, h, up.Len() != 0)
			}
		}
	}
}
