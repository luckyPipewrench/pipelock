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
	// No tool policy: each rejection must come from the request key guard.
	for name, ic := range cfgs {
		for i, raw := range raws {
			opts := MCPProxyOpts{Scanner: testInputScanner(t), InputCfg: ic, stdioInputScanDisabled: ic == nil || !ic.Enabled}
			h := scanHTTPInputDecision([]byte(raw), &bytes.Buffer{}, "s", "s", opts).Blocked != nil
			frame := ParseMCPFrame([]byte(raw))
			// Isolate the frame predicate from content scanning and its core floor.
			gateOpts := MCPProxyOpts{InputCfg: ic}
			httpGate := EvaluateMCPInputGates(t.Context(), frame, []byte(raw), "s", gateOpts, config.ActionWarn, config.ActionForward, false)
			stdioGate := evaluateMCPInputGatesStdio(t.Context(), frame, []byte(raw), []byte(raw), nil, gateOpts, config.ActionWarn, config.ActionForward, false)
			if httpGate.ContentVerdict.Clean || stdioGate.ContentVerdict.Clean {
				t.Errorf("cfg=%s case=%d: isolated frame gate allowed invalid input: HTTP=%+v stdio=%+v", name, i, httpGate.ContentVerdict, stdioGate.ContentVerdict)
			}
			var up, logs bytes.Buffer
			onParseError := "forward"
			if ic != nil && ic.Enabled {
				onParseError = ic.OnParseError
			}
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(raw+"\n")), transport.NewStdioWriter(&up), &logs, config.ActionWarn, onParseError, make(chan BlockedRequest, 1), nil, nil, opts)
			if !h || up.Len() != 0 {
				t.Errorf("cfg=%-12s case=%d httpBlocked=%v stdioForwarded=%v", name, i, h, up.Len() != 0)
			}
		}
		raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"PATH":"one","Path":"two"}},"note":"ordinary metadata"}`
		opts := MCPProxyOpts{Scanner: testInputScanner(t), InputCfg: ic, stdioInputScanDisabled: ic == nil || !ic.Enabled}
		if scanHTTPInputDecision([]byte(raw), &bytes.Buffer{}, "s", "s", opts).Blocked != nil {
			t.Errorf("cfg=%s: valid HTTP request blocked", name)
		}
		var up, logs bytes.Buffer
		ForwardScannedInput(transport.NewStdioReader(strings.NewReader(raw+"\n")), transport.NewStdioWriter(&up), &logs, config.ActionWarn, "forward", make(chan BlockedRequest, 1), nil, nil, opts)
		if up.String() != raw+"\n" {
			t.Errorf("cfg=%s: valid stdio request not forwarded intact: %s", name, up.String())
		}
	}
}
