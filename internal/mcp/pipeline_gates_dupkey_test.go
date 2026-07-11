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

var a2aDuplicateKeyPolicy = buildPolicyConfig(config.ActionBlock, []config.ToolPolicyRule{{
	Name:        "malicious-a2a-payload",
	ToolPattern: `^SendMessage$`,
	ArgPattern:  `malicious`,
}})

var a2aDuplicateKeyMessages = []struct {
	name string
	msg  []byte
}{
	{
		name: "top-level params duplicate",
		msg:  []byte(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"parts":[{"kind":"text","text":"malicious"}]}},"params":{"message":{"parts":[{"kind":"text","text":"benign"}]}}}`),
	},
	{
		name: "nested params duplicate",
		msg:  []byte(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"parts":[{"kind":"text","text":"malicious"}]},"message":{"parts":[{"kind":"text","text":"benign"}]}}}`),
	},
}

func TestEvaluateMCPInputGates_A2ADuplicateKeysFailClosedWithScanningDisabled(t *testing.T) {
	for _, tt := range a2aDuplicateKeyMessages {
		t.Run(tt.name, func(t *testing.T) {
			frame := ParseMCPFrame(tt.msg)
			if frame.ParseErr == nil {
				t.Fatal("ParseMCPFrame ParseErr = nil, want duplicate-key error")
			}
			if v := a2aDuplicateKeyPolicy.CheckRequest(tt.msg); !v.Matched || v.Action != config.ActionBlock {
				t.Fatalf("policy duplicate-key defense = %+v, want block match", v)
			}

			eval := EvaluateMCPInputGates(
				t.Context(),
				frame,
				tt.msg,
				"session-1",
				MCPProxyOpts{PolicyCfg: a2aDuplicateKeyPolicy},
				config.ActionWarn,
				config.ActionBlock,
				false,
			)

			if eval.BlockingGate != blockingGateParseError {
				t.Fatalf("BlockingGate = %q, want %s", eval.BlockingGate, blockingGateParseError)
			}
			if eval.ContentVerdict.Error == "" {
				t.Fatal("ContentVerdict.Error is empty, want duplicate-key parse error")
			}
		})
	}
}

func TestEvaluateMCPInputGatesStdio_A2ADuplicateKeysFailClosedWithPolicyOnly(t *testing.T) {
	for _, tt := range a2aDuplicateKeyMessages {
		t.Run(tt.name, func(t *testing.T) {
			frame := ParseMCPFrame(tt.msg)
			if frame.ParseErr == nil {
				t.Fatal("ParseMCPFrame ParseErr = nil, want duplicate-key error")
			}
			if v := a2aDuplicateKeyPolicy.CheckRequest(tt.msg); !v.Matched || v.Action != config.ActionBlock {
				t.Fatalf("policy duplicate-key defense = %+v, want block match", v)
			}

			eval := EvaluateMCPInputGatesStdio(
				t.Context(),
				frame,
				tt.msg,
				tt.msg,
				nil,
				MCPProxyOpts{
					Scanner:   testInputScanner(t),
					PolicyCfg: a2aDuplicateKeyPolicy,
				},
				config.ActionWarn,
				config.ActionBlock,
			)

			if eval.BlockingGate != blockingGateParseError {
				t.Fatalf("BlockingGate = %q, want %s", eval.BlockingGate, blockingGateParseError)
			}
			if eval.ContentVerdict.Error == "" {
				t.Fatal("ContentVerdict.Error is empty, want duplicate-key parse error")
			}
		})
	}
}

func TestScanHTTPInput_A2ADuplicateKeysPolicyOnlyNotForwardable(t *testing.T) {
	for _, tt := range a2aDuplicateKeyMessages {
		t.Run(tt.name, func(t *testing.T) {
			result := scanHTTPInputDecision(tt.msg, &bytes.Buffer{}, "session-1", "session-1", MCPProxyOpts{
				Scanner:   testInputScanner(t),
				PolicyCfg: a2aDuplicateKeyPolicy,
			})

			if result.Blocked == nil {
				t.Fatal("Blocked = nil, want duplicate-key parse-error block")
			}
			if result.Blocked.ErrorCode != -32600 {
				t.Fatalf("ErrorCode = %d, want -32600", result.Blocked.ErrorCode)
			}
		})
	}
}

func TestForwardScannedInput_A2ADuplicateKeysPolicyOnlyNotForwarded(t *testing.T) {
	for _, tt := range a2aDuplicateKeyMessages {
		t.Run(tt.name, func(t *testing.T) {
			var serverIn bytes.Buffer
			var logW bytes.Buffer
			blockedCh := make(chan BlockedRequest, 1)

			ForwardScannedInput(
				transport.NewStdioReader(strings.NewReader(string(tt.msg)+"\n")),
				transport.NewStdioWriter(&serverIn),
				&logW,
				config.ActionWarn,
				config.ActionBlock,
				blockedCh,
				nil,
				nil,
				MCPProxyOpts{
					Scanner:   testInputScanner(t),
					PolicyCfg: a2aDuplicateKeyPolicy,
				},
			)

			if serverIn.Len() > 0 {
				t.Fatalf("unsafe duplicate-key request was forwarded upstream: %q", serverIn.String())
			}
			var gotBlocked bool
			for br := range blockedCh {
				gotBlocked = true
				if br.ErrorCode != -32600 {
					t.Fatalf("ErrorCode = %d, want -32600", br.ErrorCode)
				}
			}
			if !gotBlocked {
				t.Fatal("blockedCh produced no duplicate-key parse-error block")
			}
		})
	}
}
