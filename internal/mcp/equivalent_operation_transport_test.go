// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestEquivalentOperationPolicyTransportGateParity(t *testing.T) {
	sc := testInputScanner(t)
	policyCfg := policy.New(config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionWarn,
		Rules:   policy.DefaultToolPolicyRules(),
	})
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"move_file","arguments":{"source":"/tmp/staged","destination":"/home/user/.bashrc"}}}`)
	frame := ParseMCPFrame(msg)
	opts := testOpts(sc)
	opts.PolicyCfg = policyCfg

	httpEval := EvaluateMCPInputGates(context.Background(), frame, msg, "session", opts, config.ActionWarn, config.ActionBlock, true)
	stdioEval := EvaluateMCPInputGatesStdio(context.Background(), frame, msg, msg, nil, opts, config.ActionWarn, config.ActionBlock)
	for name, verdict := range map[string]policy.Verdict{
		"HTTP":  httpEval.PolicyVerdict,
		"stdio": stdioEval.PolicyVerdict,
	} {
		if !verdict.Matched || verdict.Action != config.ActionBlock || !slices.Contains(verdict.Rules, "Shell Profile Modification") {
			t.Fatalf("%s policy verdict = %+v, want Shell Profile Modification block", name, verdict)
		}
	}
}

func TestEquivalentOperationWarnPresetsExposeRuleOnBothMCPTransports(t *testing.T) {
	sc := testInputScanner(t)
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"move_file","arguments":{"source":"/tmp/staged","destination":"/home/user/.bashrc"}}}`

	for _, preset := range []string{"audit", "generic-agent"} {
		t.Run(preset, func(t *testing.T) {
			cfg, err := config.Load("../../configs/" + preset + ".yaml")
			if err != nil {
				t.Fatal(err)
			}
			policyCfg := policy.New(cfg.MCPToolPolicy)
			opts := testOpts(sc)
			opts.PolicyCfg = policyCfg

			var stdioOut, stdioLog bytes.Buffer
			blocked := make(chan BlockedRequest, 1)
			ForwardScannedInput(
				transport.NewStdioReader(strings.NewReader(request+"\n")),
				transport.NewStdioWriter(&stdioOut),
				&stdioLog,
				config.ActionWarn,
				config.ActionBlock,
				blocked,
				nil,
				nil,
				opts,
			)
			if !strings.Contains(stdioOut.String(), request) || !strings.Contains(stdioLog.String(), "policy:Shell Profile Modification") {
				t.Fatalf("stdio output=%q log=%q, want forwarded call and named warning", stdioOut.String(), stdioLog.String())
			}
			for br := range blocked {
				t.Fatalf("warn preset unexpectedly blocked stdio request: %+v", br)
			}

			var httpLog bytes.Buffer
			if got := scanHTTPInput([]byte(request), &httpLog, "session", "session", opts); got != nil {
				t.Fatalf("warn preset unexpectedly blocked HTTP request: %+v", got)
			}
			if !strings.Contains(httpLog.String(), "policy:Shell Profile Modification") {
				t.Fatalf("HTTP log=%q, want named warning", httpLog.String())
			}
		})
	}
}
