// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

const uninspectablePatchTargetsReason = "uninspectable_patch_targets"

// toolPolicyCaptureObserver collects records in a slice rather than a channel.
// A fixed-capacity channel makes this test's outcome depend on how many records
// the producers emit: one emission short and the receive blocks, one too many and
// the send blocks, and either way the test hangs instead of failing.
type toolPolicyCaptureObserver struct {
	capture.NopObserver
	mu      sync.Mutex
	records []capture.ToolPolicyRecord
}

func (o *toolPolicyCaptureObserver) ObserveToolPolicyVerdict(_ context.Context, record *capture.ToolPolicyRecord) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.records = append(o.records, *record)
}

func (o *toolPolicyCaptureObserver) snapshot() []capture.ToolPolicyRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]capture.ToolPolicyRecord(nil), o.records...)
}

func TestEquivalentOperationPolicyTransportGateParity(t *testing.T) {
	sc := testInputScanner(t)
	policyCfg := policy.New(config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionWarn,
		Rules:   policy.DefaultToolPolicyRules(),
	})
	for _, tc := range []struct {
		name     string
		msg      string
		wantRule string
	}{
		{name: "move", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"move_file","arguments":{"source":"/tmp/staged","destination":"/home/user/.bashrc"}}}`, wantRule: "Shell Profile Modification"},
		{name: "namespaced move", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mcp__filesystem__move_file","arguments":{"source":"/tmp/staged","destination":"/home/user/.bashrc"}}}`, wantRule: "Shell Profile Modification"},
		{name: "dotted move", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.move_file","arguments":{"source":"/tmp/staged","destination":"/home/user/.bashrc"}}}`, wantRule: "Shell Profile Modification"},
		{name: "colon move", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem:move_file","arguments":{"source":"/tmp/staged","destination":"/home/user/.bashrc"}}}`, wantRule: "Shell Profile Modification"},
		{name: "content mutation", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"apply_patch","arguments":{"patch":"--- a/.bashrc\n+++ b/.bashrc\n@@ -1 +1 @@\n-old\n+new\n"}}}`, wantRule: "Shell Profile Modification"},
		{name: "credential read", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/home/user/.ssh/id_rsa"}}}`, wantRule: "Credential File Access"},
		{name: "delete", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/home/user/.bashrc"}}}`, wantRule: "Protected Path Delete"},
		{name: "metadata", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chmod_file","arguments":{"path":"/home/user/.bashrc","mode":"0600"}}}`, wantRule: "Protected Path Metadata Change"},
		{name: "link", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_symlink","arguments":{"target":"/home/user/.bashrc","linkPath":"/tmp/profile"}}}`, wantRule: "Protected Path Link Creation"},
		{name: "uninspectable patch", msg: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"apply_patch","arguments":{"patch":"diff --git a/file"}}}`, wantRule: uninspectablePatchTargetsReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte(tc.msg)
			frame := ParseMCPFrame(msg)
			opts := testOpts(sc)
			opts.PolicyCfg = policyCfg

			httpEval := EvaluateMCPInputGates(context.Background(), frame, msg, "session", opts, config.ActionWarn, config.ActionBlock, true)
			stdioEval := EvaluateMCPInputGatesStdio(context.Background(), frame, msg, msg, nil, opts, config.ActionWarn, config.ActionBlock)
			for name, verdict := range map[string]policy.Verdict{
				"HTTP":  httpEval.PolicyVerdict,
				"stdio": stdioEval.PolicyVerdict,
			} {
				if !verdict.Matched || verdict.Action != config.ActionBlock || !slices.Contains(verdict.Rules, tc.wantRule) {
					t.Fatalf("%s policy verdict = %+v, want %s block", name, verdict, tc.wantRule)
				}
			}
		})
	}
}

func TestUninspectablePatchReasonReachesTransportEvidence(t *testing.T) {
	sc := testInputScanner(t)
	policyCfg := policy.New(config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionWarn,
		Rules:   policy.DefaultToolPolicyRules(),
	})
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"apply_patch","arguments":{"patch":"diff --git a/file"}}}`
	observer := &toolPolicyCaptureObserver{}

	httpOpts := testOpts(sc)
	httpOpts.PolicyCfg = policyCfg
	httpOpts.CaptureObs = observer
	httpOpts.Transport = transportMCPHTTP
	var httpLog bytes.Buffer
	if decision := scanHTTPInputDecision([]byte(request), &httpLog, "session", "session", httpOpts); decision.Blocked == nil {
		t.Fatal("HTTP request was not blocked")
	}
	assertUninspectablePatchLog(t, "HTTP", httpLog.String())

	stdioOpts := testOpts(sc)
	stdioOpts.PolicyCfg = policyCfg
	stdioOpts.CaptureObs = observer
	stdioOpts.Transport = transportMCPStdio
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
		stdioOpts,
	)
	if len(blocked) != 1 || stdioOut.Len() != 0 {
		t.Fatalf("stdio blocked=%d output=%q, want one block and no forwarded request", len(blocked), stdioOut.String())
	}
	assertUninspectablePatchLog(t, "stdio", stdioLog.String())

	records := observer.snapshot()
	if len(records) != 2 {
		t.Fatalf("captured %d tool policy records, want one per transport", len(records))
	}
	for _, record := range records {
		if len(record.RawFindings) != 1 || record.RawFindings[0].PolicyRule != uninspectablePatchTargetsReason {
			t.Fatalf("capture findings = %+v, want only %q", record.RawFindings, uninspectablePatchTargetsReason)
		}
	}

	verdict := policyCfg.CheckRequest([]byte(request))
	layer, pattern, _ := pickAttribution(MCPInputEvaluation{PolicyVerdict: verdict})
	if layer != mcpReceiptLayerPolicy || pattern != uninspectablePatchTargetsReason {
		t.Fatalf("receipt attribution = (%q, %q), want (%q, %q)", layer, pattern, mcpReceiptLayerPolicy, uninspectablePatchTargetsReason)
	}
}

func assertUninspectablePatchLog(t *testing.T, transportName, log string) {
	t.Helper()
	if !strings.Contains(log, "policy:"+uninspectablePatchTargetsReason) {
		t.Fatalf("%s log=%q, want dedicated patch inspection reason", transportName, log)
	}
	for _, falseReason := range []string{"policy:Persistence Path Write", "policy:Shell Profile Modification"} {
		if strings.Contains(log, falseReason) {
			t.Fatalf("%s log=%q, contains false reason %q", transportName, log, falseReason)
		}
	}
}

func TestEquivalentOperationWarnPresetsExposeRuleOnBothMCPTransports(t *testing.T) {
	sc := testInputScanner(t)
	requestTemplate := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"move_file","arguments":{"source":"/tmp/staged","destination":"/home/user/.bashrc"}}}`

	for _, toolName := range []string{"move_file", "mcp__filesystem__move_file", "filesystem.move_file", "filesystem:move_file"} {
		request := strings.Replace(requestTemplate, "move_file", toolName, 1)
		for _, preset := range []string{"audit", "generic-agent"} {
			t.Run(preset+"/"+toolName, func(t *testing.T) {
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
}
