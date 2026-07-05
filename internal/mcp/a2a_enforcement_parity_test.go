// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	testA2AMethod         = "SendMessage"
	testA2ASecondMethod   = "GetTask"
	testA2ADoWReason      = "a2a budget exceeded"
	testA2ADoWBudgetType  = "a2a_per_method"
	testA2AChainPattern   = "a2a-send-burst"
	testA2ARequestPayload = `{"message":{"parts":[{"kind":"text","text":"hello"}]}}`
)

func testA2ARequest(id int, method string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"` + method + `","params":` + testA2ARequestPayload + `}`)
}

func testA2APublishRequest(id int, method string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"` + method + `","params":{"message":{"parts":[{"kind":"text","text":"publish to https://api.service.example/updates"}]}}}`)
}

func testA2AChainMatcher() *chains.Matcher {
	return chains.New(&config.ToolChainDetection{
		Enabled:       true,
		Action:        config.ActionBlock,
		WindowSize:    20,
		WindowSeconds: 300,
		MaxGap:        intPtrInput(3),
		ToolCategories: map[string][]string{
			"network": {
				a2aBaselineIdentity(testA2AMethod),
				a2aBaselineIdentity(testA2ASecondMethod),
			},
		},
		CustomPatterns: []config.ChainPattern{{
			Name:     testA2AChainPattern,
			Sequence: []string{"network", "network"},
			Severity: config.SeverityHigh,
			Action:   config.ActionBlock,
		}},
	})
}

func TestScanHTTPInput_A2ADoWBlock(t *testing.T) {
	sc := testScannerForHTTP(t)
	var gotIdentity string
	opts := MCPProxyOpts{
		Scanner:  sc,
		InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		DoWCheck: func(identity, argsJSON string) (bool, string, string, string) {
			gotIdentity = identity
			if identity == a2aBaselineIdentity(testA2AMethod) && strings.Contains(argsJSON, `"method":"`+testA2AMethod+`"`) {
				return false, config.ActionBlock, testA2ADoWReason, testA2ADoWBudgetType
			}
			return true, "", "", ""
		},
	}

	blocked := scanHTTPInput(testA2ARequest(1, testA2AMethod), io.Discard, "a2a-session", "a2a-session", opts)
	if blocked == nil {
		t.Fatal("expected A2A DoW block")
	}
	if gotIdentity != a2aBaselineIdentity(testA2AMethod) {
		t.Fatalf("DoW identity = %q, want %q", gotIdentity, a2aBaselineIdentity(testA2AMethod))
	}
	if !strings.Contains(blocked.ErrorMessage, testA2ADoWReason) {
		t.Fatalf("ErrorMessage = %q, want DoW reason", blocked.ErrorMessage)
	}
}

func TestScanHTTPInput_A2ADoWAllowDoesNotFalseBlock(t *testing.T) {
	sc := testScannerForHTTP(t)
	var gotIdentity string
	opts := MCPProxyOpts{
		Scanner:  sc,
		InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		DoWCheck: func(identity, _ string) (bool, string, string, string) {
			gotIdentity = identity
			return true, "", "", ""
		},
	}

	blocked := scanHTTPInput(testA2ARequest(1, testA2AMethod), io.Discard, "a2a-session", "a2a-session", opts)
	if blocked != nil {
		t.Fatalf("A2A DoW allow should not block: %+v", blocked)
	}
	if gotIdentity != a2aBaselineIdentity(testA2AMethod) {
		t.Fatalf("DoW identity = %q, want %q", gotIdentity, a2aBaselineIdentity(testA2AMethod))
	}
}

func TestScanHTTPInput_A2AChainBlock(t *testing.T) {
	sc := testScannerForHTTP(t)
	var logBuf bytes.Buffer
	opts := MCPProxyOpts{
		Scanner:      sc,
		InputCfg:     &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		ChainMatcher: testA2AChainMatcher(),
	}

	first := scanHTTPInput(testA2ARequest(1, testA2AMethod), &logBuf, "a2a-session", "a2a-session", opts)
	if first != nil {
		t.Fatalf("first A2A chain element should not block: %+v", first)
	}
	second := scanHTTPInput(testA2ARequest(2, testA2ASecondMethod), &logBuf, "a2a-session", "a2a-session", opts)
	if second == nil {
		t.Fatal("expected A2A chain block on second method")
	}
	if second.ErrorCode != -32004 {
		t.Fatalf("ErrorCode = %d, want -32004", second.ErrorCode)
	}
	if !strings.Contains(logBuf.String(), testA2AChainPattern) {
		t.Fatalf("expected chain pattern in log, got: %s", logBuf.String())
	}
}

func TestScanHTTPInput_A2AChainNonMatchAllows(t *testing.T) {
	sc := testScannerForHTTP(t)
	opts := MCPProxyOpts{
		Scanner:      sc,
		InputCfg:     &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		ChainMatcher: testA2AChainMatcher(),
	}

	blocked := scanHTTPInput(testA2ARequest(1, testA2AMethod), io.Discard, "a2a-session", "a2a-session", opts)
	if blocked != nil {
		t.Fatalf("single A2A chain element should not block: %+v", blocked)
	}
}

func TestRunHTTPListenerProxy_A2ASessionBindingBlocksNoBaseline(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()

	sc := testScannerForHTTP(t)
	baseline := tools.NewToolBaseline()
	toolCfg := &tools.ToolScanConfig{
		Baseline:                baseline,
		Action:                  config.ActionBlock,
		BindingUnknownAction:    config.ActionBlock,
		BindingNoBaselineAction: config.ActionBlock,
	}
	baseURL, _, logBuf := startListenerProxy(t, upstream.URL, sc,
		&InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		toolCfg,
		nil,
	)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(string(testA2ARequest(1, testA2AMethod))))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST listener proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(response): %v", err)
	}
	if !strings.Contains(string(payload), bindingReasonNoBaseline) {
		t.Fatalf("expected A2A session binding block, got: %s", payload)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
	if !strings.Contains(logBuf.String(), a2aBaselineIdentity(testA2AMethod)) {
		t.Fatalf("expected A2A identity in binding log, got: %s", logBuf.String())
	}
}

func TestScanHTTPInput_A2ASessionBindingDoesNotUseSameNamedTool(t *testing.T) {
	sc := testScannerForHTTP(t)
	baseline := tools.NewToolBaseline()
	baseline.SetKnownTools([]string{a2aBaselineIdentity(testA2AMethod)})
	toolCfg := &tools.ToolScanConfig{
		Baseline:                baseline,
		Action:                  config.ActionBlock,
		BindingUnknownAction:    config.ActionBlock,
		BindingNoBaselineAction: config.ActionBlock,
	}
	opts := MCPProxyOpts{
		Scanner:  sc,
		InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		ToolCfg:  toolCfg,
	}

	blocked := scanHTTPInput(testA2ARequest(1, testA2AMethod), io.Discard, "a2a-session", "a2a-session", opts)
	if blocked == nil {
		t.Fatal("same-named MCP tool baseline satisfied A2A binding")
	}
	if !strings.Contains(blocked.ErrorMessage, bindingReasonUnknownTool) {
		t.Fatalf("ErrorMessage = %q, want %s", blocked.ErrorMessage, bindingReasonUnknownTool)
	}
}

func TestScanHTTPInput_A2ATaintAskDeniedWithoutApprover(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://docs.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})
	opts := MCPProxyOpts{
		Scanner:  sc,
		InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		Rec:      rec,
		TaintCfg: &cfg.Taint,
	}

	blocked := scanHTTPInput(testA2APublishRequest(1, testA2AMethod), io.Discard, "a2a-session", "a2a-session", opts)
	if blocked == nil {
		t.Fatal("expected A2A taint ask-denied block")
	}
	if !strings.Contains(blocked.ErrorMessage, "external_publish_after_untrusted_external_exposure") {
		t.Fatalf("ErrorMessage = %q, want taint reason", blocked.ErrorMessage)
	}
}

func TestEvaluateMCPInputGates_A2ATaintActionRefDoesNotCollideWithSameNamedTool(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	opts := MCPProxyOpts{
		Scanner:  sc,
		TaintCfg: &cfg.Taint,
	}
	toolMsg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + a2aBaselineIdentity(testA2AMethod) + `","arguments":{"message":{"parts":[{"kind":"text","text":"publish to https://api.service.example/updates"}]}}}}`)
	a2aMsg := testA2APublishRequest(2, testA2AMethod)

	toolEval := EvaluateMCPInputGates(context.Background(), ParseMCPFrame(toolMsg), toolMsg, "taint-session", opts, config.ActionWarn, config.ActionBlock, true)
	a2aEval := EvaluateMCPInputGates(context.Background(), ParseMCPFrame(a2aMsg), a2aMsg, "taint-session", opts, config.ActionWarn, config.ActionBlock, true)

	if toolEval.TaintDecision.ActionRef == "" || a2aEval.TaintDecision.ActionRef == "" {
		t.Fatalf("expected taint action refs, got tool=%q a2a=%q", toolEval.TaintDecision.ActionRef, a2aEval.TaintDecision.ActionRef)
	}
	if toolEval.TaintDecision.ActionRef == a2aEval.TaintDecision.ActionRef {
		t.Fatalf("same-named MCP tool and A2A method share taint action ref %q", toolEval.TaintDecision.ActionRef)
	}
	if !strings.HasPrefix(toolEval.TaintDecision.ActionRef, "mcp:tool:a2a:") {
		t.Fatalf("tool action ref = %q, want tool namespace", toolEval.TaintDecision.ActionRef)
	}
	if !strings.HasPrefix(a2aEval.TaintDecision.ActionRef, "mcp:a2a:") {
		t.Fatalf("A2A action ref = %q, want A2A namespace", a2aEval.TaintDecision.ActionRef)
	}
}

func TestScanHTTPInput_A2ADoWBlockLeavesNoChainTrace(t *testing.T) {
	sc := testScannerForHTTP(t)
	opts := MCPProxyOpts{
		Scanner:      sc,
		InputCfg:     &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
		ChainMatcher: testA2AChainMatcher(),
		DoWCheck: func(identity, _ string) (bool, string, string, string) {
			if identity == a2aBaselineIdentity(testA2AMethod) {
				return false, config.ActionBlock, testA2ADoWReason, testA2ADoWBudgetType
			}
			return true, "", "", ""
		},
	}

	first := scanHTTPInput(testA2ARequest(1, testA2AMethod), io.Discard, "a2a-session", "a2a-session", opts)
	if first == nil || !strings.Contains(first.ErrorMessage, testA2ADoWReason) {
		t.Fatalf("first A2A request should DoW-block, got: %+v", first)
	}
	second := scanHTTPInput(testA2ARequest(2, testA2ASecondMethod), io.Discard, "a2a-session", "a2a-session", opts)
	if second != nil {
		t.Fatalf("DoW-blocked A2A request left a chain trace; second block: %+v", second)
	}
}

func TestForwardScannedInput_A2ADoWBlock(t *testing.T) {
	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock}
	opts.DoWCheck = func(identity, _ string) (bool, string, string, string) {
		if identity == a2aBaselineIdentity(testA2AMethod) {
			return false, config.ActionBlock, testA2ADoWReason, testA2ADoWBudgetType
		}
		return true, "", "", ""
	}

	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(string(testA2ARequest(1, testA2AMethod))+"\n")),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)

	if strings.Contains(serverIn.String(), testA2AMethod) {
		t.Fatal("expected A2A DoW-blocked request not to be forwarded")
	}
	var gotBlock bool
	for br := range blockedCh {
		if strings.Contains(br.ErrorMessage, testA2ADoWReason) {
			gotBlock = true
		}
	}
	if !gotBlock {
		t.Fatalf("expected A2A DoW block; log=%s", logW.String())
	}
}

func TestForwardScannedInput_A2ADoWBlockLeavesNoChainTrace(t *testing.T) {
	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock}
	opts.ChainMatcher = testA2AChainMatcher()
	opts.DoWCheck = func(identity, _ string) (bool, string, string, string) {
		if identity == a2aBaselineIdentity(testA2AMethod) {
			return false, config.ActionBlock, testA2ADoWReason, testA2ADoWBudgetType
		}
		return true, "", "", ""
	}

	input := string(testA2ARequest(1, testA2AMethod)) + "\n" +
		string(testA2ARequest(2, testA2ASecondMethod)) + "\n"
	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(input)),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)

	if strings.Contains(serverIn.String(), testA2AMethod) {
		t.Fatalf("expected DoW-blocked A2A request not to forward, got: %s", serverIn.String())
	}
	if !strings.Contains(serverIn.String(), testA2ASecondMethod) {
		t.Fatalf("DoW-blocked A2A request left a chain trace; second request did not forward: %s", serverIn.String())
	}
	var gotDoWBlock bool
	for br := range blockedCh {
		if strings.Contains(br.ErrorMessage, testA2ADoWReason) {
			gotDoWBlock = true
			continue
		}
		if strings.Contains(br.ErrorMessage, testA2AChainPattern) {
			t.Fatalf("DoW-blocked A2A request left a chain trace; chain block: %+v", br)
		}
		t.Fatalf("unexpected block: %+v; log=%s", br, logW.String())
	}
	if !gotDoWBlock {
		t.Fatalf("expected A2A DoW block; log=%s", logW.String())
	}
	if !strings.Contains(logW.String(), testA2ADoWReason) {
		t.Fatalf("expected DoW reason in log, got: %s", logW.String())
	}
}

func TestForwardScannedInput_A2ADoWAllowDoesNotFalseBlock(t *testing.T) {
	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock}
	opts.DoWCheck = func(identity, _ string) (bool, string, string, string) {
		if identity != a2aBaselineIdentity(testA2AMethod) {
			t.Fatalf("DoW identity = %q, want %q", identity, a2aBaselineIdentity(testA2AMethod))
		}
		return true, "", "", ""
	}

	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	req := string(testA2ARequest(1, testA2AMethod)) + "\n"
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(req)),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)

	for br := range blockedCh {
		t.Fatalf("A2A DoW allow should not block: %+v; log=%s", br, logW.String())
	}
	if !strings.Contains(serverIn.String(), testA2AMethod) {
		t.Fatalf("expected A2A request to forward, got: %s", serverIn.String())
	}
}

func TestForwardScannedInput_A2ASessionBindingBlocksUnknownMethod(t *testing.T) {
	sc := testInputScanner(t)
	baseline := tools.NewToolBaseline()
	baseline.SetKnownTools([]string{"read_file"})
	bindingCfg := &SessionBindingConfig{
		Baseline:          baseline,
		UnknownToolAction: config.ActionBlock,
		NoBaselineAction:  config.ActionBlock,
	}

	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(string(testA2ARequest(1, testA2AMethod))+"\n")),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		bindingCfg,
		nil,
		testOpts(sc),
	)

	if strings.Contains(serverIn.String(), testA2AMethod) {
		t.Fatalf("expected A2A session-binding-blocked request not to forward, got: %s", serverIn.String())
	}
	var gotBlock bool
	for br := range blockedCh {
		if br.ErrorData != nil || br.ErrorCode != 0 {
			gotBlock = true
		}
	}
	if !gotBlock {
		t.Fatalf("expected A2A session binding block; log=%s", logW.String())
	}
	if !strings.Contains(logW.String(), a2aBaselineIdentity(testA2AMethod)) {
		t.Fatalf("expected A2A identity in binding log, got: %s", logW.String())
	}
}

func TestForwardScannedInput_A2ASessionBindingDoesNotUseSameNamedTool(t *testing.T) {
	sc := testInputScanner(t)
	baseline := tools.NewToolBaseline()
	baseline.SetKnownTools([]string{a2aBaselineIdentity(testA2AMethod)})
	bindingCfg := &SessionBindingConfig{
		Baseline:          baseline,
		UnknownToolAction: config.ActionBlock,
		NoBaselineAction:  config.ActionBlock,
	}

	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(string(testA2ARequest(1, testA2AMethod))+"\n")),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		bindingCfg,
		nil,
		testOpts(sc),
	)

	if strings.Contains(serverIn.String(), testA2AMethod) {
		t.Fatalf("same-named MCP tool baseline let A2A request forward: %s", serverIn.String())
	}
	var gotBlock bool
	var gotReason bool
	for br := range blockedCh {
		if br.ErrorData != nil || br.ErrorCode != 0 {
			gotBlock = true
		}
		if strings.Contains(br.ErrorMessage, bindingReasonUnknownTool) {
			gotReason = true
		}
	}
	if !gotBlock {
		t.Fatalf("expected A2A session binding block; log=%s", logW.String())
	}
	if !gotReason {
		t.Fatalf("expected block reason %q; log=%s", bindingReasonUnknownTool, logW.String())
	}
}

func TestForwardScannedInput_A2ATaintAskDeniedWithoutApprover(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://docs.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})
	opts := testOpts(sc)
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock}
	opts.Rec = rec
	opts.TaintCfg = &cfg.Taint

	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(string(testA2APublishRequest(1, testA2AMethod))+"\n")),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)

	if strings.Contains(serverIn.String(), testA2AMethod) {
		t.Fatalf("expected A2A taint-blocked request not to forward, got: %s", serverIn.String())
	}
	var gotBlock bool
	for br := range blockedCh {
		if strings.Contains(br.ErrorMessage, "external_publish_after_untrusted_external_exposure") {
			gotBlock = true
		}
	}
	if !gotBlock {
		t.Fatalf("expected A2A taint block; log=%s", logW.String())
	}
}

func TestForwardScannedInput_A2AChainBlock(t *testing.T) {
	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock}
	opts.ChainMatcher = testA2AChainMatcher()

	input := string(testA2ARequest(1, testA2AMethod)) + "\n" +
		string(testA2ARequest(2, testA2ASecondMethod)) + "\n"
	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(input)),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)

	var gotChainBlock bool
	for br := range blockedCh {
		if strings.Contains(br.ErrorMessage, testA2AChainPattern) {
			gotChainBlock = true
		}
	}
	if !gotChainBlock {
		t.Fatalf("expected A2A chain block; log=%s", logW.String())
	}
}

func TestForwardScannedInput_A2AChainNonMatchAllows(t *testing.T) {
	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock}
	opts.ChainMatcher = testA2AChainMatcher()

	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	req := string(testA2ARequest(1, testA2AMethod)) + "\n"
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(req)),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)

	for br := range blockedCh {
		t.Fatalf("single A2A chain element should not block: %+v; log=%s", br, logW.String())
	}
	if !strings.Contains(serverIn.String(), testA2AMethod) {
		t.Fatalf("expected single A2A request to forward, got: %s", serverIn.String())
	}
}

func TestForwardScannedInput_A2ABodyURLFieldBlocks(t *testing.T) {
	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock}
	a2aCfg := enabledA2ACfg()
	a2aCfg.Action = config.ActionBlock
	opts.A2ACfg = a2aCfg

	body := `{"jsonrpc":"2.0","id":1,"method":"` + testA2AMethod + `","params":{"message":{"parts":[{"kind":"file","url":"http://169.254.169.254/latest/meta-data/"}]}}}`
	var serverIn bytes.Buffer
	var logW bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(body+"\n")),
		transport.NewStdioWriter(&serverIn),
		&logW,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)

	if serverIn.Len() != 0 {
		t.Fatalf("expected stdio A2A body block before forward, got: %s", serverIn.String())
	}
	var gotA2ABlock bool
	for br := range blockedCh {
		if strings.Contains(br.ErrorMessage, "A2A input scanning") {
			gotA2ABlock = true
		}
	}
	if !gotA2ABlock {
		t.Fatalf("expected stdio A2A body block; log=%s", logW.String())
	}
	if !strings.Contains(logW.String(), "a2a input blocked") {
		t.Fatalf("expected A2A body gate log, got: %s", logW.String())
	}
}
