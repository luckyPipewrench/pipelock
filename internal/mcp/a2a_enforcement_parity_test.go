// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
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
