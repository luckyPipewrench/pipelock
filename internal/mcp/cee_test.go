// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCEEDepsReconfigure_SerializesPolicyAndStateSnapshots(t *testing.T) {
	strict := config.CrossRequestDetection{
		Enabled: true,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1,
			WindowMinutes: 5,
			Action:        config.ActionBlock,
		},
	}
	cee := NewCEEDeps(strict, metrics.New())
	oldTracker, _, _, oldCfg, release := cee.snapshot()
	if oldTracker == nil || oldCfg.EntropyBudget.BitsPerWindow != 1 {
		t.Fatalf("old CEE snapshot = tracker:%p cfg:%+v", oldTracker, oldCfg)
	}
	oldTracker.Record(testMCPSessionKey, []byte("abc"))
	if !oldTracker.BudgetExceeded(testMCPSessionKey) {
		t.Fatal("strict snapshot did not enforce its own budget")
	}

	permissive := strict
	permissive.EntropyBudget.BitsPerWindow = 1000
	done := make(chan struct{})
	go func() {
		cee.Reconfigure(permissive, metrics.New())
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("permissive reload acquired its write lock while an old policy snapshot was active")
	case <-time.After(100 * time.Millisecond):
	}

	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reload remained wedged after the in-flight CEE check completed")
	}

	newTracker, _, _, newCfg, newRelease := cee.snapshot()
	defer newRelease()
	if newTracker != oldTracker {
		t.Fatal("reload discarded entropy history instead of reusing the tracker")
	}
	if newCfg.EntropyBudget.BitsPerWindow != 1000 {
		t.Fatalf("new policy budget = %v, want 1000", newCfg.EntropyBudget.BitsPerWindow)
	}
	if newTracker.BudgetExceeded(testMCPSessionKey) {
		t.Fatal("new permissive snapshot retained the old strict limit")
	}
}

func TestCEEDepsReconfigure_RetiresAndRecreatesComponents(t *testing.T) {
	cfg := config.CrossRequestDetection{
		Enabled: true,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 32,
			WindowMinutes: 5,
		},
	}
	cee := NewCEEDeps(cfg, metrics.New())
	oldTracker, oldBuffer := cee.Components()
	if oldTracker == nil || oldBuffer != nil {
		t.Fatalf("initial components = tracker:%p buffer:%p", oldTracker, oldBuffer)
	}
	oldTracker.Record(testMCPSessionKey, []byte("secret state"))

	cfg.EntropyBudget.Enabled = false
	cfg.FragmentReassembly.Enabled = true
	cfg.FragmentReassembly.MaxBufferBytes = 128
	cfg.FragmentReassembly.WindowMinutes = 5
	cee.Reconfigure(cfg, metrics.New())
	tracker, oldBuffer := cee.Components()
	if tracker != nil || oldBuffer == nil {
		t.Fatalf("fragment-only components = tracker:%p buffer:%p", tracker, oldBuffer)
	}
	if got := oldTracker.CurrentUsage(testMCPSessionKey); got != 0 {
		t.Fatalf("retired tracker retained %.1f bits", got)
	}
	oldBuffer.Append(testMCPSessionKey, []byte("split-secret"))

	cfg.EntropyBudget.Enabled = true
	cfg.FragmentReassembly.Enabled = false
	cee.Reconfigure(cfg, metrics.New())
	tracker, buffer := cee.Components()
	if tracker == nil || tracker == oldTracker || buffer != nil {
		t.Fatalf("entropy-only components = tracker:%p old:%p buffer:%p", tracker, oldTracker, buffer)
	}
	if got := oldBuffer.TotalBufferBytes(); got != 0 {
		t.Fatalf("retired fragment buffer retained %d bytes", got)
	}
}

func TestCEEDepsReconfigure_PreservesHistoryAndAppliesStricterPolicy(t *testing.T) {
	cfg := config.CrossRequestDetection{
		Enabled: true,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled: true, BitsPerWindow: 1000, WindowMinutes: 5, Action: config.ActionBlock,
		},
	}
	cee := NewCEEDeps(cfg, metrics.New())
	tracker, _ := cee.Components()
	tracker.Record(testMCPSessionKey, []byte("recorded-before-reload"))

	cee.Reconfigure(cfg, metrics.New())
	unchanged, _ := cee.Components()
	if unchanged != tracker || unchanged.CurrentUsage(testMCPSessionKey) == 0 {
		t.Fatal("unrelated reload discarded the active entropy tracker or its history")
	}

	cfg.EntropyBudget.BitsPerWindow = 1
	cee.Reconfigure(cfg, metrics.New())
	strict, _ := cee.Components()
	if strict != tracker || !strict.BudgetExceeded(testMCPSessionKey) {
		t.Fatal("stricter reload did not apply to retained entropy history")
	}

	cfg.Enabled = false
	cee.Reconfigure(cfg, metrics.New())
	retired, buffer := cee.Components()
	if retired != nil || buffer != nil || tracker.CurrentUsage(testMCPSessionKey) != 0 {
		t.Fatal("disabled reload retained active or buffered CEE state")
	}
}

const (
	testMCPSessionKey = "session-001"
	testMCPAgent      = "myagent"
	testMCPSessionIP  = "10.0.0.1"

	// Fake AWS key suffix, built as constant to avoid repetition.
	// Combined with prefix at runtime to avoid gosec G101.
	testMCPAWSKeySuffix = "IOSF" + "ODNN7EXAMPLE"

	// 300 second window (5 minutes), matching entropy budget default.
	testMCPWindowSecs = 300
)

// testMCPScanner creates a Scanner with default DLP patterns and SSRF disabled.
func testMCPScanner() *scanner.Scanner {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF (no DNS in unit tests)
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	return scanner.MustNew(cfg)
}

func TestCeeSessionKeyMCP_EmptyAgent(t *testing.T) {
	got := ceeSessionKeyMCP("", testMCPSessionIP)
	if got != testMCPSessionIP {
		t.Errorf("ceeSessionKeyMCP(%q, %q) = %q, want %q", "", testMCPSessionIP, got, testMCPSessionIP)
	}
}

func TestCeeSessionKeyMCP_WithAgent(t *testing.T) {
	got := ceeSessionKeyMCP(testMCPAgent, testMCPSessionIP)
	want := testMCPAgent + "|" + testMCPSessionIP
	if got != want {
		t.Errorf("ceeSessionKeyMCP(%q, %q) = %q, want %q", testMCPAgent, testMCPSessionIP, got, want)
	}
}

func TestMCPCEEFragmentPayloads(t *testing.T) {
	tests := []struct {
		name  string
		frame MCPFrame
		want  map[string]string
	}{
		{
			name:  "tool arguments keep sibling values in separate streams",
			frame: ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"integrity_checker","arguments":{"z":["three",true],"a":{"y":"one","x":2}}}}`)),
			want: map[string]string{
				"$/a/x": "2",
				"$/a/y": "one",
				"$/z/0": "three",
				"$/z/1": "true",
			},
		},
		{
			name:  "non-tool call falls back to raw frame",
			frame: ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)),
			want:  map[string]string{"": `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		},
		{
			name: "malformed arguments fall back to raw frame",
			frame: MCPFrame{
				Raw:    []byte("raw-frame"),
				Method: methodToolsCall,
				Args:   []byte(`{"unterminated"`),
			},
			want: map[string]string{"": "raw-frame"},
		},
		{
			name: "arguments without scalar content fall back to raw frame",
			frame: MCPFrame{
				Raw:    []byte("raw-frame"),
				Method: methodToolsCall,
				Args:   []byte(`{"empty":[]}`),
			},
			want: map[string]string{"": "raw-frame"},
		},
		{
			name: "empty tool arguments fall back to raw frame",
			frame: MCPFrame{
				Raw:    []byte("raw-frame"),
				Method: methodToolsCall,
			},
			want: map[string]string{"": "raw-frame"},
		},
		{
			name: "null argument falls back to raw frame",
			frame: MCPFrame{
				Raw:    []byte("raw-frame"),
				Method: methodToolsCall,
				Args:   []byte(`null`),
			},
			want: map[string]string{"": "raw-frame"},
		},
		{
			name: "extra root value falls back to raw frame",
			frame: MCPFrame{
				Raw:    []byte("raw-frame"),
				Method: methodToolsCall,
				Args:   []byte(`"one" "two"`),
			},
			want: map[string]string{"": "raw-frame"},
		},
		{
			name: "root scalar and escaped path are retained",
			frame: MCPFrame{
				Raw:    []byte("raw-frame"),
				Method: methodToolsCall,
				Args:   []byte(`{"a/b~c":[null,"value"]}`),
			},
			want: map[string]string{"$/a~1b~0c/1": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mcpCEEFragmentPayloads(tt.frame)
			if len(got) != len(tt.want) {
				t.Fatalf("mcpCEEFragmentPayloads() = %#v, want %#v", got, tt.want)
			}
			for path, want := range tt.want {
				if value := string(got[path]); value != want {
					t.Fatalf("mcpCEEFragmentPayloads()[%q] = %q, want %q", path, value, want)
				}
			}
		})
	}
}

func TestMCPCEEFragmentPayloads_AddsToolStreamForUnambiguousValue(t *testing.T) {
	frame := ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"integrity_checker","arguments":{"rotating_name":"AKIA","empty":""}}}`))
	payloads := mcpCEEFragmentPayloads(frame)

	if got := string(payloads["$/rotating_name"]); got != "AKIA" {
		t.Fatalf("path payload = %q, want %q", got, "AKIA")
	}
	if got := string(payloads["@tool/integrity_checker"]); got != "AKIA" {
		t.Fatalf("singleton tool payload = %q, want %q", got, "AKIA")
	}
}

func TestMCPCEEFragmentPayloads_DoesNotJoinSiblingValues(t *testing.T) {
	frame := ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"integrity_checker","arguments":{"alpha":"one","beta":"two"}}}`))
	payloads := mcpCEEFragmentPayloads(frame)

	if _, ok := payloads["@tool/integrity_checker"]; ok {
		t.Fatalf("multi-value tool call unexpectedly joined sibling values: %#v", payloads)
	}
}

func TestMCPCEEUnambiguousToolValue(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		payloads  map[string][]byte
		wantOK    bool
		wantPath  string
		wantValue string
	}{
		{
			name:     "empty tool name",
			payloads: map[string][]byte{"$/alpha": []byte("value")},
		},
		{
			name:     "all values empty",
			toolName: "integrity_checker",
			payloads: map[string][]byte{"$/alpha": nil, "$/beta": {}},
		},
		{
			name:      "one non-empty value",
			toolName:  "integrity_checker",
			payloads:  map[string][]byte{"$/alpha": []byte("value"), "$/beta": nil},
			wantOK:    true,
			wantPath:  "@tool/integrity_checker",
			wantValue: "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, value, ok := mcpCEEUnambiguousToolValue(tt.toolName, tt.payloads)
			if ok != tt.wantOK || path != tt.wantPath || string(value) != tt.wantValue {
				t.Fatalf("mcpCEEUnambiguousToolValue() = (%q, %q, %t), want (%q, %q, %t)", path, value, ok, tt.wantPath, tt.wantValue, tt.wantOK)
			}
		})
	}
}

func TestMCPCEEFragmentSessionKey(t *testing.T) {
	if got := mcpCEEFragmentSessionKey("session", ""); got != "session" {
		t.Fatalf("raw fragment key = %q, want session", got)
	}
	first := mcpCEEFragmentSessionKey("session", "$/alpha")
	second := mcpCEEFragmentSessionKey("session", "$/beta")
	if first == second || !strings.HasPrefix(first, "session|mcp-arg|") {
		t.Fatalf("argument keys = %q / %q, want distinct hashed keys", first, second)
	}
	if strings.Contains(first, "alpha") || strings.Contains(second, "beta") {
		t.Fatalf("argument key exposed its plaintext path: %q / %q", first, second)
	}
}

func TestAppendMCPCEEArgumentText_RejectsMalformedNestedValues(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		useNum bool
	}{
		{
			name:   "malformed object key",
			input:  `{"`,
			useNum: true,
		},
		{
			name:   "malformed array item",
			input:  `["ok",`,
			useNum: true,
		},
		{
			name:   "number without UseNumber is an unexpected token type",
			input:  `1`,
			useNum: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := json.NewDecoder(strings.NewReader(tt.input))
			if tt.useNum {
				decoder.UseNumber()
			}
			if appendMCPCEEArgumentText(decoder, make(map[string][]byte), "$") {
				t.Fatal("appendMCPCEEArgumentText() = true, want false")
			}
		})
	}
}

func TestCeeRecordMCP_ReassemblesToolArgumentsAcrossCalls(t *testing.T) {
	cee := testMCPCEEFragmentBlock(t)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)

	first := ParseMCPFrame(mcpChunkedCEERequest(1, "AKI"+"A"))
	second := ParseMCPFrame(mcpChunkedCEERequest(2, testMCPAWSKeySuffix))
	var logBuf bytes.Buffer

	if reason := ceeRecordMCP(testMCPSessionKey, first.Raw, mcpCEEFragmentPayloads(first), cee, sc, &logBuf, nil); reason != "" {
		t.Fatalf("first fragment blocked: %s", reason)
	}
	reason := ceeRecordMCP(testMCPSessionKey, second.Raw, mcpCEEFragmentPayloads(second), cee, sc, &logBuf, nil)
	if !strings.Contains(reason, "cross-request fragment DLP match") {
		t.Fatalf("second fragment reason = %q, want fragment DLP block", reason)
	}
	if !strings.Contains(reason, "cross_request_detection.fragment_reassembly.max_buffer_bytes") {
		t.Fatalf("fragment block missing live remediation knob: %q", reason)
	}
}

func TestCeeRecordMCP_ReassemblesRotatedSingletonArgumentsAcrossCalls(t *testing.T) {
	cee := testMCPCEEFragmentBlock(t)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)

	first := ParseMCPFrame(mcpSingletonCEERequest(1, "fresh_alpha", "integrity_checker", "AKI"+"A"))
	second := ParseMCPFrame(mcpSingletonCEERequest(2, "fresh_beta", "integrity_checker", testMCPAWSKeySuffix))
	var logBuf bytes.Buffer

	if reason := ceeRecordMCP(testMCPSessionKey, first.Raw, mcpCEEFragmentPayloads(first), cee, sc, &logBuf, nil); reason != "" {
		t.Fatalf("first rotated fragment blocked: %s", reason)
	}
	reason := ceeRecordMCP(testMCPSessionKey, second.Raw, mcpCEEFragmentPayloads(second), cee, sc, &logBuf, nil)
	if !strings.Contains(reason, "cross-request fragment DLP match") {
		t.Fatalf("second rotated fragment reason = %q, want fragment DLP block", reason)
	}
}

func TestCeeRecordMCP_DoesNotJoinSingletonValuesAcrossTools(t *testing.T) {
	cee := testMCPCEEFragmentBlock(t)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)

	first := ParseMCPFrame(mcpSingletonCEERequest(1, "alpha", "first_tool", "AKI"+"A"))
	second := ParseMCPFrame(mcpSingletonCEERequest(2, "beta", "second_tool", testMCPAWSKeySuffix))
	var logBuf bytes.Buffer

	if reason := ceeRecordMCP(testMCPSessionKey, first.Raw, mcpCEEFragmentPayloads(first), cee, sc, &logBuf, nil); reason != "" {
		t.Fatalf("first tool fragment blocked: %s", reason)
	}
	if reason := ceeRecordMCP(testMCPSessionKey, second.Raw, mcpCEEFragmentPayloads(second), cee, sc, &logBuf, nil); reason != "" {
		t.Fatalf("different tool names unexpectedly joined: %s", reason)
	}
}

func TestCeeRecordMCP_EntropyUsesFragmentPayloadAndSkipsEmptyPath(t *testing.T) {
	cee := NewCEEDeps(config.CrossRequestDetection{
		Enabled: true,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1,
			WindowMinutes: testMCPWindowSecs / 60,
			Action:        config.ActionBlock,
		},
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 64,
			WindowMinutes:  testMCPWindowSecs / 60,
		},
	}, metrics.New())
	t.Cleanup(cee.Close)

	reason := ceeRecordMCP(testMCPSessionKey, nil, map[string][]byte{
		"$/empty": nil,
		"$/value": []byte("entropy"),
	}, cee, nil, &bytes.Buffer{}, nil)
	if !strings.Contains(reason, "entropy budget exceeded") {
		t.Fatalf("reason = %q, want entropy budget block", reason)
	}
}

func TestCeeRecordMCP_FragmentSkipsEmptyPayloads(t *testing.T) {
	cee := testMCPCEEFragmentBlock(t)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)

	first := []byte("AKI" + "A")
	second := []byte(testMCPAWSKeySuffix)
	var logBuf bytes.Buffer

	if reason := ceeRecordMCP(testMCPSessionKey, first, map[string][]byte{
		"$/empty":  nil,
		"$/active": first,
	}, cee, sc, &logBuf, nil); reason != "" {
		t.Fatalf("first fragment blocked: %s", reason)
	}
	if reason := ceeRecordMCP(testMCPSessionKey, second, map[string][]byte{
		"$/empty":  {},
		"$/active": second,
	}, cee, sc, &logBuf, nil); !strings.Contains(reason, "cross-request fragment DLP match") {
		t.Fatalf("second fragment reason = %q, want fragment DLP block", reason)
	}
}

func testMCPCEEFragmentBlock(t *testing.T) *CEEDeps {
	t.Helper()
	cee := NewCEEDeps(config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 64,
			WindowMinutes:  testMCPWindowSecs / 60,
		},
	}, metrics.New())
	t.Cleanup(cee.Close)
	return cee
}

func mcpChunkedCEERequest(id int, chunk string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/call","params":{"name":"integrity_checker","arguments":{"alpha":"` + chunk + `","beta":"part ` + strconv.Itoa(id) + `/120"}}}`)
}

func mcpSingletonCEERequest(id int, argumentName, toolName, chunk string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/call","params":{"name":"` + toolName + `","arguments":{"` + argumentName + `":"` + chunk + `"}}}`)
}

func TestCeeRecordMCP_NilCEE(t *testing.T) {
	reason := ceeRecordMCP(testMCPSessionKey, []byte("payload"), map[string][]byte{"": []byte("payload")}, nil, nil, &bytes.Buffer{}, nil)
	if reason != "" {
		t.Errorf("expected empty reason for nil CEE, got %q", reason)
	}
}

func TestCeeRecordMCP_EmptyPayload(t *testing.T) {
	cee := &CEEDeps{}
	reason := ceeRecordMCP(testMCPSessionKey, []byte{}, map[string][]byte{}, cee, nil, &bytes.Buffer{}, nil)
	if reason != "" {
		t.Errorf("expected empty reason for empty payload, got %q", reason)
	}

	// Also test nil payload.
	reason = ceeRecordMCP(testMCPSessionKey, nil, nil, cee, nil, &bytes.Buffer{}, nil)
	if reason != "" {
		t.Errorf("expected empty reason for nil payload, got %q", reason)
	}
}

func TestCeeRecordMCP_EntropyBudgetBlock(t *testing.T) {
	// Use a tiny budget so we exceed it immediately.
	et := scanner.NewEntropyTracker(1.0, testMCPWindowSecs)
	defer et.Close()

	m := metrics.New()
	logger, err := audit.New("json", "stdout", "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	ceeCfg := &config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: testMCPWindowSecs / 60,
			Action:        config.ActionBlock,
		},
	}
	cee := &CEEDeps{
		Tracker: et,
		Metrics: m,
		Config:  ceeCfg,
	}

	sc := testMCPScanner()
	defer sc.Close()

	var logBuf bytes.Buffer
	payload := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz")
	reason := ceeRecordMCP(testMCPSessionKey, payload, map[string][]byte{"": payload}, cee, sc, &logBuf, logger)

	if reason == "" {
		t.Fatal("expected non-empty reason for entropy budget block")
	}

	// Log output should mention CEE.
	if !bytes.Contains(logBuf.Bytes(), []byte("CEE")) {
		t.Error("expected log output to contain CEE")
	}
}

func TestCeeRecordMCP_EntropyBudgetWarn(t *testing.T) {
	// Use a tiny budget so we exceed it immediately.
	et := scanner.NewEntropyTracker(1.0, testMCPWindowSecs)
	defer et.Close()

	m := metrics.New()

	ceeCfg := &config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: testMCPWindowSecs / 60,
			Action:        config.ActionWarn,
		},
	}
	cee := &CEEDeps{
		Tracker: et,
		Metrics: m,
		Config:  ceeCfg,
	}

	var logBuf bytes.Buffer
	payload := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz")
	reason := ceeRecordMCP(testMCPSessionKey, payload, map[string][]byte{"": payload}, cee, nil, &logBuf, nil)

	// Warn mode: should NOT block (empty reason).
	if reason != "" {
		t.Errorf("expected empty reason for warn mode, got %q", reason)
	}

	// Log output should still mention CEE (warning was emitted).
	if !bytes.Contains(logBuf.Bytes(), []byte("CEE")) {
		t.Error("expected log output to contain CEE for warn mode")
	}
}

func TestCeeRecordMCP_FragmentDLPBlock(t *testing.T) {
	fb := scanner.NewFragmentBuffer(65536, 1000, testMCPWindowSecs)
	defer fb.Close()

	sc := testMCPScanner()
	defer sc.Close()

	m := metrics.New()
	logger, err := audit.New("json", "stdout", "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	ceeCfg := &config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  testMCPWindowSecs / 60,
		},
		Action: config.ActionBlock,
	}
	cee := &CEEDeps{
		Buffer:  fb,
		Metrics: m,
		Config:  ceeCfg,
	}

	// Build fake AWS key at runtime to avoid gosec G101.
	part1 := "AKI" + "A"
	part2 := testMCPAWSKeySuffix

	var logBuf bytes.Buffer

	// First fragment: not enough to trigger.
	reason := ceeRecordMCP(testMCPSessionKey, []byte(part1), map[string][]byte{"": []byte(part1)}, cee, sc, &logBuf, logger)
	if reason != "" {
		t.Fatalf("expected no block on first fragment, got %q", reason)
	}

	// Second fragment: completes the key, should block.
	reason = ceeRecordMCP(testMCPSessionKey, []byte(part2), map[string][]byte{"": []byte(part2)}, cee, sc, &logBuf, logger)
	if reason == "" {
		t.Fatal("expected non-empty reason for fragment DLP block")
	}
}

func TestCeeRecordMCP_FragmentDLPWarn(t *testing.T) {
	fb := scanner.NewFragmentBuffer(65536, 1000, testMCPWindowSecs)
	defer fb.Close()

	sc := testMCPScanner()
	defer sc.Close()

	m := metrics.New()
	logger, err := audit.New("json", "stdout", "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	ceeCfg := &config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  testMCPWindowSecs / 60,
		},
		Action: config.ActionWarn, // warn, not block
	}
	cee := &CEEDeps{
		Buffer:  fb,
		Metrics: m,
		Config:  ceeCfg,
	}

	// Build fake AWS key at runtime to avoid gosec G101.
	part1 := "AKI" + "A"
	part2 := testMCPAWSKeySuffix

	var logBuf bytes.Buffer

	// First fragment.
	reason := ceeRecordMCP("warn-session", []byte(part1), map[string][]byte{"": []byte(part1)}, cee, sc, &logBuf, logger)
	if reason != "" {
		t.Fatalf("expected no block on first fragment, got %q", reason)
	}

	// Second fragment: completes the key. Warn mode should NOT block.
	reason = ceeRecordMCP("warn-session", []byte(part2), map[string][]byte{"": []byte(part2)}, cee, sc, &logBuf, logger)
	if reason != "" {
		t.Errorf("expected empty reason for warn mode, got %q", reason)
	}

	// Log output should still mention CEE (warning emitted).
	if !bytes.Contains(logBuf.Bytes(), []byte("CEE")) {
		t.Error("expected log output to contain CEE for warn mode")
	}
}

func TestCeeRecordMCP_EntropyBudgetWarnWithLogger(t *testing.T) {
	et := scanner.NewEntropyTracker(1.0, testMCPWindowSecs)
	defer et.Close()

	m := metrics.New()
	logger, err := audit.New("json", "stdout", "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	ceeCfg := &config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: testMCPWindowSecs / 60,
			Action:        config.ActionWarn,
		},
	}
	cee := &CEEDeps{
		Tracker: et,
		Metrics: m,
		Config:  ceeCfg,
	}

	var logBuf bytes.Buffer
	payload := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz")
	reason := ceeRecordMCP(testMCPSessionKey, payload, map[string][]byte{"": payload}, cee, nil, &logBuf, logger)

	// Warn mode: should NOT block.
	if reason != "" {
		t.Errorf("expected empty reason for warn mode, got %q", reason)
	}
}
