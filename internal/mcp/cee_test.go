// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
				"@tool/integrity_checker/args$/a/x": "2",
				"@tool/integrity_checker/args$/a/y": "one",
				"@tool/integrity_checker/args$/z/0": "three",
				"@tool/integrity_checker/args$/z/1": "true",
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
				Raw:          []byte("raw-frame"),
				Method:       methodToolsCall,
				ToolCallName: "integrity_checker",
				Args:         []byte(`{"unterminated"`),
			},
			want: map[string]string{"": "raw-frame"},
		},
		{
			name: "arguments without scalar content fall back to raw frame",
			frame: MCPFrame{
				Raw:          []byte("raw-frame"),
				Method:       methodToolsCall,
				ToolCallName: "integrity_checker",
				Args:         []byte(`{"empty":[]}`),
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
				Raw:          []byte("raw-frame"),
				Method:       methodToolsCall,
				ToolCallName: "integrity_checker",
				Args:         []byte(`null`),
			},
			want: map[string]string{"": "raw-frame"},
		},
		{
			name: "extra root value falls back to raw frame",
			frame: MCPFrame{
				Raw:          []byte("raw-frame"),
				Method:       methodToolsCall,
				ToolCallName: "integrity_checker",
				Args:         []byte(`"one" "two"`),
			},
			want: map[string]string{"": "raw-frame"},
		},
		{
			name: "root scalar and escaped path are retained",
			frame: MCPFrame{
				Raw:          []byte("raw-frame"),
				Method:       methodToolsCall,
				ToolCallName: "integrity_checker",
				Args:         []byte(`{"a/b~c":[null,"value"]}`),
			},
			want: map[string]string{
				"@tool/integrity_checker/args$/a~1b~0c/1": "value",
				"@tool/integrity_checker/singleton":       "value",
			},
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

	if got := string(payloads["@tool/integrity_checker/args$/rotating_name"]); got != "AKIA" {
		t.Fatalf("path payload = %q, want %q", got, "AKIA")
	}
	if got := string(payloads["@tool/integrity_checker/singleton"]); got != "AKIA" {
		t.Fatalf("singleton tool payload = %q, want %q", got, "AKIA")
	}
}

func TestMCPCEEFragmentPayloads_DoesNotJoinSiblingValues(t *testing.T) {
	frame := ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"integrity_checker","arguments":{"alpha":"one","beta":"two"}}}`))
	payloads := mcpCEEFragmentPayloads(frame)

	if _, ok := payloads["@tool/integrity_checker/singleton"]; ok {
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
			payloads: map[string][]byte{"@tool/integrity_checker/args$/alpha": []byte("value")},
		},
		{
			name:     "all values empty",
			toolName: "integrity_checker",
			payloads: map[string][]byte{"@tool/integrity_checker/args$/alpha": nil, "@tool/integrity_checker/args$/beta": {}},
		},
		{
			name:      "one non-empty value",
			toolName:  "integrity_checker",
			payloads:  map[string][]byte{"@tool/integrity_checker/args$/alpha": []byte("value"), "@tool/integrity_checker/args$/beta": nil},
			wantOK:    true,
			wantPath:  "@tool/integrity_checker/singleton",
			wantValue: "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toolPrefix, _ := mcpCEEToolStreamPrefixFor(tt.toolName)
			path, value, ok := mcpCEEUnambiguousToolValue(toolPrefix, tt.payloads)
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
			if appendMCPCEEArgumentText(decoder, make(map[string][]byte), "@tool/integrity_checker", []byte("$"), 0) {
				t.Fatal("appendMCPCEEArgumentText() = true, want false")
			}
		})
	}
}

func TestMCPCEEFragmentPayloads_FallsBackToRawAtDepthLimit(t *testing.T) {
	depth := mcpCEEArgumentMaxDepth + 1
	frame := MCPFrame{
		Raw:          []byte("raw-depth-limit"),
		Method:       methodToolsCall,
		ToolCallName: "integrity_checker",
		Args:         []byte(strings.Repeat("[", depth) + `"value"` + strings.Repeat("]", depth)),
	}

	assertMCPCEERawFallback(t, frame)
}

func TestMCPCEEFragmentPayloads_FallsBackToRawAtPathLimit(t *testing.T) {
	frame := MCPFrame{
		Raw:          []byte("raw-path-limit"),
		Method:       methodToolsCall,
		ToolCallName: "integrity_checker",
		Args:         []byte(`{"` + strings.Repeat("x", mcpCEEArgumentMaxPathBytes) + `":"value"}`),
	}

	assertMCPCEERawFallback(t, frame)
}

func TestMCPCEEFragmentPayloads_FallsBackToRawAtStreamLimit(t *testing.T) {
	frame := MCPFrame{
		Raw:          []byte("raw-stream-limit"),
		Method:       methodToolsCall,
		ToolCallName: "integrity_checker",
		Args:         mcpCEEArgumentsWithLeaves(mcpCEEArgumentMaxStreams + 1),
	}

	assertMCPCEERawFallback(t, frame)
}

func TestMCPCEEFragmentPayloads_FallsBackToRawWhenSingletonWouldExceedStreamLimit(t *testing.T) {
	frame := MCPFrame{
		Raw:          []byte("raw-singleton-stream-limit"),
		Method:       methodToolsCall,
		ToolCallName: "integrity_checker",
		Args:         mcpCEEArgumentsWithSingleNonEmptyLeaf(mcpCEEArgumentMaxStreams),
	}

	assertMCPCEERawFallback(t, frame)
}

func TestMCPCEEFragmentPayloads_FallsBackToRawAtStreamKeyLimit(t *testing.T) {
	frame := MCPFrame{
		Raw:          []byte("raw-stream-key-limit"),
		Method:       methodToolsCall,
		ToolCallName: strings.Repeat("x", mcpCEEArgumentMaxStreamKeyBytes),
		Args:         []byte(`{"alpha":"value"}`),
	}

	assertMCPCEERawFallback(t, frame)
}

func TestMCPCEEFragmentPayloads_FallsBackToRawWithoutToolName(t *testing.T) {
	frame := MCPFrame{
		Raw:    []byte("raw-missing-tool-name"),
		Method: methodToolsCall,
		Args:   []byte(`{"alpha":"value"}`),
	}

	assertMCPCEERawFallback(t, frame)
}

func assertMCPCEERawFallback(t *testing.T, frame MCPFrame) {
	t.Helper()
	payloads := mcpCEEFragmentPayloads(frame)
	if len(payloads) != 1 || string(payloads[""]) != string(frame.Raw) {
		t.Fatalf("mcpCEEFragmentPayloads() = %#v, want complete raw frame %q", payloads, frame.Raw)
	}
}

func mcpCEEArgumentsWithLeaves(leaves int) []byte {
	var args strings.Builder
	args.WriteByte('{')
	for index := range leaves {
		if index > 0 {
			args.WriteByte(',')
		}
		args.WriteString(strconv.Quote("field_" + strconv.Itoa(index)))
		args.WriteByte(':')
		args.WriteString(strconv.Quote("value"))
	}
	args.WriteByte('}')
	return []byte(args.String())
}

func mcpCEEArgumentsWithSingleNonEmptyLeaf(leaves int) []byte {
	var args strings.Builder
	args.WriteByte('{')
	for index := range leaves {
		if index > 0 {
			args.WriteByte(',')
		}
		args.WriteString(strconv.Quote("field_" + strconv.Itoa(index)))
		args.WriteByte(':')
		if index == 0 {
			args.WriteString(strconv.Quote("value"))
		} else {
			args.WriteString(strconv.Quote(""))
		}
	}
	args.WriteByte('}')
	return []byte(args.String())
}

func TestCeeRecordMCP_ReassemblesToolArgumentsAcrossCalls(t *testing.T) {
	cee := testMCPCEEFragmentBlock(t)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)

	first := ParseMCPFrame(mcpChunkedCEERequest(1, "AKI"+"A"))
	second := ParseMCPFrame(mcpChunkedCEERequest(2, testMCPAWSKeySuffix))
	var logBuf bytes.Buffer

	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: first.Raw, frame: first, cee: cee, sc: sc, logW: &logBuf}); reason != "" {
		t.Fatalf("first fragment blocked: %s", reason)
	}
	reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: second.Raw, frame: second, cee: cee, sc: sc, logW: &logBuf})
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

	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: first.Raw, frame: first, cee: cee, sc: sc, logW: &logBuf}); reason != "" {
		t.Fatalf("first rotated fragment blocked: %s", reason)
	}
	reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: second.Raw, frame: second, cee: cee, sc: sc, logW: &logBuf})
	if !strings.Contains(reason, "cross-request fragment DLP match") {
		t.Fatalf("second rotated fragment reason = %q, want fragment DLP block", reason)
	}
}

func TestCeeRecordMCP_ReassemblesSamePathWithinTool(t *testing.T) {
	cee := testMCPCEEFragmentBlock(t)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)

	first := ParseMCPFrame(mcpSingletonCEERequest(1, "alpha", "integrity_checker", "AKI"+"A"))
	second := ParseMCPFrame(mcpSingletonCEERequest(2, "alpha", "integrity_checker", testMCPAWSKeySuffix))
	var logBuf bytes.Buffer

	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: first.Raw, frame: first, cee: cee, sc: sc, logW: &logBuf}); reason != "" {
		t.Fatalf("first same-path fragment blocked: %s", reason)
	}
	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: second.Raw, frame: second, cee: cee, sc: sc, logW: &logBuf}); !strings.Contains(reason, "cross-request fragment DLP match") {
		t.Fatalf("same-path fragments within one tool = %q, want fragment DLP block", reason)
	}
}

func TestCeeRecordMCP_DoesNotJoinSamePathValuesAcrossTools(t *testing.T) {
	cee := testMCPCEEFragmentBlock(t)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)

	first := ParseMCPFrame(mcpSingletonCEERequest(1, "alpha", "first_tool", "AKI"+"A"))
	second := ParseMCPFrame(mcpSingletonCEERequest(2, "alpha", "second_tool", testMCPAWSKeySuffix))
	var logBuf bytes.Buffer

	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: first.Raw, frame: first, cee: cee, sc: sc, logW: &logBuf}); reason != "" {
		t.Fatalf("first tool fragment blocked: %s", reason)
	}
	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: second.Raw, frame: second, cee: cee, sc: sc, logW: &logBuf}); reason != "" {
		t.Fatalf("different tool names unexpectedly joined: %s", reason)
	}
}

func TestCeeRecordMCP_HighLeafFallbackPreservesExistingFragment(t *testing.T) {
	buffer := scanner.NewFragmentBuffer(64, 3, testMCPWindowSecs)
	t.Cleanup(buffer.Close)
	cee := &CEEDeps{
		Buffer: buffer,
		Config: &config.CrossRequestDetection{
			Action: config.ActionBlock,
			FragmentReassembly: config.CrossRequestFragments{
				Enabled:        true,
				MaxBufferBytes: 64,
				WindowMinutes:  testMCPWindowSecs / 60,
			},
		},
	}
	sc := testMCPScanner()
	t.Cleanup(sc.Close)
	var logBuf bytes.Buffer

	first := ParseMCPFrame(mcpSingletonCEERequest(1, "alpha", "integrity_checker", "AKI"+"A"))
	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: first.Raw, frame: first, cee: cee, sc: sc, logW: &logBuf}); reason != "" {
		t.Fatalf("first fragment blocked: %s", reason)
	}

	highLeafArgs := mcpCEEArgumentsWithLeaves(mcpCEEArgumentMaxStreams + 1)
	highLeaf := ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"integrity_checker","arguments":` + string(highLeafArgs) + `}}`))
	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: highLeaf.Raw, frame: highLeaf, cee: cee, sc: sc, logW: &logBuf}); reason != "" {
		t.Fatalf("high-leaf frame blocked: %s", reason)
	}

	second := ParseMCPFrame(mcpSingletonCEERequest(3, "alpha", "integrity_checker", testMCPAWSKeySuffix))
	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: second.Raw, frame: second, cee: cee, sc: sc, logW: &logBuf}); !strings.Contains(reason, "cross-request fragment DLP match") {
		t.Fatalf("secret split around high-leaf frame = %q, want fragment DLP block", reason)
	}
}

func TestCeeRecordMCP_DeduplicatesEquivalentSingletonFindings(t *testing.T) {
	m := metrics.New()
	cee := NewCEEDeps(config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionWarn,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 64,
			WindowMinutes:  testMCPWindowSecs / 60,
		},
	}, m)
	t.Cleanup(cee.Close)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)
	auditPath := filepath.Join(t.TempDir(), "cee-audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	var logBuf bytes.Buffer

	first := ParseMCPFrame(mcpSingletonCEERequest(1, "alpha", "integrity_checker", "AKI"+"A"))
	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: first.Raw, frame: first, cee: cee, sc: sc, logW: &logBuf, logger: logger}); reason != "" {
		t.Fatalf("first fragment blocked in warn mode: %s", reason)
	}
	second := ParseMCPFrame(mcpSingletonCEERequest(2, "alpha", "integrity_checker", testMCPAWSKeySuffix))
	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, entropyPayload: second.Raw, frame: second, cee: cee, sc: sc, logW: &logBuf, logger: logger}); reason != "" {
		t.Fatalf("completed secret blocked in warn mode: %s", reason)
	}
	logger.Close()

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var matches float64
	for _, family := range families {
		if family.GetName() == "pipelock_cross_request_dlp_match_total" && len(family.Metric) == 1 {
			matches = family.Metric[0].GetCounter().GetValue()
		}
	}
	if matches != 1 {
		t.Fatalf("cross-request DLP match metric = %v, want 1", matches)
	}

	auditData, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if anomalies := strings.Count(string(auditData), `"scanner":"cross_request_fragment"`); anomalies != 1 {
		t.Fatalf("cross-request fragment anomaly records = %d, want 1; audit=%s", anomalies, auditData)
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

	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey,
		fragmentPayloads: map[string][]byte{
			"$/empty": nil,
			"$/value": []byte("entropy"),
		},
		cee:  cee,
		logW: &bytes.Buffer{},
	})
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

	if reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey:     testMCPSessionKey,
		entropyPayload: first,
		fragmentPayloads: map[string][]byte{
			"$/empty":  nil,
			"$/active": first,
		},
		cee: cee, sc: sc, logW: &logBuf,
	}); reason != "" {
		t.Fatalf("first fragment blocked: %s", reason)
	}
	if reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey:     testMCPSessionKey,
		entropyPayload: second,
		fragmentPayloads: map[string][]byte{
			"$/empty":  {},
			"$/active": second,
		},
		cee: cee, sc: sc, logW: &logBuf,
	}); !strings.Contains(reason, "cross-request fragment DLP match") {
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
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: []byte("payload"), fragmentPayloads: map[string][]byte{"": []byte("payload")}, logW: &bytes.Buffer{},
	})
	if reason != "" {
		t.Errorf("expected empty reason for nil CEE, got %q", reason)
	}
}

func TestCeeRecordMCP_EmptyPayload(t *testing.T) {
	cee := &CEEDeps{}
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: []byte{}, fragmentPayloads: map[string][]byte{}, cee: cee, logW: &bytes.Buffer{},
	})
	if reason != "" {
		t.Errorf("expected empty reason for empty payload, got %q", reason)
	}

	// Also test nil payload.
	reason = ceeRecordMCP(ceeRecordMCPOptions{sessionKey: testMCPSessionKey, cee: cee, logW: &bytes.Buffer{}})
	if reason != "" {
		t.Errorf("expected empty reason for nil payload, got %q", reason)
	}
}

func TestCeeRecordMCP_EmptyActivePayload(t *testing.T) {
	cee := testMCPCEEFragmentBlock(t)
	if reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey:       testMCPSessionKey,
		fragmentPayloads: map[string][]byte{},
		cee:              cee,
		logW:             &bytes.Buffer{},
	}); reason != "" {
		t.Fatalf("empty active CEE payload = %q, want no block", reason)
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
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: payload, fragmentPayloads: map[string][]byte{"": payload}, cee: cee, sc: sc, logW: &logBuf, logger: logger,
	})

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
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: payload, fragmentPayloads: map[string][]byte{"": payload}, cee: cee, logW: &logBuf,
	})

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
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: []byte(part1), fragmentPayloads: map[string][]byte{"": []byte(part1)}, cee: cee, sc: sc, logW: &logBuf, logger: logger,
	})
	if reason != "" {
		t.Fatalf("expected no block on first fragment, got %q", reason)
	}

	// Second fragment: completes the key, should block.
	reason = ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: []byte(part2), fragmentPayloads: map[string][]byte{"": []byte(part2)}, cee: cee, sc: sc, logW: &logBuf, logger: logger,
	})
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
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: "warn-session", entropyPayload: []byte(part1), fragmentPayloads: map[string][]byte{"": []byte(part1)}, cee: cee, sc: sc, logW: &logBuf, logger: logger,
	})
	if reason != "" {
		t.Fatalf("expected no block on first fragment, got %q", reason)
	}

	// Second fragment: completes the key. Warn mode should NOT block.
	reason = ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: "warn-session", entropyPayload: []byte(part2), fragmentPayloads: map[string][]byte{"": []byte(part2)}, cee: cee, sc: sc, logW: &logBuf, logger: logger,
	})
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
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: payload, fragmentPayloads: map[string][]byte{"": payload}, cee: cee, logW: &logBuf, logger: logger,
	})

	// Warn mode: should NOT block.
	if reason != "" {
		t.Errorf("expected empty reason for warn mode, got %q", reason)
	}
}
