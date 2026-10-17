// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestJSONInspectionResponseWarn(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	card := cardtest.Number()
	for _, shape := range []struct{ name, prefix, suffix string }{
		{"result", `"result":`, ``},
		{"tools-sibling", `"result":{"tools":[],"note":`, `}`},
		{"tools-error", `"result":{"tools":[]},"error":{"code":-1,"message":"failed","data":`, `}`},
		{"tools-error-fallback", `"result":{"tools":[]},"error":`, ``},
		{"tools-params", `"result":{"tools":[]},"params":`, ``},
		{"tools-extension", `"result":{"tools":[]},"extra":`, ``},
		{"extension", `"result":{},"extra":`, ``},
	} {
		for _, value := range []struct{ name, raw, action string }{
			{"exponent", `[1e10001]`, config.ActionBlock},
			{"digits", `[` + strings.Repeat("9", 4097) + `]`, config.ActionBlock},
			{"depth", strings.Repeat("[", 65) + `1` + strings.Repeat("]", 65), config.ActionBlock},
			{"empty-depth-budget", strings.Repeat("[", 64) + `[]` + strings.Repeat("]", 64), config.ActionBlock},
			{"clean", `[1,2]`, ""},
			{"informational", `[` + card[:8] + `,` + card[8:] + `]`, config.ActionWarn},
			{"ordinary-card", `["` + card + `"]`, config.ActionWarn},
		} {
			t.Run(shape.name+"/"+value.name, func(t *testing.T) {
				line := []byte(`{"jsonrpc":"2.0","id":1,` + shape.prefix + value.raw + shape.suffix + `}`)
				v := ScanResponseDispatch(line, sc, true, ResponseScanOptions{ActionOverride: config.ActionWarn})
				if value.action == config.ActionBlock {
					if v.Clean || (v.Action != config.ActionBlock && v.Error == "") {
						t.Fatalf("incomplete inspection forwarded: clean=%v action=%s error=%s", v.Clean, v.Action, v.Error)
					}
					return
				}
				if v.Error != "" || v.Clean != (value.action == "") || v.Action != value.action {
					t.Fatalf("control: clean=%v action=%s error=%s", v.Clean, v.Action, v.Error)
				}
				if value.name == "informational" && !scanner.OnlyInformational(v.DLPMatches) {
					t.Fatal("missing informational evidence")
				}
			})
		}
	}
}

func TestJSONInspectionStreamsWarn(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	card := cardtest.Number()
	for _, payload := range []struct {
		name, body string
		refuse     bool
	}{
		{"exponent", `[1e10001]`, true},
		{"digits", `[` + strings.Repeat("9", 4097) + `]`, true},
		{"depth", strings.Repeat("[", 65) + `1` + strings.Repeat("]", 65), true},
		{"clean", `[1,2]`, false},
		{"informational", `[` + card[:8] + `,` + card[8:] + `]`, false},
	} {
		for _, transport := range []string{"generic", "generic-exempt", "a2a"} {
			t.Run(transport+"/"+payload.name, func(t *testing.T) {
				stream := "data: " + payload.body + "\n\n"
				var out bytes.Buffer
				warnings := 0
				opts := GenericSSEScanOptions{ResponseScanExempt: transport == "generic-exempt", OnFinding: func(error) { warnings++ }}
				var err error
				if transport == "a2a" {
					cfg := enabledA2ACfg()
					cfg.Action = config.ActionWarn
					err = ScanA2AStreamWithOptions(t.Context(), strings.NewReader(stream), &out, nil, sc, A2AStreamOptions{Config: cfg, Warning: opts})
				} else {
					cfg := enabledSSECfg()
					cfg.Action = config.ActionWarn
					err = ScanGenericSSEStreamWithOptions(t.Context(), strings.NewReader(stream), &out, nil, sc, cfg, opts)
				}
				if payload.refuse {
					if !errors.Is(err, ErrSSEStreamScanError) || out.Len() != 0 {
						t.Fatalf("incomplete event forwarded or misclassified: err=%v bytes=%d", err, out.Len())
					}
					return
				}
				if err != nil || out.String() != stream {
					t.Fatalf("control refused: err=%v bytes=%d", err, out.Len())
				}
				if payload.name == "informational" && warnings == 0 {
					t.Fatal("missing warning record")
				}
			})
		}
	}
	// Ordinary DLP retains warn-forward semantics on generic SSE.
	stream := `data: ["` + card + `"]` + "\n\n"
	var out bytes.Buffer
	cfg := enabledSSECfg()
	cfg.Action = config.ActionWarn
	if err := ScanGenericSSEStream(t.Context(), strings.NewReader(stream), &out, nil, sc, cfg); err != nil || out.String() != stream {
		t.Fatalf("ordinary warn changed: %v", err)
	}
}

func TestJSONInspectionInputAndA2AWarn(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	for _, body := range []string{`[1e10001]`, `[` + strings.Repeat("9", 4097) + `]`, strings.Repeat("[", 65) + `1` + strings.Repeat("]", 65)} {
		line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"report","arguments":` + body + `}}`)
		v := ScanRequest(t.Context(), line, sc, config.ActionWarn, config.ActionForward)
		if v.Clean || v.Action != config.ActionBlock {
			t.Fatalf("input refusal downgraded: action=%s error=%s", v.Action, v.Error)
		}
		cfg := enabledA2ACfg()
		cfg.Action = config.ActionWarn
		for _, scan := range []func([]byte) A2AScanResult{
			func(b []byte) A2AScanResult { return ScanA2ARequestBody(t.Context(), b, sc, cfg) },
			func(b []byte) A2AScanResult { return ScanA2AResponseBody(t.Context(), b, sc, cfg) },
		} {
			v := scan([]byte(body))
			if v.Clean || v.Action != config.ActionBlock {
				t.Fatal("A2A refusal downgraded")
			}
		}
	}
	// A serialized document in a text leaf must retain its independent budget.
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]string{"note": "[1e10001]"}})
	if v := ScanResponse(raw, sc); v.Clean || v.Action != config.ActionBlock {
		t.Fatalf("serialized refusal downgraded: %s", v.Action)
	}
}

func TestJSONInspectionMixedVerdict(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	limit := sc.ScanJSONCardRuns(t.Context(), `[1e10001]`)
	injection := []scanner.ResponseMatch{{PatternName: "ordinary injection"}}
	if responseFindingAction(sc, ResponseScanOptions{}, injection, limit) != config.ActionBlock {
		t.Fatal("mixed response refusal downgraded")
	}
	if mcpContentActionIgnoringCoreFloor(config.ActionWarn, limit, injection) != config.ActionBlock {
		t.Fatal("mixed input refusal downgraded")
	}
	// Suppressions select pattern findings, not incomplete inspection.
	result, dropped := keepUnsuppressedDLP(scanner.TextDLPResult{Matches: limit}, "https://api.vendor.example", []config.SuppressEntry{{Rule: scanner.UninspectableJSONNumberPattern}})
	if result.Clean || !scanner.HasInspectionLimit(result.Matches) || len(dropped) != 0 {
		t.Fatal("suppression removed inspection refusal")
	}
}

func TestJSONInspectionRuntimeWarn(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	card := cardtest.Number()
	for _, tt := range []struct {
		name, payload string
		refuse        bool
	}{
		{"limit", `[1e10001]`, true},
		{"clean", `[1,2]`, false},
		{"informational", `[` + card[:8] + `,` + card[8:] + `]`, false},
		{"ordinary", `["` + card + `"]`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			line := `{"jsonrpc":"2.0","id":1,"result":{"structuredContent":` + tt.payload + `}}` + "\n"
			var out, record bytes.Buffer
			_, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(line)), transport.NewStdioWriter(&out), &record, nil, MCPProxyOpts{Scanner: sc, ResponseActionOverride: config.ActionWarn})
			if err != nil {
				t.Fatal(err)
			}
			if tt.refuse {
				if !strings.Contains(out.String(), `"error"`) || strings.Contains(out.String(), "1e10001") {
					t.Fatal("stdio forwarded incomplete response")
				}
			} else if out.String() != line {
				t.Fatal("stdio warn control changed")
			}
			request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"report","arguments":` + tt.payload + `}}`)
			result := scanHTTPInputDecision(request, &record, "inspection-session", "inspection-session", MCPProxyOpts{Scanner: sc, InputCfg: newHTTPInputCfg(config.ActionWarn)})
			if (result.Blocked != nil) != tt.refuse {
				t.Fatalf("MCP HTTP blocked=%v want=%v", result.Blocked != nil, tt.refuse)
			}
		})
	}
}

func TestJSONInspectionRawHelperMetadata(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	for _, line := range []string{`{`, `{"jsonrpc":"2.0","id":1,"method":"report"}`} {
		if matches := responseJSONCardMatches(sc, []byte(line)); len(matches) != 0 {
			t.Fatal("routing metadata became payload evidence")
		}
	}
}

func TestJSONInspectionResponseScalar(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	for _, tt := range []struct{ body, action string }{
		{`1e10001`, ""}, {cardtest.Number() + `e10001`, config.ActionWarn},
	} {
		v := ScanResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":`+tt.body+`}`), sc)
		if v.Error != "" || v.Action != tt.action || v.Clean != (tt.action == "") {
			t.Fatalf("scalar changed: clean=%v action=%s error=%s", v.Clean, v.Action, v.Error)
		}
	}
}

func TestJSONInspectionMCPFragmentsWarn(t *testing.T) {
	cfg := config.Defaults().CrossRequestDetection
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	cfg.FragmentReassembly.Enabled = true
	cfg.FragmentReassembly.MaxBufferBytes = 65536
	cfg.FragmentReassembly.WindowMinutes = 5
	deps := NewCEEDeps(cfg, nil)
	t.Cleanup(deps.Close)
	sc := testScannerWithAction(t, config.ActionWarn)
	var record bytes.Buffer
	first := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: "inspection", fragmentPayloads: map[string][]byte{"raw": []byte(`[1e`)}, cee: deps, sc: sc, logW: &record})
	if first != "" {
		t.Fatal("first fragment refused")
	}
	second := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: "inspection", fragmentPayloads: map[string][]byte{"raw": []byte(`10001]`)}, cee: deps, sc: sc, logW: &record})
	if second == "" {
		t.Fatal("MCP fragment inspection refusal downgraded")
	}
}

func TestJSONInspectionMCPFragmentDuplicateWarn(t *testing.T) {
	cfg := config.Defaults().CrossRequestDetection
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	cfg.FragmentReassembly.Enabled = true
	cfg.FragmentReassembly.MaxBufferBytes = 65536
	cfg.FragmentReassembly.WindowMinutes = 5
	cfg.EntropyBudget.Enabled = false
	deps := NewCEEDeps(cfg, nil)
	t.Cleanup(deps.Close)
	sc := testScannerWithAction(t, config.ActionWarn)
	paths := []string{"report" + mcpCEEArgumentStreamSuffix + "$.value", "report" + mcpCEESingletonStreamSuffix}
	if paths[0] > paths[1] {
		paths[0], paths[1] = paths[1], paths[0]
	}
	card := cardtest.Number()
	prefixes := map[string][]byte{paths[0]: []byte(`{"n":1,"s":"` + card[:8]), paths[1]: []byte(`{"n":1e10001,"s":"` + card[:8])}
	ending := []byte(card[8:] + `"}`)
	probe := sc.ScanTextForDLP(t.Context(), string(prefixes[paths[1]])+string(ending))
	if !scanner.HasInspectionLimit(probe.Matches) || len(probe.Matches) < 2 || probe.Matches[0].IsInspectionLimit() {
		t.Fatal("mixed-finding fixture did not exercise ordinary-first ordering")
	}
	var record bytes.Buffer
	if reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: "inspection", fragmentPayloads: prefixes, cee: deps, sc: sc, logW: &record}); reason != "" {
		t.Fatal("partial fragments refused")
	}
	matched := ""
	reason := ceeRecordMCP(ceeRecordMCPOptions{sessionKey: "inspection", fragmentPayloads: map[string][]byte{paths[0]: ending, paths[1]: ending}, cee: deps, sc: sc, logW: &record, matchedPattern: &matched})
	if reason == "" || matched != scanner.UninspectableJSONNumberPattern {
		t.Fatalf("duplicate filtering lost refusal: blocked=%v pattern=%s", reason != "", matched)
	}
}
