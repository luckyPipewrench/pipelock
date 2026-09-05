// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestA2AScanVerdictPreservesScanError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result := ScanA2AResponseBody(ctx, []byte(`{"message":{"parts":[{"text":"ordinary response"}]}}`), testA2AScanner(t), enabledA2ACfg())
	verdict := a2aScanToVerdict([]byte(`1`), result)
	if verdict.Clean || verdict.Action != config.ActionBlock || !strings.Contains(verdict.Error, "response scan failed") || len(verdict.Matches) != 0 || string(verdict.ID) != "1" {
		t.Fatalf("incomplete A2A scan verdict = %+v", verdict)
	}
}

func TestAlternateResponsePathsPreserveScanError(t *testing.T) {
	for _, path := range []string{"agent-card", "tools-list-sibling"} {
		for _, cancelled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancelled=%v", path, cancelled), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if cancelled {
					cancel()
				}
				sc := testA2AScanner(t)
				var verdict jsonrpc.ScanVerdict
				if path == "agent-card" {
					cfg := enabledA2ACfg()
					cfg.Action = config.ActionWarn
					result := ScanAgentCard(ctx, []byte(`{"name":"ordinary","skills":[],"supportedInterfaces":[]}`), sc, nil, cardCacheKey{}, cfg)
					verdict = agentCardToVerdict([]byte(`7`), result, cfg)
				} else {
					verdict = scanToolsListNonToolFieldsContext(ctx, []byte(`{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"echo","description":"ordinary"}],"note":"ordinary response"}}`), sc, ResponseScanOptions{ActionOverride: config.ActionWarn})
				}
				if string(verdict.ID) != "7" || len(verdict.Matches) != 0 || len(verdict.DLPMatches) != 0 {
					t.Fatalf("unexpected response evidence: %+v", verdict)
				}
				if !cancelled {
					if !verdict.Clean || verdict.Error != "" {
						t.Fatalf("ordinary response refused: %+v", verdict)
					}
					return
				}
				if verdict.Clean || verdict.Action != config.ActionBlock || !strings.Contains(verdict.Error, "response scan failed") {
					t.Fatalf("incomplete response scan lost its error: %+v", verdict)
				}
				var output bytes.Buffer
				if err := writeTextVerdict(&output, verdict); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), "[ERROR]") || strings.Contains(output.String(), "INJECTION") {
					t.Fatalf("incorrect error classification: %s", output.String())
				}
			})
		}
	}
}

func TestScanA2AResponseBody_CanceledResponseScanIsNotInjection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := ScanA2AResponseBody(ctx, []byte(`{"message":{"parts":[{"text":"ordinary response"}]}}`), testA2AScanner(t), enabledA2ACfg())
	if result.Clean {
		t.Fatal("canceled response scan must fail closed")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("Action = %q, want %q", result.Action, config.ActionBlock)
	}
	if !strings.Contains(result.Reason, "response scan incomplete") {
		t.Fatalf("Reason = %q, want response scan error", result.Reason)
	}
	if len(result.InjectFindings) != 0 {
		t.Fatalf("InjectFindings = %v, want no injection findings", result.InjectFindings)
	}
}

func TestScanRequest_CanceledResponseScanReturnsErrorWithoutInjection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	verdict := ScanRequest(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`), testA2AScanner(t), config.ActionBlock, config.ActionBlock)
	if verdict.Clean {
		t.Fatal("canceled response scan must fail closed")
	}
	if verdict.Action != config.ActionBlock {
		t.Fatalf("Action = %q, want %q", verdict.Action, config.ActionBlock)
	}
	if !strings.Contains(verdict.Error, "response scan incomplete") {
		t.Fatalf("Error = %q, want response scan error", verdict.Error)
	}
	if len(verdict.Inject) != 0 {
		t.Fatalf("Inject = %v, want no injection findings", verdict.Inject)
	}
}

// cancelOnErrorCheck schedules ordinary cancellation at successive scanner
// checkpoints, including individual-string rescans after the joined scan.
type cancelOnErrorCheck struct {
	context.Context
	cancel context.CancelFunc
	checks atomic.Int32
	after  int32
}

func (c *cancelOnErrorCheck) Err() error {
	if c.checks.Add(1) == c.after {
		c.cancel()
	}
	return c.Context.Err()
}

func TestScanRequestCancellationAtSuccessiveScanCheckpoints(t *testing.T) {
	sc := testA2AScanner(t)
	for _, input := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{"a":"ordinary","b":"content"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"a":"ordinary","b":"content"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"a":"ordinary","b":"content"}}`,
	} {
		cancelledCheckpoints := 0
		for checkpoint := int32(1); checkpoint <= 32; checkpoint++ {
			t.Run(fmt.Sprintf("%s/checkpoint-%d", input, checkpoint), func(t *testing.T) {
				base, cancel := context.WithCancel(t.Context())
				defer cancel()
				ctx := &cancelOnErrorCheck{Context: base, cancel: cancel, after: checkpoint}
				verdict := ScanRequest(ctx, []byte(input), sc, config.ActionWarn, config.ActionWarn)
				if base.Err() == nil {
					return // This input completed before the selected checkpoint.
				}
				cancelledCheckpoints++
				if verdict.Clean || verdict.Action != config.ActionBlock || verdict.Error == "" || len(verdict.Inject) != 0 {
					t.Fatalf("cancelled scan returned %+v", verdict)
				}
			})
		}
		if cancelledCheckpoints == 0 {
			t.Fatalf("request %s exposed no reachable cancellation checkpoint", input)
		}
	}
}

func TestMCPListenerHeaderCanceledResponseScanIsParseError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	headers := make(http.Header)
	headers.Set("Mcp-Param-Mode", "ordinary")

	result := scanMCPListenerHeadersForDLP(ctx, headers, testA2AScanner(t), nil)
	if result == nil {
		t.Fatal("canceled response scan must fail closed")
	}
	if result.reason != blockreason.ParseError {
		t.Fatalf("reason = %q, want %q", result.reason, blockreason.ParseError)
	}
	if len(result.matches) != 0 {
		t.Fatalf("matches = %v, want no injection or DLP matches", result.matches)
	}
}

func TestA2ABodyCancellationAtSuccessiveScanCheckpoints(t *testing.T) {
	sc := testA2AScanner(t)
	cancelledCheckpoints := 0
	for checkpoint := int32(1); checkpoint <= 64; checkpoint++ {
		t.Run(fmt.Sprint(checkpoint), func(t *testing.T) {
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := &cancelOnErrorCheck{Context: base, cancel: cancel, after: checkpoint}
			result := ScanA2AResponseBody(ctx, []byte(`{"message":{"parts":[{"text":"ordinary response"},{"text":"another response"}]}}`), sc, enabledA2ACfg())
			if base.Err() == nil {
				return
			}
			cancelledCheckpoints++
			if result.Clean || result.Action != config.ActionBlock || result.ScanError == "" || len(result.InjectFindings) != 0 {
				t.Fatalf("cancelled A2A body returned %+v", result)
			}
		})
	}
	if cancelledCheckpoints == 0 {
		t.Fatal("A2A body exposed no reachable cancellation checkpoint")
	}
}

func TestResponseStreamCancellationAtSuccessiveScanCheckpoints(t *testing.T) {
	sc := testA2AScanner(t)
	for _, kind := range []string{"generic", "a2a"} {
		const maxCheckpoint = 64
		cancelledCheckpoints := 0
		ended := false
		for checkpoint := int32(1); checkpoint <= maxCheckpoint; checkpoint++ {
			reached := false
			t.Run(fmt.Sprintf("%s/%d", kind, checkpoint), func(t *testing.T) {
				base, cancel := context.WithCancel(t.Context())
				defer cancel()
				ctx := &cancelOnErrorCheck{Context: base, cancel: cancel, after: checkpoint}
				body := "data: {\"text\":\"ordinary response\"}\n\ndata: {\"text\":\"another response\"}\n\n"
				var out bytes.Buffer
				var err error
				if kind == "generic" {
					err = ScanGenericSSEStream(ctx, strings.NewReader(body), &out, nil, sc, enabledSSECfg())
				} else {
					err = ScanA2AStream(ctx, strings.NewReader(body), &out, nil, sc, enabledA2ACfg())
				}
				if base.Err() == nil {
					t.Skipf("checkpoint %d not reached; finite stream scan completed", checkpoint)
				}
				cancelledCheckpoints++
				if err == nil {
					t.Fatal("cancelled response scan returned nil error")
				}
				if errors.Is(err, context.Canceled) {
					// Cancellation before an event scan reaches the stream loop is
					// returned directly. It is still an incomplete scan, never a
					// finding.
					reached = true
					return
				}
				if !errors.Is(err, ErrSSEStreamScanError) {
					t.Fatalf("cancelled response scan error = %v, want ErrSSEStreamScanError", err)
				}
				if errors.Is(err, ErrSSEStreamFinding) || strings.Contains(err.Error(), "injection") {
					t.Fatalf("cancellation classified as injection: %v", err)
				}
				reached = true
			})
			if !reached {
				ended = true
				break
			}
		}
		if cancelledCheckpoints == 0 {
			t.Fatalf("%s stream exposed no reachable cancellation checkpoint", kind)
		}
		if !ended && cancelledCheckpoints == maxCheckpoint {
			t.Fatalf("%s stream exceeded bounded checkpoint guard of %d", kind, maxCheckpoint)
		}
	}
}

func TestContextTrackerCancelledScanIsIncomplete(t *testing.T) {
	cfg := enabledA2ACfg()
	cfg.SessionSmugglingDetection = true
	tracker := NewContextTracker(cfg)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	blocked, reason := tracker.TrackAndScan(ctx, "fixture-context", "fixture-task", []string{"ordinary response"}, testA2AScanner(t))
	if !blocked || !strings.Contains(reason, "response scan incomplete") || strings.Contains(reason, "injection") {
		t.Fatalf("cancelled context result = %v, %q", blocked, reason)
	}
}

func TestRawForwardCancellationAtSuccessiveScanCheckpoints(t *testing.T) {
	sc := testA2AScanner(t)
	cancelledCheckpoints := 0
	for checkpoint := int32(1); checkpoint <= 48; checkpoint++ {
		t.Run(fmt.Sprint(checkpoint), func(t *testing.T) {
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := &cancelOnErrorCheck{Context: base, cancel: cancel, after: checkpoint}
			verdict := scanRawBeforeForward(ctx, []byte(`{"id":1,"a":"ordinary","b":"\u0063ontent"}`), sc, config.ActionWarn)
			if base.Err() == nil {
				return
			}
			cancelledCheckpoints++
			if verdict.Clean || verdict.Action != config.ActionBlock || verdict.Error == "" || len(verdict.Inject) != 0 {
				t.Fatalf("cancelled raw scan returned %+v", verdict)
			}
		})
	}
	if cancelledCheckpoints == 0 {
		t.Fatal("raw forward exposed no reachable cancellation checkpoint")
	}
}

func TestScanGenericSSEStream_CanceledDuringResponseScanIsNotInjection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterRead{payload: []byte("data: ordinary response\n\n"), cancel: cancel}
	var out bytes.Buffer

	err := ScanGenericSSEStream(ctx, reader, &out, nil, testA2AScanner(t), enabledSSECfg())
	if !errors.Is(err, ErrSSEStreamScanError) {
		t.Fatalf("error = %v, want ErrSSEStreamScanError", err)
	}
	if errors.Is(err, ErrSSEStreamFinding) {
		t.Fatalf("error = %v, must not be an SSE finding", err)
	}
	if !strings.Contains(err.Error(), "response scan incomplete") {
		t.Fatalf("error = %q, want response scan error", err)
	}
	if strings.Contains(err.Error(), "injection") {
		t.Fatalf("error = %q, must not classify cancellation as injection", err)
	}
	if out.Len() != 0 {
		t.Fatalf("forwarded %q after incomplete scan", out.String())
	}
}

func TestScanA2AStream_CanceledDuringResponseScanIsNotFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterRead{payload: []byte("data: {\"message\":{\"parts\":[{\"text\":\"ordinary response\"}]}}\n\n"), cancel: cancel}
	var out bytes.Buffer

	err := ScanA2AStream(ctx, reader, &out, nil, testA2AScanner(t), enabledA2ACfg())
	if !errors.Is(err, ErrSSEStreamScanError) {
		t.Fatalf("error = %v, want ErrSSEStreamScanError", err)
	}
	if errors.Is(err, ErrA2AStreamFinding) {
		t.Fatalf("error = %v, must not be an A2A finding", err)
	}
	if strings.Contains(err.Error(), "injection") {
		t.Fatalf("error = %q, must not classify cancellation as injection", err)
	}
	if out.Len() != 0 {
		t.Fatalf("forwarded %q after incomplete scan", out.String())
	}
}

type cancelAfterRead struct {
	payload []byte
	cancel  context.CancelFunc
	done    bool
}

func (r *cancelAfterRead) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(p, r.payload)
	r.cancel()
	return n, io.EOF
}

func TestBatchPreservesScanErrorBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	failed := a2aScanToVerdict([]byte(`2`), ScanA2AResponseBody(ctx, []byte(`{"message":{"parts":[{"text":"ordinary response"}]}}`), testA2AScanner(t), enabledA2ACfg()))
	if failed.Action != config.ActionBlock || failed.Error == "" {
		t.Fatalf("producer failed to report scan error: %+v", failed)
	}
	for _, input := range []string{
		`[{"jsonrpc":"2.0","id":1,"result":"ordinary"},{"jsonrpc":"2.0","id":2,"result":"ordinary"}]`,
		`[{"jsonrpc":"2.0","id":2,"result":"ordinary"},{"jsonrpc":"2.0","id":1,"result":"ordinary"}]`,
		`[{"id":3},{"jsonrpc":"2.0","id":2,"result":"ordinary"}]`,
		`[[{"jsonrpc":"2.0","id":2,"result":"ordinary"}],{"jsonrpc":"2.0","id":1,"result":"ordinary"}]`,
	} {
		t.Run(input, func(t *testing.T) {
			var batch []json.RawMessage
			if err := json.Unmarshal([]byte(input), &batch); err != nil {
				t.Fatal(err)
			}
			var scan func([]byte) jsonrpc.ScanVerdict
			scan = func(elem []byte) jsonrpc.ScanVerdict {
				if len(elem) > 0 && elem[0] == '[' {
					var nested []json.RawMessage
					if err := json.Unmarshal(elem, &nested); err != nil {
						t.Fatal(err)
					}
					verdict, _ := scanBatchElements(nested, scan)
					return verdict
				}
				var rpc jsonrpc.RPCResponse
				if err := json.Unmarshal(elem, &rpc); err != nil {
					t.Fatal(err)
				}
				if string(rpc.ID) == "2" {
					return failed
				}
				return ScanResponse(elem, testA2AScanner(t))
			}
			verdict, finding := scanBatchElements(batch, scan)
			if verdict.Clean || verdict.Action != config.ActionBlock || verdict.Error == "" || len(verdict.Matches) != 0 || len(verdict.DLPMatches) != 0 || finding {
				t.Fatalf("batch scan failure = %+v, finding=%v", verdict, finding)
			}
		})
	}
}

func TestForwardScannedPreservesRequestCancellation(t *testing.T) {
	for _, toolsEnabled := range []bool{false, true} {
		for _, cancelled := range []bool{false, true} {
			t.Run(fmt.Sprintf("tools=%t/cancelled=%t", toolsEnabled, cancelled), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if cancelled {
					cancel()
				}
				opts := MCPProxyOpts{Scanner: testScannerWithAction(t, config.ActionWarn), WarnContext: ctx}
				line := `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ordinary response"}]}}`
				if toolsEnabled {
					opts.ToolCfg = &tools.ToolScanConfig{Action: config.ActionWarn, Baseline: tools.NewToolBaseline()}
					line = `{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"lookup","description":"Look up a record."}],"note":"ordinary response"}}`
				}
				emitter, recorder, dir, _ := newReceiptTestHarness(t)
				opts.ReceiptEmitter = emitter
				tracker := NewRequestTracker()
				actionID := receipt.NewActionID()
				tracker.TrackOutcome([]byte(`7`), TrackedRequestOutcome{Receipt: receipt.EmitOpts{ActionID: actionID, Transport: transportMCPStdio, Target: "lookup", MCPMethod: methodToolsCall, ToolName: "lookup"}})
				var out, log strings.Builder
				found, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(line+"\n")), transport.NewStdioWriter(&out), &log, tracker, opts)
				if err != nil {
					t.Fatal(err)
				}
				if cancelled {
					var response jsonrpc.RPCResponse
					if err := json.Unmarshal([]byte(out.String()), &response); err != nil {
						t.Fatal(err)
					}
					if len(response.Error) == 0 || string(response.ID) != "7" || strings.Contains(out.String(), "ordinary response") || found || strings.Contains(log.String(), "injection") || !strings.Contains(log.String(), "response scan failed") {
						t.Fatalf("cancelled forwarding: found=%t output=%s log=%s", found, out.String(), log.String())
					}
				} else if strings.TrimSpace(out.String()) != line {
					t.Fatalf("clean response changed: output=%s log=%s", out.String(), log.String())
				}
				if err := recorder.Close(); err != nil {
					t.Fatal(err)
				}
				records := readActionReceipts(t, dir)
				wantReason := "reason=complete"
				wantStatus := "status=result"
				if cancelled {
					wantReason = "reason=response_scan_error"
					wantStatus = "status=error"
				}
				if len(records) != 1 || records[0].ActionRecord.ActionID != actionID || !strings.Contains(records[0].ActionRecord.Pattern, wantReason) || !strings.Contains(records[0].ActionRecord.Pattern, wantStatus) {
					t.Fatalf("incorrect tracked outcome: %+v", records)
				}
				if toolsEnabled && opts.ToolCfg.Baseline.HasBaseline() == cancelled {
					t.Fatalf("tool baseline committed=%t after cancelled=%t", opts.ToolCfg.Baseline.HasBaseline(), cancelled)
				}
			})
		}
	}
}

func TestForwardScannedCancellationBlockWriteFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ordinary"}]}}`+"\n")), transport.NewStdioWriter(&errWriter{limit: 0}), io.Discard, nil, MCPProxyOpts{Scanner: testScannerWithAction(t, config.ActionWarn), WarnContext: ctx})
	if err == nil || !strings.Contains(err.Error(), "writing scan-error block response") {
		t.Fatalf("write failure lost: %v", err)
	}
}
