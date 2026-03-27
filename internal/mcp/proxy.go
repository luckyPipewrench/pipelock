// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	decide "github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// syncWriter wraps an io.Writer with a mutex to make concurrent writes safe.
// Used in RunProxy where multiple goroutines write to clientOut and logW.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// Compile-time assertion: syncWriter implements transport.MessageWriter.
var _ transport.MessageWriter = (*syncWriter)(nil)

func (sw *syncWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

// WriteMessage writes a JSON-RPC message followed by a newline in a single
// Write call under the mutex, preventing interleaving between concurrent
// goroutines (e.g., the blocked request drainer and ForwardScanned).
func (sw *syncWriter) WriteMessage(msg []byte) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if len(msg) > transport.MaxLineSize {
		return fmt.Errorf("message too large: %d bytes", len(msg))
	}
	buf := make([]byte, len(msg)+1)
	copy(buf, msg)
	buf[len(msg)] = '\n'
	if _, err := sw.w.Write(buf); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	return nil
}

// isResponse returns true if msg is a JSON-RPC response (has "result" or "error"
// field). Messages with only a "method" field (server-initiated requests) return
// false. A message with both "method" and "result" is treated as a response
// (security-conservative: if it carries a result payload, validate its ID).
func isResponse(msg []byte) bool {
	var probe struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(msg, &probe) != nil {
		return false
	}
	return len(probe.Result) > 0 || len(probe.Error) > 0
}

// isRequest returns true if msg is a JSON-RPC request (has "method" field and
// is not a response). Used to guard tracker.Track so only outbound client
// requests are tracked, not client responses to server-initiated calls.
func isRequest(msg []byte) bool {
	var probe struct {
		Method string          `json:"method"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(msg, &probe) != nil {
		return false
	}
	return probe.Method != "" && len(probe.Result) == 0 && len(probe.Error) == 0
}

// ForwardScanned reads JSON-RPC 2.0 messages from reader, scans each for prompt
// injection, and forwards to writer based on the scanner's configured action
// (warn, block, strip). Scan verdicts are logged to logW.
// When toolCfg is non-nil, tool descriptions in tools/list responses are scanned
// for poisoning and tracked for drift (rug pull) detection. Tool scanning runs
// independently of general response scanning so a "block" tool action is never
// bypassed by a "warn" general action.
// When tracker is non-nil, response IDs are validated against previously tracked
// request IDs to prevent confused deputy attacks (unsolicited responses).
// When rec is non-nil and adaptiveCfg is enabled, threat signals are recorded
// and the effective action may be upgraded based on session escalation level.
// When ks is non-nil, the kill switch is checked on each message so activation
// mid-stream terminates already-open sessions immediately.
// Returns true if any injection was detected.
func ForwardScanned(reader transport.MessageReader, writer transport.MessageWriter, logW io.Writer, tracker *RequestTracker, opts MCPProxyOpts) (bool, error) {
	sc := opts.Scanner
	approver := opts.Approver
	toolCfg := opts.ToolCfg
	ks := opts.KillSwitch
	rec := opts.Rec
	adaptiveCfg := opts.AdaptiveCfg
	m := opts.Metrics

	// blockAll tracks whether the session is at a critical escalation level
	// with block_all=true. Checked once up front and refreshed after each
	// message so mid-stream escalation takes effect immediately.
	blockAll := rec != nil && decide.UpgradeAction("", rec.EscalationLevel(), adaptiveCfg) == config.ActionBlock
	if blockAll {
		_, _ = fmt.Fprintf(logW, "pipelock: session deny — escalation level %s, blocking all responses\n",
			session.EscalationLabel(rec.EscalationLevel()))
	}

	foundInjection := false
	// lineNum counts non-empty messages, not raw lines. StdioReader skips
	// empty lines internally, so this is a message index. ScanStream (scan.go)
	// preserves raw line counting for user-facing diagnostics.
	lineNum := 0

	for {
		line, err := reader.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return foundInjection, fmt.Errorf("reading input: %w", err)
		}
		lineNum++

		// Kill switch: deny all responses when activated mid-stream.
		// Checked per message so activation after session start takes effect
		// immediately on already-open MCP sessions.
		if ks != nil {
			if d := ks.IsActiveMCP(line); d.Active {
				rpcID := extractRPCID(line)
				if rpcID == nil {
					// Notification: drop silently (no response possible).
					_, _ = fmt.Fprintf(logW, "pipelock: response line %d: kill switch dropped notification (source=%s)\n",
						lineNum, d.Source)
					continue
				}
				_, _ = fmt.Fprintf(logW, "pipelock: response line %d: kill switch denied (source=%s)\n",
					lineNum, d.Source)
				resp := killswitch.ErrorResponse(rpcID, d.Message)
				if wErr := writer.WriteMessage(resp); wErr != nil {
					return foundInjection, fmt.Errorf("writing kill switch response: %w", wErr)
				}
				continue
			}
		}

		// On-entry de-escalation for long-lived response streams.
		tryRecoverSession(rec, adaptiveCfg, m)

		// block_all enforcement: write a JSON-RPC error for every message when
		// the session is at an escalation level with block_all=true. Refresh
		// on each message so mid-stream escalation AND recovery both take
		// effect immediately on already-open MCP sessions.
		if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
			wasBlocked := blockAll
			blockAll = decide.UpgradeAction("", rec.EscalationLevel(), adaptiveCfg) == config.ActionBlock
			if blockAll && !wasBlocked {
				_, _ = fmt.Fprintf(logW, "pipelock: session deny — escalation level %s, blocking all responses\n",
					session.EscalationLabel(rec.EscalationLevel()))
			}
		}
		if blockAll {
			rpcID := extractRPCID(line)
			// Notifications (no ID) must not receive a response per JSON-RPC spec.
			// Drop them silently instead of writing an error.
			if rpcID == nil {
				continue
			}
			resp := blockSessionDenyResponse(rpcID, session.EscalationLabel(rec.EscalationLevel()))
			if wErr := writer.WriteMessage(resp); wErr != nil {
				return foundInjection, fmt.Errorf("writing session deny: %w", wErr)
			}
			continue
		}

		// MCP does not use JSON-RPC batch messages (top-level arrays).
		// A batch from the server is either malformed or an attempt to
		// bypass per-message ID validation. Fail closed.
		if len(line) > 0 && line[0] == '[' {
			_, _ = fmt.Fprintf(logW, "pipelock: line %d: blocked batch JSON-RPC message (not supported by MCP)\n", lineNum)
			continue
		}

		// Confused deputy: validate response IDs against tracked requests.
		// Only check actual responses (have "result" or "error"), not
		// server-initiated requests (have "method") which use their own IDs.
		// The Seeded() gate defers validation until the first client request
		// is tracked. This prevents a race where a fast server response
		// arrives before ForwardScannedInput tracks the outbound request ID
		// (concurrent goroutines). The window is not exploitable: before any
		// client request, no valid request ID exists to hijack.
		if tracker != nil && tracker.Seeded() && isResponse(line) {
			rpcID := extractRPCID(line)
			if rpcID != nil && !tracker.Validate(rpcID) {
				_, _ = fmt.Fprintf(logW, "pipelock: line %d: confused deputy: unsolicited response ID %s\n",
					lineNum, string(rpcID))
				resp := blockResponse(rpcID)
				if err := writer.WriteMessage(resp); err != nil {
					return foundInjection, fmt.Errorf("writing confused deputy block: %w", err)
				}
				continue
			}
		}

		// Tool scanning runs first. tools/list responses contain instructional
		// text ("you must call this tool") that the general injection scanner
		// would flag as false positives. The dedicated tool scanner uses
		// purpose-built poisoning patterns instead. When tool scanning
		// identifies a message as tools/list, skip the general scan entirely.
		isToolsList := false
		// toolPoisonDetected tracks whether a tool-poisoning finding was raised
		// for this message (even in warn mode). A message that raised a
		// tool-poison near-miss signal must not also apply RecordClean: the
		// same message cannot both raise and decay the session threat score.
		toolPoisonDetected := false
		if toolCfg != nil {
			toolResult := tools.ScanTools(line, sc, toolCfg)
			isToolsList = toolResult.IsToolsList
			// Session binding: capture tool names from tools/list responses.
			if toolResult.IsToolsList && toolCfg.Baseline != nil && len(toolResult.ToolNames) > 0 {
				if !toolCfg.Baseline.HasBaseline() {
					toolCfg.Baseline.SetKnownTools(toolResult.ToolNames)
				} else {
					added := toolCfg.Baseline.CheckNewTools(toolResult.ToolNames)
					for _, name := range added {
						_, _ = fmt.Fprintf(logW, "pipelock: tool %q added post-baseline\n", name)
					}
				}
			}
			if toolResult.IsToolsList && !toolResult.Clean {
				foundInjection = true
				toolPoisonDetected = true
				tools.LogToolFindings(logW, lineNum, toolResult)

				originalToolAction := toolCfg.Action
				toolAction := originalToolAction
				// Escalation upgrade for tool poison detection.
				if rec != nil {
					toolAction = decide.UpgradeAction(toolAction, rec.EscalationLevel(), adaptiveCfg)
					if toolAction != originalToolAction {
						// Emit adaptive-upgrade telemetry when escalation changed the action.
						_, _ = fmt.Fprintf(logW, "pipelock: line %d: adaptive upgrade tool-poison %s->%s (level=%s)\n",
							lineNum, originalToolAction, toolAction, session.EscalationLabel(rec.EscalationLevel()))
						if m != nil {
							m.RecordAdaptiveUpgrade(originalToolAction, toolAction, session.EscalationLabel(rec.EscalationLevel()))
						}
					}
				}

				if toolAction == config.ActionBlock {
					// Signal: tool poisoning blocked.
					if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
						recordSignalWithEscalation(rec, session.SignalBlock, adaptiveCfg.EscalationThreshold, logW, nil, m, "", "", "")
					}
					resp := blockResponse(toolResult.RPCID)
					if err := writer.WriteMessage(resp); err != nil {
						return foundInjection, fmt.Errorf("writing tool block: %w", err)
					}
					continue
				}
				// warn: logged above, record near-miss and fall through to general handling.
				if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
					recordSignalWithEscalation(rec, session.SignalNearMiss, adaptiveCfg.EscalationThreshold, logW, nil, m, "", "", "")
				}
			}
		}

		// For tools/list responses, skip general scanning of the result field
		// (tool descriptions contain instructional text that triggers FPs).
		// Still scan the error field: injection could hide in non-tool fields.
		var verdict jsonrpc.ScanVerdict
		if isToolsList {
			verdict = scanToolsListNonToolFields(line, sc)
		} else {
			verdict = ScanResponse(line, sc)
		}

		if verdict.Clean {
			// Clean message: decay threat score. Skip decay when tool-poisoning
			// was detected for this message — a near-miss signal and a clean
			// decay on the same message would incorrectly counteract each other.
			if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled && !toolPoisonDetected {
				rec.RecordClean(adaptiveCfg.DecayPerCleanRequest)
			}
			if err := writer.WriteMessage(line); err != nil {
				return foundInjection, fmt.Errorf("writing line: %w", err)
			}
			continue
		}

		// Parse error: always fail-closed regardless of action setting.
		// Unparseable responses could hide injection in malformed content.
		if verdict.Error != "" {
			_, _ = fmt.Fprintf(logW, "pipelock: line %d: %s\n", lineNum, verdict.Error)
			// Scan raw text for injection even when not valid JSON-RPC.
			rawResult := sc.ScanResponse(context.Background(), string(line))
			if !rawResult.Clean {
				foundInjection = true
				names := matchNames(rawResult.Matches)
				_, _ = fmt.Fprintf(logW, "pipelock: line %d: injection in non-JSON content (%s)\n",
					lineNum, strings.Join(names, ", "))
			}
			_, _ = fmt.Fprintf(logW, "pipelock: line %d: blocking unparseable response\n", lineNum)
			resp := blockResponse(nil)
			if err := writer.WriteMessage(resp); err != nil {
				return foundInjection, fmt.Errorf("writing block response: %w", err)
			}
			continue
		}

		// Injection detected.
		foundInjection = true
		action := sc.ResponseAction()
		originalAction := action
		names := matchNames(verdict.Matches)

		// Escalation upgrade: may promote warn/ask to block for elevated sessions.
		if rec != nil {
			action = decide.UpgradeAction(action, rec.EscalationLevel(), adaptiveCfg)
		}
		escalationDriven := action != originalAction

		_, _ = fmt.Fprintf(logW, "pipelock: line %d: injection detected (%s), action=%s\n",
			lineNum, strings.Join(names, ", "), action)

		switch action {
		case config.ActionBlock:
			// Escalation-driven blocks use -32001 (session deny code) to
			// distinguish them from direct injection blocks (-32000).
			var resp []byte
			if escalationDriven {
				resp = blockSessionDenyResponse(verdict.ID, session.EscalationLabel(rec.EscalationLevel()))
			} else {
				resp = blockResponse(verdict.ID)
			}
			if err := writer.WriteMessage(resp); err != nil {
				return foundInjection, fmt.Errorf("writing block response: %w", err)
			}
		case config.ActionAsk:
			if approver == nil {
				_, _ = fmt.Fprintf(logW, "pipelock: line %d: no HITL approver configured, blocking\n", lineNum)
				resp := blockResponse(verdict.ID)
				if err := writer.WriteMessage(resp); err != nil {
					return foundInjection, fmt.Errorf("writing block response: %w", err)
				}
			} else {
				preview := ""
				if len(verdict.Matches) > 0 {
					preview = verdict.Matches[0].MatchText
				}
				d := approver.Ask(&hitl.Request{
					URL:      "mcp-response",
					Reason:   fmt.Sprintf("prompt injection detected: %s", strings.Join(names, ", ")),
					Patterns: names,
					Preview:  preview,
				})
				switch d {
				case hitl.DecisionAllow:
					_, _ = fmt.Fprintf(logW, "pipelock: line %d: operator allowed\n", lineNum)
					if err := writer.WriteMessage(line); err != nil {
						return foundInjection, fmt.Errorf("writing line: %w", err)
					}
				case hitl.DecisionStrip:
					_, _ = fmt.Fprintf(logW, "pipelock: line %d: operator chose strip\n", lineNum)
					if err := stripOrBlock(line, sc, writer, logW, verdict.ID); err != nil {
						return foundInjection, fmt.Errorf("writing strip/block response: %w", err)
					}
				default: // DecisionBlock
					_, _ = fmt.Fprintf(logW, "pipelock: line %d: operator blocked\n", lineNum)
					resp := blockResponse(verdict.ID)
					if err := writer.WriteMessage(resp); err != nil {
						return foundInjection, fmt.Errorf("writing block response: %w", err)
					}
				}
			}
		case config.ActionStrip:
			if err := stripOrBlock(line, sc, writer, logW, verdict.ID); err != nil {
				return foundInjection, fmt.Errorf("writing strip/block response: %w", err)
			}
		default: // warn
			if err := writer.WriteMessage(line); err != nil {
				return foundInjection, fmt.Errorf("writing line: %w", err)
			}
		}

		// Signal recording: record after action is taken.
		if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
			switch action {
			case config.ActionBlock:
				recordSignalWithEscalation(rec, session.SignalBlock, adaptiveCfg.EscalationThreshold, logW, nil, m, "", "", "")
			case config.ActionStrip:
				recordSignalWithEscalation(rec, session.SignalStrip, adaptiveCfg.EscalationThreshold, logW, nil, m, "", "", "")
			default:
				// Warn/ask: near-miss signal (injection detected but not blocked).
				recordSignalWithEscalation(rec, session.SignalNearMiss, adaptiveCfg.EscalationThreshold, logW, nil, m, "", "", "")
			}
		}
	}

	return foundInjection, nil
}

// stripOrBlock tries to strip injection from the response. If stripping fails,
// it falls back to blocking (fail-closed). Returns a write error if the writer fails.
func stripOrBlock(line []byte, sc *scanner.Scanner, writer transport.MessageWriter, logW io.Writer, rpcID json.RawMessage) error {
	stripped, sErr := stripResponse(line, sc)
	if sErr != nil {
		_, _ = fmt.Fprintf(logW, "pipelock: strip failed (%v), blocking instead\n", sErr)
		return writer.WriteMessage(blockResponse(rpcID))
	}
	return writer.WriteMessage(stripped)
}

// rpcError is a JSON-RPC 2.0 error response sent when a response is blocked.
type rpcError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcErrorDetail  `json:"error"`
}

type rpcErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// blockResponse generates a JSON-RPC 2.0 error response for a blocked message.
// Code -32000 is in the implementation-defined error range.
func blockResponse(id json.RawMessage) []byte {
	resp := rpcError{
		JSONRPC: jsonrpc.Version,
		ID:      id,
		Error: rpcErrorDetail{
			Code:    -32000,
			Message: "pipelock: prompt injection detected in MCP response",
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// blockSessionDenyResponse generates a JSON-RPC 2.0 error for block_all session
// denial. Uses error code -32001 (implementation-defined) with a session-deny
// message. Distinct from blockResponse to distinguish session-level blocks
// from per-message injection blocks in logs and client error handling.
func blockSessionDenyResponse(id json.RawMessage, levelLabel string) []byte {
	resp := rpcError{
		JSONRPC: jsonrpc.Version,
		ID:      id,
		Error: rpcErrorDetail{
			Code:    -32001,
			Message: "pipelock: session escalation level " + levelLabel,
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// stripRPCResponse is used only by stripResponse for typed result manipulation.
// The main jsonrpc.RPCResponse uses json.RawMessage for flexible scanning.
type stripRPCResponse struct {
	JSONRPC string              `json:"jsonrpc"`
	ID      json.RawMessage     `json:"id"`
	Result  *jsonrpc.ToolResult `json:"result,omitempty"`
	Error   json.RawMessage     `json:"error,omitempty"`
}

// maxStripDepth limits recursion between stripResponseDepth and stripBatchDepth
// to prevent stack overflow from maliciously nested JSON arrays.
const maxStripDepth = 4

// stripResponse re-parses a JSON-RPC response, redacts matched injection
// patterns in content blocks and error fields, and returns the re-marshaled JSON.
func stripResponse(line []byte, sc *scanner.Scanner) ([]byte, error) {
	return stripResponseDepth(line, sc, 0)
}

func stripResponseDepth(line []byte, sc *scanner.Scanner, depth int) ([]byte, error) {
	// Handle batch responses (JSON array).
	if len(line) > 0 && line[0] == '[' {
		if depth >= maxStripDepth {
			return nil, fmt.Errorf("batch nesting too deep (max %d)", maxStripDepth)
		}
		return stripBatchDepth(line, sc, depth+1)
	}

	var rpc stripRPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return nil, fmt.Errorf("parsing response for strip: %w", err)
	}

	if rpc.Result != nil {
		for i, block := range rpc.Result.Content {
			if block.Text == "" {
				continue
			}
			result := sc.ScanResponse(context.Background(), block.Text)
			if !result.Clean {
				if result.TransformedContent != "" {
					rpc.Result.Content[i].Text = result.TransformedContent
				} else {
					// Detection from non-redactable pass (vowel-fold/decoded).
					// Can't strip, fail-closed to block.
					return nil, fmt.Errorf("injection detected but not redactable in content block %d", i)
				}
			}
		}
	}

	// Scan error.message and error.data for injection content.
	if len(rpc.Error) > 0 {
		var errObj struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data,omitempty"`
		}
		if json.Unmarshal(rpc.Error, &errObj) == nil {
			changed := false
			if errObj.Message != "" {
				result := sc.ScanResponse(context.Background(), errObj.Message)
				if !result.Clean {
					if result.TransformedContent != "" {
						errObj.Message = result.TransformedContent
						changed = true
					} else {
						return nil, fmt.Errorf("injection detected but not redactable in error message")
					}
				}
			}
			if len(errObj.Data) > 0 {
				var dataStr string
				if json.Unmarshal(errObj.Data, &dataStr) == nil && dataStr != "" {
					result := sc.ScanResponse(context.Background(), dataStr)
					if !result.Clean {
						if result.TransformedContent != "" {
							if newData, mErr := json.Marshal(result.TransformedContent); mErr == nil {
								errObj.Data = newData
								changed = true
							}
						} else {
							return nil, fmt.Errorf("injection detected but not redactable in error data")
						}
					}
				}
			}
			if changed {
				if newErr, mErr := json.Marshal(errObj); mErr == nil {
					rpc.Error = newErr
				}
			}
		}
	}

	return json.Marshal(rpc)
}

// stripBatchDepth handles stripping injection from batch (array) JSON-RPC responses.
func stripBatchDepth(line []byte, sc *scanner.Scanner, depth int) ([]byte, error) {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return nil, fmt.Errorf("parsing batch for strip: %w", err)
	}
	result := make([]json.RawMessage, len(batch))
	for i, elem := range batch {
		stripped, err := stripResponseDepth(elem, sc, depth)
		if err != nil {
			// Never forward unstripped injection — block the element instead.
			result[i] = json.RawMessage(blockResponse(nil))
		} else {
			result[i] = json.RawMessage(stripped)
		}
	}
	return json.Marshal(result)
}

// matchNames extracts pattern names from a list of response matches.
func matchNames(matches []scanner.ResponseMatch) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.PatternName)
	}
	return names
}

// recordSignalWithEscalation wraps RecordSignal and handles escalation returns:
// logs the transition and updates metrics gauges. logW is the stderr writer for
// the MCP proxy. auditLogger and m may be nil (stdio mode has no audit logger
// or metrics). sessionKey and clientIP are used for audit log context; pass ""
// when not available (e.g., stdio transports).
func recordSignalWithEscalation(rec session.Recorder, sig session.SignalType, threshold float64, logW io.Writer, auditLogger *audit.Logger, m *metrics.Metrics, sessionKey, clientIP, requestID string) {
	decide.RecordEscalation(rec, sig, decide.EscalationParams{
		Threshold:     threshold,
		Logger:        auditLogger,
		Metrics:       m,
		ConsoleWriter: logW,
		Session:       sessionKey,
		ClientIP:      clientIP,
		RequestID:     requestID,
	})
}

// AdaptiveConfigFunc returns the current adaptive enforcement config.
// Used by long-lived listeners (RunHTTPListenerProxy) so they read the
// live config after each hot-reload instead of a stale startup snapshot.
// Returns nil when adaptive enforcement is disabled.
type AdaptiveConfigFunc func() *config.AdaptiveEnforcement

// InputScanConfig holds the settings for MCP input scanning.
// Passed to RunProxy to control request scanning behavior.
type InputScanConfig struct {
	Enabled      bool
	Action       string // warn, block
	OnParseError string // block, forward
}

// RunProxy launches an MCP server subprocess and proxies stdio through
// the scanner. Client input is scanned for DLP/injection (if enabled) before
// forwarding to the server's stdin. Server stdout is scanned and forwarded
// to the client. Server stderr is forwarded to logW.
// When toolCfg is non-nil with a non-empty Action, tool description scanning
// and drift detection are enabled for this proxy session.
// Both clientOut and logW are wrapped in mutex adapters to prevent concurrent
// write races between the input scanning goroutine, blocked request drainer,
// child process stderr, and the main goroutine's response scanning.
// When store is non-nil, a per-invocation session recorder is created and used
// for adaptive enforcement signal recording across both input and response scanning.
// adaptiveCfg provides escalation thresholds and upgrade rules; it is only consulted
// when store is non-nil and rec is created.
// RunProxy starts an MCP server subprocess and proxies stdin/stdout with
// bidirectional scanning. onChildReady is called after the child process
// starts and its PID is registered with the lineage tracker; callers use
// this to start the file sentry event loop after attribution is ready.
func RunProxy(ctx context.Context, clientIn io.Reader, clientOut io.Writer, logW io.Writer, command []string, opts MCPProxyOpts, extraEnv ...string) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...) //nolint:gosec // command comes from user CLI args

	// Per-invocation adaptive enforcement recorder. Nil when Store is nil
	// (adaptive enforcement disabled), so all downstream callers are nil-safe.
	var rec session.Recorder
	if opts.Store != nil {
		rec = opts.Store.GetOrCreate(session.NextInvocationKey("mcp-stdio"))
	}

	// Wrap shared writers in mutex adapters. Multiple goroutines write to
	// clientOut (blocked request drainer + response scanner) and logW
	// (input scanner + response scanner + child stderr).
	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}

	// Restrict child process environment to safe variables only.
	// Prevents leaking secrets from the proxy's environment to the MCP server.
	// Extra env vars from --env flags are appended (user explicitly opted in).
	cmd.Env = append(safeEnv(), extraEnv...)

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}

	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	cmd.Stderr = safeLogW

	// Enable subreaper before starting the child so we adopt orphaned
	// grandchildren. This lets the lineage tracker attribute file writes
	// to the agent's process tree.
	//
	// If subreaper setup fails (e.g. missing CAP_SYS_RESOURCE in containers),
	// PID attribution is unreliable. Warn and disable the lineage tracker
	// rather than silently producing wrong results. File sentry DLP scanning
	// still runs — only process-tree attribution is affected.
	lineage := opts.Lineage
	if lineage != nil {
		if err := lineage.EnableSubreaper(); err != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: warning: subreaper setup failed, disabling PID attribution: %v\n", err)
			lineage = nil
		}
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting MCP server %q: %w", command[0], err)
	}

	// Track child PID for file write attribution.
	if lineage != nil {
		lineage.TrackPID(cmd.Process.Pid)
	}

	// Signal that the child is started and PID is tracked. The file sentry
	// event loop starts here so attribution is ready before classifying writes.
	if opts.OnChildReady != nil {
		opts.OnChildReady()
	}

	// Channel for blocked request IDs from input scanning goroutine.
	// Blocked drainer goroutine writes error responses to safeClientOut,
	// which is mutex-protected against concurrent writes from ForwardScanned.
	blockedCh := make(chan BlockedRequest, 16)

	// Set up tool scanning with a fresh baseline for this proxy session.
	// The baseline is shared between ForwardScanned (response-side, captures
	// tools/list) and ForwardScannedInput (request-side, validates tools/call).
	// Must be created before goroutines that reference it.
	var fwdToolCfg *tools.ToolScanConfig
	if opts.ToolCfg != nil && opts.ToolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:                tools.NewToolBaseline(),
			Action:                  opts.ToolCfg.Action,
			DetectDrift:             opts.ToolCfg.DetectDrift,
			BindingUnknownAction:    opts.ToolCfg.BindingUnknownAction,
			BindingNoBaselineAction: opts.ToolCfg.BindingNoBaselineAction,
			ExtraPoison:             opts.ToolCfg.ExtraPoison,
		}
	}

	// Build session binding config for input scanning. Shares the same
	// tools.ToolBaseline so tools/list captures (response-side) are visible to
	// tools/call validation (request-side).
	var bindingCfg *SessionBindingConfig
	if fwdToolCfg != nil && fwdToolCfg.BindingUnknownAction != "" {
		bindingCfg = &SessionBindingConfig{
			Baseline:          fwdToolCfg.Baseline,
			UnknownToolAction: fwdToolCfg.BindingUnknownAction,
			NoBaselineAction:  fwdToolCfg.BindingNoBaselineAction,
		}
	}

	// Request tracker for confused deputy protection. Always created so
	// response ID validation is active regardless of which input scanning
	// features are enabled.
	tracker := NewRequestTracker()

	// Build per-invocation opts with session-specific recorder and tool baseline.
	inputOpts := opts
	inputOpts.Rec = rec

	// Forward client input to server stdin (with optional input scanning).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverIn.Close() //nolint:errcheck // best-effort close on stdin forward
		inputCfg := opts.InputCfg
		if inputCfg != nil && inputCfg.Enabled {
			clientReader := transport.NewStdioReader(clientIn)
			serverWriter := transport.NewStdioWriter(serverIn)
			ForwardScannedInput(clientReader, serverWriter, safeLogW, inputCfg.Action, inputCfg.OnParseError, blockedCh, bindingCfg, tracker, inputOpts)
		} else if opts.PolicyCfg != nil || bindingCfg != nil || opts.ChainMatcher != nil {
			// Policy checking, session binding, or chain detection enabled but content scanning disabled.
			// Route through ForwardScannedInput with pass-through content scanning.
			// Use onParseError="block" (fail-closed) so malformed JSON can't bypass policy.
			clientReader := transport.NewStdioReader(clientIn)
			serverWriter := transport.NewStdioWriter(serverIn)
			ForwardScannedInput(clientReader, serverWriter, safeLogW, config.ActionWarn, config.ActionBlock, blockedCh, bindingCfg, tracker, inputOpts)
		} else {
			// No content scanning, but still route through ForwardScannedInput
			// so request IDs are tracked for confused deputy protection.
			// ActionWarn = pass-through, ActionBlock on parse error = fail-closed.
			clientReader := transport.NewStdioReader(clientIn)
			serverWriter := transport.NewStdioWriter(serverIn)
			noScanOpts := inputOpts
			noScanOpts.PolicyCfg = nil
			noScanOpts.ChainMatcher = nil
			ForwardScannedInput(clientReader, serverWriter, safeLogW, config.ActionWarn, config.ActionBlock, blockedCh, nil, tracker, noScanOpts)
		}
	}()

	// Drain blocked request channel and write error responses to client.
	// Runs in a separate goroutine so ForwardScanned can proceed concurrently.
	var wgBlocked sync.WaitGroup
	wgBlocked.Add(1)
	go func() {
		defer wgBlocked.Done()
		for blocked := range blockedCh {
			if blocked.IsNotification {
				// Notifications have no ID — silently drop (no error response).
				continue
			}
			var resp []byte
			if blocked.SyntheticResponse != nil {
				resp = blocked.SyntheticResponse
			} else {
				resp = blockRequestResponse(blocked)
			}
			if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send block response: %v\n", wErr)
			}
		}
	}()

	// Scan and forward server output to client.
	serverReader := transport.NewStdioReader(serverOut)
	fwdOpts := inputOpts
	fwdOpts.ToolCfg = fwdToolCfg // session-specific baseline
	_, scanErr := ForwardScanned(serverReader, safeClientOut, safeLogW, tracker, fwdOpts)

	// Wait for subprocess to exit.
	waitErr := cmd.Wait()

	// Wait for stdin goroutine to finish (server exit closes pipe, unblocking scanner).
	wg.Wait()

	// Wait for blocked channel drain to complete.
	wgBlocked.Wait()

	if scanErr != nil {
		return fmt.Errorf("scanning: %w", scanErr)
	}

	return waitErr
}

// safeEnvKeys are environment variables safe to pass to child MCP server processes.
// These cannot be overridden via --env to prevent footgun scenarios (e.g. --env PATH=/evil).
var safeEnvKeys = []string{"PATH", "HOME", "USER", "LANG", "TERM", "TZ", "TMPDIR", "SHELL"}

// safeEnvKeySet mirrors safeEnvKeys as a set for O(1) lookup in IsSafeEnvKey.
var safeEnvKeySet = func() map[string]bool {
	m := make(map[string]bool, len(safeEnvKeys))
	for _, k := range safeEnvKeys {
		m[k] = true
	}
	return m
}()

// dangerousEnvKeys are environment variable names that can inject code or libraries
// into child processes. These are blocked even when explicitly requested via --env.
var dangerousEnvKeys = map[string]bool{
	// Dynamic linker injection (Linux/macOS).
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	// Runtime code injection.
	"NODE_OPTIONS":      true,
	"PYTHONSTARTUP":     true,
	"PYTHONPATH":        true,
	"PERL5OPT":          true,
	"RUBYOPT":           true,
	"BASH_ENV":          true,
	"JAVA_TOOL_OPTIONS": true,
	"_JAVA_OPTIONS":     true,
	"JDK_JAVA_OPTIONS":  true,
	// Credential helper injection — causes git to execute arbitrary programs.
	"GIT_ASKPASS": true,
	// Proxy redirection — the MCP proxy IS the controlled network path.
	// Both cases listed because Go checks HTTP_PROXY/http_proxy, Node.js
	// checks case-insensitively, etc. Mixed-case caught by IsDangerousEnvKey.
	"HTTP_PROXY":  true,
	"HTTPS_PROXY": true,
	"ALL_PROXY":   true,
	"FTP_PROXY":   true,
	"NO_PROXY":    true,
	"http_proxy":  true,
	"https_proxy": true,
	"all_proxy":   true,
	"ftp_proxy":   true,
	"no_proxy":    true,
}

// IsSafeEnvKey reports whether the given key is one of the system variables
// already provided by safeEnv(). These cannot be overridden via --env.
func IsSafeEnvKey(key string) bool {
	return safeEnvKeySet[key]
}

// IsDangerousEnvKey reports whether the given environment variable name is
// blocked from passthrough because it can inject code or redirect traffic.
// Proxy-related vars are checked case-insensitively since different runtimes
// (Go, Node.js, Python, curl) honor different casings.
func IsDangerousEnvKey(key string) bool {
	if dangerousEnvKeys[key] {
		return true
	}
	// Case-insensitive catch-all for proxy vars. Covers mixed-case forms
	// like Http_Proxy that some runtimes (notably Node.js) honor.
	upper := strings.ToUpper(key)
	return strings.HasSuffix(upper, "_PROXY")
}

// safeEnv builds a filtered environment from the current process, keeping only
// variables in safeEnvKeys. This prevents accidental secret leakage to MCP servers.
func safeEnv() []string {
	var env []string
	for _, key := range safeEnvKeys {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	return env
}
