// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

func emitRequestScopedTimeout(
	respReader transport.MessageReader,
	writer transport.MessageWriter,
	logW io.Writer,
	tracker *RequestTracker,
	id json.RawMessage,
	logMessage string,
	opts MCPProxyOpts,
) {
	if c, ok := respReader.(io.Closer); ok {
		_ = c.Close()
	}
	if len(id) != 0 {
		outcome, ok := consumeTrackedRequestOutcome(tracker, id)
		if ok {
			resp := timeoutErrorResponse(id)
			if wErr := writer.WriteMessage(resp); wErr != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: failed to send timeout response: %v\n", wErr)
			}
			emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), logW, outcome.Receipt, "error", int64(len(resp)), "response_timeout")
		}
	}
	_, _ = fmt.Fprintln(logW, logMessage)
}

func emitTrackedTerminalOutcome(logW io.Writer, tracker *RequestTracker, id json.RawMessage, resp []byte, reason string, opts MCPProxyOpts) {
	outcome, ok := consumeTrackedRequestOutcome(tracker, id)
	if !ok {
		return
	}
	emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), logW, outcome.Receipt, mcpResponseStatus(resp), int64(len(resp)), reason)
}

func emitTrackedIncompleteOutcome(logW io.Writer, tracker *RequestTracker, id json.RawMessage, reason string, opts MCPProxyOpts) {
	outcome, ok := consumeTrackedRequestOutcome(tracker, id)
	if !ok {
		return
	}
	emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), logW, outcome.Receipt, "incomplete", -1, reason)
}

func consumeTrackedRequestOutcome(tracker *RequestTracker, id json.RawMessage) (TrackedRequestOutcome, bool) {
	if tracker == nil {
		return TrackedRequestOutcome{}, true
	}
	return tracker.Consume(id)
}

// RunHTTPProxy bridges stdio (client) to an upstream HTTP MCP server with
// bidirectional scanning. Reads JSON-RPC from clientIn, POSTs to upstreamURL,
// scans responses via ForwardScanned, writes to clientOut.
// When opts.Store is non-nil, a per-invocation session recorder is created and
// used for adaptive enforcement signal recording across both input and response
// scanning.
func RunHTTPProxy(
	ctx context.Context,
	clientIn io.Reader,
	clientOut io.Writer,
	logW io.Writer,
	upstreamURL string,
	extraHeaders http.Header,
	opts MCPProxyOpts,
) error {
	// Set transport for capture records if not already set by caller.
	if opts.Transport == "" {
		opts.Transport = "mcp_http_upstream"
	}
	if opts.ContractServer == "" {
		opts.ContractServer = mcpContractServerFromUpstream(upstreamURL)
	}
	opts.TaintExternalSource = true

	if gate, gateErr := evaluateMCPUpstreamGate(ctx, upstreamURL, opts); gateErr != nil {
		return fmt.Errorf("contract upstream evaluation: %w", gateErr)
	} else if gate.Verdict == config.ActionBlock {
		return fmt.Errorf("contract upstream denied: %s", mcpContractBlockReason(gate))
	}

	// Create a child context so we can stop the GET stream when stdin EOF is reached.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Per-invocation adaptive enforcement recorder. Mint the invocation
	// key once so it can also feed scanHTTPInputDecision below, keeping
	// CEE state and audit correlation scoped to this RunHTTPProxy call
	// instead of a shared "default" bucket across unrelated invocations.
	invocationKey := session.NextInvocationKey("mcp-http")
	var rec session.Recorder
	if opts.Store != nil {
		rec = opts.Store.GetOrCreate(invocationKey)
	}
	defer recordMCPBaselineSample(opts, rec)

	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}

	httpClient := transport.NewHTTPClient(upstreamURL, extraHeaders)
	var upstreamMu sync.Mutex

	// Tool scanning baseline for this session. Clone the caller's ToolCfg
	// with a fresh per-session baseline so drift detection is scoped to
	// this invocation.
	toolCfg := opts.toolCfg()
	var fwdToolCfg *tools.ToolScanConfig
	if toolCfg != nil && toolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:    tools.NewToolBaseline(),
			Action:      toolCfg.Action,
			DetectDrift: toolCfg.DetectDrift,
			ExtraPoison: toolCfg.ExtraPoison,
		}
	}

	// Request tracker for confused deputy protection.
	tracker := NewRequestTracker()

	// Session-scoped opts: override Rec and ToolCfg from the caller's opts.
	fwdOpts := opts
	fwdOpts.Rec = rec
	fwdOpts.ToolCfg = fwdToolCfg
	fwdOpts.ToolCfgFn = nil
	fwdOpts.WarnContext = ctx
	resolverRuntime := newDeferResolverRuntime(ctx)
	fwdOpts.DeferResolverRuntime = resolverRuntime
	defer func() {
		resolverRuntime.Cancel()
		if manager := fwdOpts.deferManager(); manager != nil {
			manager.ResolveAll(config.ActionBlock, deferred.SourceCancel)
		}
		resolverRuntime.Wait()
	}()

	clientReader := transport.NewStdioReader(clientIn)

	var wg sync.WaitGroup
	var getStreamOnce sync.Once
	var lastScanErr error

	for {
		msg, err := clientReader.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("reading stdin: %w", err)
		}

		// Parse the inbound frame once per message. Kill switch, request
		// tracking, and upstream-error responses all read frame.ID
		// instead of re-parsing.
		frame := ParseMCPFrame(msg)

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Kill switch: deny all messages when active.
		if opts.KillSwitch != nil {
			if d := opts.KillSwitch.IsActiveMCP(msg); d.Active {
				if manager := fwdOpts.deferManager(); manager != nil {
					manager.ResolveAll(config.ActionBlock, deferred.SourceKillSwitch)
				}
				if d.IsNotification {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					continue
				}
				rpcID := frame.ID
				resp := killswitch.ErrorResponse(rpcID, d.Message)
				if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send kill switch response: %v\n", wErr)
				}
				continue
			}
		}

		// Input scanning - call ScanRequest and CheckRequest directly.
		// The sequential (non-concurrent) architecture means no channel needed.
		decision := scanHTTPInputDecision(msg, safeLogW, invocationKey, invocationKey, fwdOpts)
		if decision.Blocked != nil {
			if !decision.Blocked.IsNotification {
				var resp []byte
				if decision.Blocked.SyntheticResponse != nil {
					resp = decision.Blocked.SyntheticResponse
				} else {
					resp = blockRequestResponse(*decision.Blocked)
				}
				if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send block response: %v\n", wErr)
				}
			}
			continue
		}
		if decision.Deferred != nil {
			manager := fwdOpts.deferManager()
			if manager == nil || !manager.Enabled() {
				resp := blockRequestResponse(BlockedRequest{
					ID:             decision.Deferred.ID,
					IsNotification: decision.Deferred.IsNotification,
					ErrorCode:      -32002,
					ErrorMessage:   "pipelock: defer is disabled",
				})
				if !decision.Deferred.IsNotification {
					_ = safeClientOut.WriteMessage(resp)
				}
				continue
			}
			deferredReq := decision.Deferred
			holdErr := manager.Hold(deferred.HeldAction{
				DeferID:    deferredReq.DeferID,
				ActionID:   deferredReq.DeferID,
				Target:     deferredReq.ToolName,
				Reason:     deferredReq.Reason,
				Surface:    opts.Transport,
				Method:     deferredReq.Method,
				SizeBytes:  len(deferredReq.ForwardMessage),
				RulePolicy: deferredReq.ResolutionPolicy,
				Payload:    append([]byte(nil), deferredReq.ForwardMessage...),
				ArgDigest:  deferredReq.ArgDigest,
				Authority: deferred.AuthoritySnapshot{
					SessionID:         deferredReq.SessionID,
					SessionIDOriginal: deferredReq.SessionIDOriginal,
				},
				Resolve: func(res deferred.Resolution) {
					if emitErr := emitDeferredResolutionReceipt(fwdOpts, safeLogW, res); emitErr != nil {
						if !deferredReq.IsNotification {
							_ = safeClientOut.WriteMessage(blockRequestResponse(BlockedRequest{
								ID:           deferredReq.ID,
								ErrorCode:    -32007,
								ErrorMessage: "pipelock: receipt emission failed",
							}))
						}
						return
					}
					switch res.FinalDecision {
					case config.ActionAllow:
						upstreamMu.Lock()
						defer upstreamMu.Unlock()
						if isRequest(deferredReq.ForwardMessage) {
							tracker.Track(deferredReq.ID)
						}
						respReader, sendErr := httpClient.SendMessage(ctx, deferredReq.ForwardMessage)
						if sendErr != nil {
							if !deferredReq.IsNotification {
								_ = safeClientOut.WriteMessage(upstreamErrorResponse(deferredReq.ID, fmt.Errorf("upstream HTTP request failed")))
							}
							return
						}
						respReader = fwdOpts.withResponseTimeout(respReader)
						foundInjection, scanErr := ForwardScanned(respReader, safeClientOut, safeLogW, tracker, fwdOpts)
						if errors.Is(scanErr, transport.ErrResponseTimeout) {
							emitRequestScopedTimeout(
								respReader,
								safeClientOut,
								safeLogW,
								tracker,
								deferredReq.ID,
								"pipelock: upstream response timeout on deferred request; failed request closed",
								fwdOpts,
							)
						} else if scanErr != nil {
							_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
						} else if !foundInjection {
							baselineIdentity := deferredReq.BaselineIdentity
							if baselineIdentity == "" {
								baselineIdentity = mcpFrameBaselineIdentity(ParseMCPFrame(deferredReq.ForwardMessage))
							}
							commitMCPToolCall(baselineMetricsRecorder(fwdOpts, rec), baselineIdentity)
						}
					default:
						if !deferredReq.IsNotification {
							_ = safeClientOut.WriteMessage(blockRequestResponse(BlockedRequest{
								ID:           deferredReq.ID,
								ErrorCode:    -32002,
								ErrorMessage: "pipelock: deferred action denied",
							}))
						}
					}
				},
			})
			if holdErr != nil {
				errorMessage, emitErr := emitHoldFailureResolution(fwdOpts, safeLogW, holdErr, holdFailureResolution{
					DeferID: deferredReq.DeferID,
					Authority: deferred.AuthoritySnapshot{
						SessionID:         deferredReq.SessionID,
						SessionIDOriginal: deferredReq.SessionIDOriginal,
					},
					Policy: manager.Policy(),
					Target: deferredReq.ToolName,
					Method: deferredReq.Method,
					Reason: deferredReq.Reason,
				})
				logHoldFailureReceiptGap(safeLogW, deferredReq.DeferID, emitErr)
				if !deferredReq.IsNotification {
					_ = safeClientOut.WriteMessage(blockRequestResponse(BlockedRequest{
						ID:           deferredReq.ID,
						ErrorCode:    -32002,
						ErrorMessage: errorMessage,
					}))
				}
			} else if held, ok := manager.Held(deferredReq.DeferID); ok && deferredReq.ResolverProfileName != "" {
				maybeStartDeferApprovalResolver(resolverRuntime, manager, held, deferredReq.ResolverProfileName, deferredReq.ResolverProfile, deferredReq.Arguments, fwdOpts.IntegrityCfg, safeLogW)
			}
			continue
		}

		// Track request ID before sending to upstream for confused deputy protection.
		// Only track requests (have "method"), not client responses to
		// server-initiated calls, to prevent tracker pollution.
		if isRequest(msg) {
			if decision.Outcome.Receipt.ActionID != "" {
				tracker.TrackOutcome(frame.ID, decision.Outcome)
			} else {
				tracker.Track(frame.ID)
			}
		}

		if gate, gateErr := evaluateMCPUpstreamGate(ctx, upstreamURL, opts); gateErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream evaluation failed: %v\n", gateErr)
			// Notifications have no id; JSON-RPC forbids responses to
			// them. Mirror the kill-switch and input-scan paths above.
			if isRPCNotification(frame.ID) {
				continue
			}
			errResp := blockRequestResponse(mcpContractBlockRequest(frame.ID, mcpContractGateOutput{}, "pipelock: contract upstream evaluation failed"))
			if wErr := safeClientOut.WriteMessage(errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send contract response: %v\n", wErr)
			}
			emitTrackedTerminalOutcome(safeLogW, tracker, frame.ID, errResp, "upstream_contract", fwdOpts)
			continue
		} else if gate.Verdict == config.ActionBlock {
			if gate.WinningSource == contractruntime.WinningSourceScanner {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream scanner denied: %s\n", gate.Reason)
			} else {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream denied: %s\n", gate.Reason)
			}
			if isRPCNotification(frame.ID) {
				continue
			}
			errResp := blockRequestResponse(mcpContractBlockRequest(frame.ID, gate, "pipelock: upstream URL blocked by live-lock contract"))
			if wErr := safeClientOut.WriteMessage(errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send contract response: %v\n", wErr)
			}
			emitTrackedTerminalOutcome(safeLogW, tracker, frame.ID, errResp, "upstream_contract", fwdOpts)
			continue
		}

		// POST to upstream.
		respReader, err := func() (transport.MessageReader, error) {
			upstreamMu.Lock()
			defer upstreamMu.Unlock()
			return httpClient.SendMessage(ctx, decision.ForwardMessage)
		}()
		if err != nil {
			// SendMessage returns context cancellation/deadline errors as-is
			// and sanitizes upstream request failures/status errors so raw
			// upstream bytes cannot cross this logging boundary.
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			// Send sanitized error to client - don't include upstream body content
			// which could contain prompt injection payloads.
			rpcID := frame.ID
			errResp := upstreamErrorResponse(rpcID, fmt.Errorf("upstream HTTP request failed"))
			if wErr := safeClientOut.WriteMessage(errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send error response: %v\n", wErr)
			}
			emitTrackedTerminalOutcome(safeLogW, tracker, frame.ID, errResp, "upstream_error", fwdOpts)
			continue
		}

		// Scan and forward response. Apply the optional per-read response
		// timeout (no-op when disabled) so a hung HTTP upstream fails closed.
		respReader = fwdOpts.withResponseTimeout(respReader)
		foundInjection, scanErr := ForwardScanned(respReader, safeClientOut, safeLogW, tracker, fwdOpts)
		if errors.Is(scanErr, transport.ErrResponseTimeout) {
			emitRequestScopedTimeout(
				respReader,
				safeClientOut,
				safeLogW,
				tracker,
				frame.ID,
				"pipelock: upstream response timeout; failed request closed, session continues",
				fwdOpts,
			)
			lastScanErr = scanErr
			continue
		}
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
			emitTrackedIncompleteOutcome(safeLogW, tracker, frame.ID, "scan_error", fwdOpts)
			lastScanErr = scanErr
		} else if !foundInjection {
			commitMCPToolCall(baselineMetricsRecorder(fwdOpts, rec), mcpFrameBaselineIdentity(frame))
		}

		// After first successful response with a session ID, start GET stream
		// for server-initiated messages. Check session ID OUTSIDE the Once so
		// that early responses without a session ID (e.g. 202) don't consume
		// the Once and permanently prevent the GET stream.
		if httpClient.SessionID() != "" {
			getStreamOnce.Do(func() {
				startGETStream(ctx, httpClient, safeClientOut, safeLogW, fwdOpts, &wg)
			})
		}
	}

	// Terminate session if established.
	if httpClient.SessionID() != "" {
		httpClient.DeleteSession(safeLogW)
	}

	// Stop GET stream and wait for it to finish.
	cancel()
	wg.Wait()
	emitPendingIncompleteOutcomes(safeLogW, tracker, fwdOpts, "upstream_closed")

	return lastScanErr
}
