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
	"net"
	"net/http"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// newReverseUpstreamTransport builds the HTTP transport the MCP HTTP listener
// uses to reach its configured upstream. It clones http.DefaultTransport for
// sane pool/timeout defaults, then sets two invariants:
//
//   - DisableCompression: true so the upstream's Content-Encoding survives
//     transparent-decompression stripping. The listener forwards bodies to the
//     scanner, and a gzip'd upstream response would otherwise reach the
//     scanner's compressed-content guard with the encoding header already
//     removed (same root cause as the forward and reverse transport fixes).
//   - Proxy: nil so an ambient HTTP_PROXY/HTTPS_PROXY cannot silently redirect
//     egress to the configured upstream and route around the redirect-disabled
//     SSRF posture at the call site. Matches the parity of the forward,
//     reverse, and TLS-intercept transports, which all dial the configured
//     upstream directly with a nil Proxy.
func newReverseUpstreamTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DisableCompression = true
	t.Proxy = nil
	return t
}

// RunHTTPListenerProxy starts an HTTP server that reverse-proxies MCP requests
// to an upstream server with bidirectional scanning. Each inbound POST is
// independently scanned and forwarded. Mcp-Session-Id and Authorization headers
// pass through transparently; the upstream owns session lifecycle.
//
// The caller is responsible for creating the net.Listener (via net.Listen or
// net.ListenConfig). This separates the bind step from serving, so callers
// detect port conflicts synchronously instead of losing them inside a goroutine.
//
// When store is non-nil, per-request session recorders are created using the
// Mcp-Session-Id header (or RemoteAddr fallback) as the session key, enabling
// adaptive enforcement signal tracking per logical MCP session.
//
// Endpoints:
//   - POST / : scan and forward JSON-RPC requests to upstream
//   - GET /health : returns 200 OK for liveness probes
func RunHTTPListenerProxy(
	ctx context.Context,
	ln net.Listener,
	upstreamURL string,
	logW io.Writer,
	opts MCPProxyOpts,
) error {
	safeLogW := &syncWriter{w: logW}
	if opts.ContractServer == "" {
		opts.ContractServer = mcpContractServerFromUpstream(upstreamURL)
	}
	if gate, gateErr := evaluateMCPUpstreamGate(ctx, upstreamURL, opts); gateErr != nil {
		return fmt.Errorf("contract upstream evaluation: %w", gateErr)
	} else if gate.Verdict == config.ActionBlock {
		return fmt.Errorf("contract upstream denied: %s", mcpContractBlockReason(gate))
	}

	// Shared tool baseline across all requests for drift detection and
	// session binding. It intentionally survives hot reloads for the
	// lifetime of this listener; reload updates policy knobs, not the
	// listener's observed tool inventory.
	toolBaseline := tools.NewToolBaseline()
	// driftEdge detects detect_drift false→true transitions. When
	// detect_drift transitions false→true via hot reload, the drift maps
	// retained from before the disabled window are stale relative to the
	// upstream's current tool inventory; ResetDriftState forces a re-seed
	// on the next tools/list so post-flip traffic is evaluated against the
	// new ground truth rather than pre-disable hashes. Other transitions
	// are no-ops: true→true preserves a legitimate baseline, true→false
	// leaves the maps intact so a subsequent re-enable can still detect
	// drift across short toggles, false→false stays empty.
	var driftEdge tools.DetectDriftRisingEdge
	toolCfgFn := func() *tools.ToolScanConfig {
		cfg := opts.toolCfg()
		if cfg == nil || cfg.Action == "" {
			return nil
		}
		if driftEdge.Observe(cfg.DetectDrift) {
			toolBaseline.ResetDriftState()
		}
		return &tools.ToolScanConfig{
			Baseline:                toolBaseline,
			Action:                  cfg.Action,
			DetectDrift:             cfg.DetectDrift,
			BindingUnknownAction:    cfg.BindingUnknownAction,
			BindingNoBaselineAction: cfg.BindingNoBaselineAction,
			ExtraPoison:             cfg.ExtraPoison,
		}
	}

	// Base opts shared across requests. Per-request fields (Rec) are
	// overridden on a copy inside each request handler. The static
	// Redact{Matcher,Limits,Profile} fields are fallbacks for direct
	// callers that bypass RedactionCfgFn; resolve the current snapshot
	// once here so we do not re-run opts.redactionConfig() three times.
	baseRedactionCfg := opts.redactionConfig()
	baseOpts := MCPProxyOpts{
		Scanner:                  opts.scanner(),
		ScannerFn:                opts.ScannerFn,
		Approver:                 opts.Approver,
		InputCfg:                 opts.inputCfg(),
		InputCfgFn:               opts.InputCfgFn,
		ToolCfg:                  toolCfgFn(),
		ToolCfgFn:                toolCfgFn,
		PolicyCfg:                opts.policyCfg(),
		PolicyCfgFn:              opts.PolicyCfgFn,
		KillSwitch:               opts.KillSwitch,
		ChainMatcher:             opts.chainMatcher(),
		ChainMatcherFn:           opts.ChainMatcherFn,
		AuditLogger:              opts.AuditLogger,
		CEE:                      opts.cee(),
		CEEFn:                    opts.CEEFn,
		Metrics:                  opts.Metrics,
		RedirectRT:               opts.redirectRT(),
		RedirectRTFn:             opts.RedirectRTFn,
		Transport:                "mcp_http_listener",
		ReceiptEmitter:           opts.receiptEmitter(),
		ReceiptEmitterFn:         opts.ReceiptEmitterFn,
		V2ReceiptEmitter:         opts.v2ReceiptEmitter(),
		V2ReceiptEmitterFn:       opts.V2ReceiptEmitterFn,
		PolicyHash:               opts.receiptPolicyHash(),
		PolicyHashFn:             opts.PolicyHashFn,
		ContractLoader:           opts.ContractLoader,
		ContractLoaderPtr:        opts.ContractLoaderPtr,
		ContractLoaderFn:         opts.ContractLoaderFn,
		ContractAgent:            opts.ContractAgent,
		ContractServer:           opts.ContractServer,
		CaptureObs:               opts.captureObserver(),
		ConfigHash:               opts.captureConfigHash(),
		ConfigHashFn:             opts.ConfigHashFn,
		AddressProtectionAgent:   opts.addressProtectionAgent(),
		AddressProtectionAgentFn: opts.AddressProtectionAgentFn,
		Profile:                  opts.captureProfile(),
		ProfileFn:                opts.ProfileFn,
		ProvenanceCfg:            opts.provenanceCfg(),
		ProvenanceCfgFn:          opts.ProvenanceCfgFn,
		RedactMatcher:            baseRedactionCfg.Matcher,
		RedactLimits:             baseRedactionCfg.Limits,
		RedactProfile:            baseRedactionCfg.Profile,
		RedactionCfgFn:           opts.RedactionCfgFn,
		DoWCheck:                 opts.DoWCheck,
		A2ACfg:                   opts.a2aCfg(),
		A2ACfgFn:                 opts.A2ACfgFn,
		MediaPolicy:              opts.mediaPolicy(),
		MediaPolicyFn:            opts.MediaPolicyFn,
		TaintCfg:                 opts.taintCfg(),
		TaintCfgFn:               opts.TaintCfgFn,
		TaintExternalSource:      true,
		EnvelopeEmitter:          opts.envelopeEmitter(),
		EnvelopeEmitterFn:        opts.EnvelopeEmitterFn,
	}

	// Shared HTTP client for upstream requests. Redirect-following is disabled
	// to prevent SSRF via crafted Location headers from the upstream.
	// 30s timeout prevents hanging on unresponsive upstreams.
	//
	// Envelope-refresh implication: because redirects never follow,
	// the mediation envelope signing refresh path that lives at
	// internal/proxy/proxy.go:348 (CheckRedirect) is moot for the
	// MCP HTTP transport - there is no second hop to rebuild an
	// envelope over. If a future change enables redirect following
	// here (for example, to support upstream servers that relocate
	// endpoints) the refresh helper must be wired into the new
	// CheckRedirect closure so signed envelopes do not flow with
	// stale @target-uri / ph / hop values. The same applies to
	// internal/mcp/transport/httpclient.go:45.
	upstreamClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: newReverseUpstreamTransport(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			info := blockreason.MustNew(blockreason.BadRequest, blockreason.SeverityInfo, blockreason.RetryNone)
			info.SetHeaders(w.Header())
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Resolve adaptive config per-request so hot-reloads take effect
		// without restarting the long-lived listener.
		adaptiveCfg := opts.adaptiveCfg()
		reqScanner := baseOpts.scanner()
		reqA2ACfg := baseOpts.a2aCfg()

		// Cap request body to prevent memory exhaustion.
		r.Body = http.MaxBytesReader(w, r.Body, int64(transport.MaxLineSize))
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			// MaxBytesReader is the only ReadAll failure that means
			// "body exceeded the limit"; truncated chunked bodies and
			// client disconnects must report 400 so dashboards do not
			// over-count 413s as oversize abuse.
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("request body too large")))
			} else {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("request body read failed")))
			}
			return
		}

		body = bytes.TrimSpace(body)
		if len(body) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("empty request body")))
			return
		}

		// Reject malformed JSON early. Without this, invalid payloads
		// reach scanHTTPInput where parse errors may be treated as
		// notifications (202 with no body), silently dropping the error.
		// Uses JSON-RPC 2.0 standard code -32700 (Parse error).
		if !json.Valid(body) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			parseErr, _ := json.Marshal(rpcError{
				JSONRPC: jsonrpc.Version,
				Error:   rpcErrorDetail{Code: -32700, Message: "pipelock: parse error: invalid JSON"},
			})
			_, _ = w.Write(parseErr)
			return
		}

		// Parse the inbound frame once per request. Every rpcID lookup
		// and upstream-error response below reads frame.ID instead of
		// re-parsing the body bytes.
		frame := ParseMCPFrame(body)

		// Validate JSON-RPC 2.0 structure for single requests: version
		// must be "2.0", method must be present and a string. Batch
		// requests (JSON arrays) are validated per-element by scanHTTPInput.
		// Uses JSON-RPC 2.0 standard code -32600 (Invalid Request).
		if body[0] != '[' {
			if reason := validateRPCStructure(body); reason != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				rpcID := frame.ID
				invalidReq, _ := json.Marshal(rpcError{
					JSONRPC: jsonrpc.Version,
					ID:      rpcID,
					Error:   rpcErrorDetail{Code: -32600, Message: "pipelock: invalid request: " + reason},
				})
				_, _ = w.Write(invalidReq)
				return
			}
		}

		// Kill switch: deny all requests when active.
		if opts.KillSwitch != nil {
			if d := opts.KillSwitch.IsActiveMCP(body); d.Active {
				w.Header().Set("Content-Type", "application/json")
				if d.IsNotification {
					w.WriteHeader(http.StatusAccepted)
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					return
				}
				rpcID := frame.ID
				_, _ = w.Write(killswitch.ErrorResponse(rpcID, d.Message))
				return
			}
		}

		// Use Mcp-Session-Id header as chain detection session key so
		// concurrent clients don't share tool call history. When no
		// session ID is present, fall back to the client IP (without
		// port) so all requests from the same agent share chain history
		// even across separate TCP connections.
		chainSessionKey := r.Header.Get("Mcp-Session-Id")
		auditSessionKey := chainSessionKey
		if chainSessionKey == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			chainSessionKey = host
			// Hash the IP for audit logs to avoid persisting raw client
			// addresses in a field that bypasses report IP redaction.
			auditSessionKey = hashSessionKey(host)
		}

		// Per-request adaptive enforcement recorder. Uses RemoteAddr (without
		// port) as a stable session key: the first request has no Mcp-Session-Id
		// yet, so using the chain key would split signals across two keys (IP
		// for first request, session ID for subsequent ones).
		var reqRec session.Recorder
		if opts.Store != nil {
			adaptiveHost, _, adaptiveErr := net.SplitHostPort(r.RemoteAddr)
			if adaptiveErr != nil {
				adaptiveHost = r.RemoteAddr
			}
			reqRec = opts.Store.GetOrCreate(adaptiveHost)
		}

		warnCtx := scanner.DLPWarnContextFromCtx(r.Context())
		if warnCtx.Transport == "" {
			warnCtx.Transport = baseOpts.Transport
		}
		warnCtx.Method = mcpWarnMethod
		warnCtx.Resource = r.URL.Path
		if warnCtx.ClientIP == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			warnCtx.ClientIP = host
		}
		httpWarnCtx := scanner.WithDLPWarnContext(r.Context(), warnCtx)
		r = r.WithContext(httpWarnCtx)

		// Scan configured sensitive listener headers for DLP patterns. The
		// body scanner doesn't see HTTP headers, so an agent could leak
		// credentials via MCP listener headers without triggering DLP.
		if headerResult := scanMCPListenerHeadersForDLP(r.Context(), r.Header, reqScanner, opts.requestBodyCfg()); headerResult != nil {
			pattern := patternUnknown
			if len(headerResult.matches) > 0 {
				pattern = headerResult.matches[0].PatternName
			}
			_, _ = fmt.Fprintf(safeLogW, "pipelock: DLP match in %s header: %s\n", headerResult.header, pattern)
			if adaptiveCfg != nil && adaptiveCfg.Enabled {
				decide.RecordSignal(reqRec, session.SignalBlock, decide.EscalationParams{
					Threshold:     adaptiveCfg.EscalationThreshold,
					Logger:        opts.AuditLogger,
					Metrics:       opts.Metrics,
					ConsoleWriter: safeLogW,
					Session:       auditSessionKey,
				})
			}
			w.Header().Set("Content-Type", "application/json")
			rpcID := frame.ID
			resp, _ := json.Marshal(rpcError{
				JSONRPC: jsonrpc.Version,
				ID:      rpcID,
				Error:   rpcErrorDetail{Code: -32001, Message: "pipelock: request blocked by MCP input scanning"},
			})
			_, _ = w.Write(resp)
			return
		}

		// A2A-Extensions header scanning: each comma-separated URI is
		// SSRF-scanned. A2A-Version is informational and passes through
		// without scanning.
		if reqA2ACfg != nil && reqA2ACfg.Enabled {
			headerResult := ScanA2AHeaders(r.Context(), r.Header, reqScanner, reqA2ACfg)
			if !headerResult.Clean {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: a2a header blocked: %s\n", headerResult.Reason)
				if adaptiveCfg != nil && adaptiveCfg.Enabled {
					ep := decide.EscalationParams{
						Threshold:     adaptiveCfg.EscalationThreshold,
						Logger:        opts.AuditLogger,
						Metrics:       opts.Metrics,
						ConsoleWriter: safeLogW,
						Session:       auditSessionKey,
					}
					switch {
					case headerResult.IsAdaptiveNeutral():
						// Score-neutral: infrastructure errors in A2A headers
						// (e.g., DNS timeout resolving an Extensions URL) are
						// not evidence of agent misbehavior.
					case headerResult.IsConfigMismatch():
						decide.RecordSignal(reqRec, session.SignalNearMiss, ep)
					default:
						decide.RecordSignal(reqRec, session.SignalBlock, ep)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				rpcID := frame.ID
				resp, _ := json.Marshal(rpcError{
					JSONRPC: jsonrpc.Version,
					ID:      rpcID,
					Error:   rpcErrorDetail{Code: -32001, Message: "pipelock: request blocked by A2A header scanning"},
				})
				_, _ = w.Write(resp)
				return
			}
		}

		// Input scanning: DLP, injection, policy, chain detection.
		scanOpts := baseOpts
		scanOpts.Rec = reqRec
		scanOpts.AdaptiveCfg = adaptiveCfg
		scanOpts.AdaptiveCfgFn = nil
		scanOpts.WarnContext = r.Context()
		decision := scanHTTPInputDecision(body, safeLogW, chainSessionKey, auditSessionKey, scanOpts)
		if blocked := decision.Blocked; blocked != nil {
			w.Header().Set("Content-Type", "application/json")
			if blocked.IsNotification {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			if blocked.SyntheticResponse != nil {
				_, _ = w.Write(blocked.SyntheticResponse)
			} else {
				_, _ = w.Write(blockRequestResponse(*blocked))
			}
			return
		}

		if gate, gateErr := evaluateMCPUpstreamGate(r.Context(), upstreamURL, scanOpts); gateErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream evaluation failed: %v\n", gateErr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(blockRequestResponse(mcpContractBlockRequest(frame.ID, mcpContractGateOutput{}, "pipelock: contract upstream evaluation failed")))
			return
		} else if gate.Verdict == config.ActionBlock {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream denied: %s\n", gate.Reason)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(blockRequestResponse(mcpContractBlockRequest(frame.ID, gate, "pipelock: upstream URL blocked by live-lock contract")))
			return
		}

		// Build upstream request with passthrough headers.
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, bytes.NewReader(decision.ForwardMessage))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("upstream HTTP request failed")))
			return
		}
		upReq.Header.Set("Content-Type", "application/json")
		upReq.Header.Set("Accept", "application/json, text/event-stream")

		if auth := r.Header.Get("Authorization"); auth != "" {
			upReq.Header.Set("Authorization", auth)
		}
		if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
			upReq.Header.Set("Mcp-Session-Id", sid)
		}

		// Forward A2A service parameter headers to upstream.
		// A2A-Extensions carries negotiated extension URIs (already scanned above).
		// A2A-Version carries protocol version (informational, no scanning needed).
		if ext := r.Header.Get("A2A-Extensions"); ext != "" {
			upReq.Header.Set("A2A-Extensions", ext)
		}
		if ver := r.Header.Get("A2A-Version"); ver != "" {
			upReq.Header.Set("A2A-Version", ver)
		}

		upResp, err := upstreamClient.Do(upReq)
		if err != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("upstream HTTP request failed")))
			return
		}
		defer func() { _ = upResp.Body.Close() }()

		// 202 Accepted: notification acknowledged, no body.
		if upResp.StatusCode == http.StatusAccepted {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		// Upstream error: sanitize before forwarding (don't leak body content
		// that could contain injection payloads).
		if upResp.StatusCode >= 400 {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream HTTP %d\n", upResp.StatusCode)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("upstream HTTP request failed")))
			return
		}

		// Fail closed on compressed upstream bodies before wrapping in
		// SingleMessageReader. ForwardScanned only ever sees the reader,
		// so a gzip/br/zstd response would be fed to the body scanners as
		// opaque bytes and silently bypass detection. DisableCompression on
		// upstreamTransport leaves the encoding header in place, so this
		// guard is authoritative; the same fail-closed pattern lives in
		// internal/proxy/forward.go and reverse.go, completing transport
		// parity for compressed responses on the MCP HTTP listener.
		if hasNonIdentityEncoding(upResp.Header.Get("Content-Encoding")) {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: blocking compressed upstream response (Content-Encoding=%q)\n", upResp.Header.Get("Content-Encoding"))
			info, err := blockreason.New(blockreason.CompressedResponse, blockreason.SeverityWarn, blockreason.RetryPolicy)
			if err == nil {
				if withLayer, layerErr := info.WithLayer("response_scan"); layerErr == nil {
					info = withLayer
				}
			} else {
				info = blockreason.MustNew(blockreason.ParseError, blockreason.SeverityWarn, blockreason.RetryNone)
			}
			info.SetHeaders(w.Header())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("compressed response cannot be scanned")))
			return
		}

		// Route the upstream body reader by Content-Type. The MCP Streamable
		// HTTP spec lets servers respond with either application/json (single
		// JSON-RPC message in body) or text/event-stream (one or more
		// JSON-RPC messages framed as SSE data: events). Without the SSE
		// branch, ForwardScanned feeds raw `data: ...\n\n` bytes to the
		// JSON-RPC parser and emits "upstream response is not parseable
		// JSON-RPC" on every SSE upstream. The stdio-to-HTTP path
		// (transport.HTTPClient.SendMessage) already does this routing at
		// internal/mcp/transport/httpclient.go; this listener has its own
		// hand-rolled HTTP request loop and so has to do it inline.
		//
		// nil tracker: HTTP reverse proxy pairs each request/response via HTTP
		// semantics, so confused deputy tracking is handled at the transport level.
		upstreamCT := upResp.Header.Get("Content-Type")
		upstreamIsSSE := isSSEContentType(upstreamCT)
		var reader transport.MessageReader
		if upstreamIsSSE {
			reader = transport.NewSSEReader(upResp.Body)
		} else {
			reader = &transport.SingleMessageReader{Body: upResp.Body}
		}
		var buf bytes.Buffer
		bufWriter := &syncWriter{w: &buf}
		reqOpts := baseOpts
		reqOpts.Rec = reqRec
		reqOpts.AdaptiveCfg = adaptiveCfg
		reqOpts.AdaptiveCfgFn = nil

		// Pass Mcp-Session-Id from upstream back to client.
		if sid := upResp.Header.Get("Mcp-Session-Id"); sid != "" {
			w.Header().Set("Mcp-Session-Id", sid)
		}

		// Re-frame the response to match the upstream wire format. When the
		// upstream emitted SSE, write each scanned message as an SSE data event
		// immediately so streaming notifications reach the agent without
		// waiting for upstream EOF. When the upstream emitted application/json
		// the buffer holds a single message and is forwarded verbatim below.
		if upstreamIsSSE {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			streamWriter := &sseMessageWriter{w: w}
			if flusher, ok := w.(http.Flusher); ok {
				streamWriter.flusher = flusher
			}
			_, scanErr := ForwardScanned(reader, streamWriter, safeLogW, nil, reqOpts)
			if scanErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
			}
			// Fail closed when the SSE pipeline errored before the first
			// event was written. Returning 202 here would let an oversized
			// or malformed upstream stream look like a successful
			// notification ack to the client. Headers are still mutable
			// because sseMessageWriter never wrote, so override the SSE
			// content-type set above with the standard application/json
			// upstream-error envelope.
			if scanErr != nil && !streamWriter.Wrote() {
				w.Header().Del("Cache-Control")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("upstream SSE response failed validation")))
				return
			}
			if !streamWriter.Wrote() {
				w.WriteHeader(http.StatusAccepted)
			}
			return
		}
		_, scanErr := ForwardScanned(reader, bufWriter, safeLogW, nil, reqOpts)
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
		}
		w.Header().Set("Content-Type", "application/json")
		output := bytes.TrimSpace(buf.Bytes())
		if len(output) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = w.Write(output)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on context cancellation.
	go func() { //nolint:gosec // G118: graceful shutdown after <-ctx.Done(); using ctx as parent would skip the grace period
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx) //nolint:errcheck // best-effort shutdown
	}()

	_, _ = fmt.Fprintf(safeLogW, "pipelock: MCP reverse proxy listening on %s\n", ln.Addr())

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP listener: %w", err)
	}
	return nil
}
