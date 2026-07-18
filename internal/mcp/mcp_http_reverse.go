// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

const listenerProxyAuthorization = "Proxy-Authorization"

const (
	listenerAuthorization      = "Authorization"
	listenerLastEventID        = "Last-Event-ID"
	listenerProtocolVersion    = "Mcp-Protocol-Version"
	listenerCORSAllowedHeaders = "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, A2A-Extensions, A2A-Version, Last-Event-ID"
)

type mcpListenerBlockDecision struct {
	reason          blockreason.Reason
	headerSeverity  blockreason.Severity
	retry           blockreason.Retry
	layer           string
	pattern         string
	target          string
	receiptSeverity string
	mutateReceipt   func(receipt.EmitOpts) receipt.EmitOpts
}

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
	opts.UpstreamHeaders = canonicalizeListenerUpstreamHeaders(opts.UpstreamHeaders)
	if err := validateListenerBearerToken(opts.ListenerBearerToken); err != nil {
		return err
	}
	if err := validateListenerUpstreamHeaders(opts.UpstreamHeaders); err != nil {
		return err
	}
	allowedOrigins, err := normalizeListenerOrigins(opts.ListenerAllowedOrigins)
	if err != nil {
		return err
	}
	opts.ListenerAllowedOrigins = allowedOrigins
	if !listenerIsLoopback(ln) && opts.ListenerBearerToken == "" && !opts.ListenerAllowUnauthenticated {
		return fmt.Errorf("non-loopback MCP listener requires bearer authentication or explicit unauthenticated acknowledgement")
	}
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
		Store:                    opts.Store,
		Baseline:                 opts.Baseline,
		BaselineFn:               opts.BaselineFn,
		AuditLogger:              opts.AuditLogger,
		CEE:                      opts.cee(),
		CEEFn:                    opts.CEEFn,
		Metrics:                  opts.Metrics,
		RedirectRT:               opts.redirectRT(),
		RedirectRTFn:             opts.RedirectRTFn,
		Transport:                "mcp_http_listener",
		ReceiptEmitter:           opts.receiptEmitter(),
		ReceiptEmitterFn:         opts.ReceiptEmitterFn,
		RequireReceipts:          opts.requireReceipts(),
		RequireReceiptsFn:        opts.RequireReceiptsFn,
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
		ServerName:               opts.ServerName,
		Suppress:                 opts.Suppress,
		SuppressFn:               opts.SuppressFn,
		ResponseTrustClass:       opts.ResponseTrustClass,
		ResponseTrustClassFn:     opts.ResponseTrustClassFn,
		ResponseActionOverride:   opts.ResponseActionOverride,
		ResponseActionOverrideFn: opts.ResponseActionOverrideFn,
		TaintCfg:                 opts.taintCfg(),
		TaintCfgFn:               opts.TaintCfgFn,
		TaintExternalSource:      true,
		TaintTrustedSource:       opts.TaintTrustedSource,
		TaintTrustedSourceFn:     opts.TaintTrustedSourceFn,
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
	upstreamStreamTransport := newReverseUpstreamTransport()
	upstreamStreamTransport.ResponseHeaderTimeout = 30 * time.Second
	upstreamStreamClient := &http.Client{
		Timeout:       0,
		Transport:     upstreamStreamTransport,
		CheckRedirect: upstreamClient.CheckRedirect,
	}

	loopbackListener := listenerIsLoopback(ln)
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if loopbackListener && opts.ListenerBearerToken == "" && opts.ListenerBearerTokenFn == nil &&
			!listenerLoopbackHostAllowed(r.Host, ln.Addr()) {
			http.Error(w, "host not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !listenerOriginAllowed(r.Header.Values("Origin"), opts.ListenerAllowedOrigins) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			setListenerCORSHeaders(w.Header(), origin)
			if r.Method == http.MethodOptions {
				if !listenerCORSPreflightAllowed(r) {
					http.Error(w, "CORS preflight not allowed", http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		listenerToken, tokenErr := listenerBearerTokenForRequest(opts)
		if tokenErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: listener credential refresh failed: %v\n", tokenErr)
			http.Error(w, "listener authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		// A loopback bind is not an authentication boundary when a browser can
		// reach it through a DNS-rebound hostname. Tokenless loopback listeners
		// accept only literal loopback authorities or localhost on the actual
		// bound port. Authenticated listeners may use deployment-specific names.
		if loopbackListener && listenerToken == "" && !listenerLoopbackHostAllowed(r.Host, ln.Addr()) {
			http.Error(w, "host not allowed", http.StatusForbidden)
			return
		}
		consumedAuthHeader, authorized := listenerBearerAuthHeader(r.Header, listenerToken)
		if listenerToken != "" && !authorized {
			w.Header().Set("Proxy-Authenticate", `Bearer realm="pipelock-mcp"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		// The listener credential is an access-control secret, not agent data
		// destined for the upstream. Remove it before header DLP and forwarding:
		// otherwise credential-shaped listener tokens block their own valid
		// requests, and Authorization-based browser auth could leak upstream.
		//
		// Deleting only the header that happened to authenticate is not enough. A
		// client may present the listener token in BOTH headers; the consumed one
		// is dropped and the other is forwarded upstream, leaking the credential.
		// Proxy-Authorization is hop-by-hop (RFC 7235 s4.4) and must never be
		// forwarded regardless of the auth outcome, so drop it unconditionally,
		// and scrub Authorization whenever it also carries the listener token.
		r.Header.Del(listenerProxyAuthorization)
		if consumedAuthHeader != "" {
			r.Header.Del(consumedAuthHeader)
		}
		if listenerToken != "" && listenerBearerAnyValueMatches(r.Header.Values(listenerAuthorization), listenerToken) {
			r.Header.Del(listenerAuthorization)
		}
		// Normalize policy-bearing service headers to the operator-pinned values
		// before validation and A2A scanning. Otherwise an ignored client override
		// can still trigger a rejection or be scanned while a different value is
		// forwarded, making the security log describe bytes the upstream never saw.
		applyOperatorPinnedServiceHeaders(r.Header, opts.UpstreamHeaders)
		methodNotAllowed := func() {
			// RFC 9110 requires a 405 to advertise the methods the listener accepts.
			w.Header().Set("Allow", strings.Join([]string{
				http.MethodPost,
				http.MethodGet,
				http.MethodDelete,
				http.MethodOptions,
			}, ", "))
			info := blockreason.MustNew(blockreason.BadRequest, blockreason.SeverityInfo, blockreason.RetryNone)
			info.SetHeaders(w.Header())
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		if !validMCPSessionID(r.Header.Values("Mcp-Session-Id")) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("invalid Mcp-Session-Id header")))
			return
		}
		if !validMCPProtocolVersion(r.Header.Values(listenerProtocolVersion)) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("invalid Mcp-Protocol-Version header")))
			return
		}
		if !validA2AVersion(r.Header.Values("A2A-Version")) ||
			!validA2AExtensions(r.Header.Values("A2A-Extensions")) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("invalid or duplicate A2A service header")))
			return
		}

		// Resolve adaptive config per-request so hot-reloads take effect
		// without restarting the long-lived listener.
		adaptiveCfg := opts.adaptiveCfg()
		reqScanner := baseOpts.scanner()
		if reqScanner == nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scanner unavailable\n")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			resp, _ := json.Marshal(rpcError{
				JSONRPC: jsonrpc.Version,
				Error:   rpcErrorDetail{Code: -32003, Message: "pipelock: scanner unavailable"},
			})
			_, _ = w.Write(resp)
			return
		}
		requestBaseOpts := baseOpts
		requestBaseOpts.Scanner = reqScanner
		requestBaseOpts.ScannerFn = nil
		reqA2ACfg := requestBaseOpts.a2aCfg()
		emitListenerBlockDecision := func(dec mcpListenerBlockDecision) {
			actionID := receipt.NewActionID()
			receiptOpts := requestBaseOpts.withReceiptPolicyHash(receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     dec.layer,
				Pattern:   dec.pattern,
				Severity:  dec.receiptSeverity,
				Transport: requestBaseOpts.Transport,
				Target:    dec.target,
			})
			if dec.mutateReceipt != nil {
				receiptOpts = dec.mutateReceipt(receiptOpts)
			}
			receiptEmitted := false
			emitter := requestBaseOpts.receiptEmitter()
			v2Emitter := requestBaseOpts.v2ReceiptEmitter()
			if emitter != nil || v2Emitter != nil || requestBaseOpts.requireReceipts() {
				if _, emitErr := EmitMCPDecision(emitter, v2Emitter, nil, MCPDecision{
					Receipt:        receiptOpts,
					RequireReceipt: requestBaseOpts.requireReceipts(),
				}); emitErr != nil {
					logReceiptEmitFailure(safeLogW, emitErr, requestBaseOpts.requireReceipts(), config.ActionBlock)
				} else if emitter != nil || v2Emitter != nil {
					receiptEmitted = true
				}
			}

			info := blockreason.MustNew(dec.reason, dec.headerSeverity, dec.retry)
			if dec.layer != "" {
				if withLayer, layerErr := info.WithLayer(dec.layer); layerErr == nil {
					info = withLayer
				}
			}
			if receiptEmitted {
				if withReceipt, receiptErr := info.WithReceipt(actionID); receiptErr == nil {
					info = withReceipt
				}
			}
			info.SetHeaders(w.Header())
		}
		blockedByUpstreamContract := func(rpcID json.RawMessage, gateOpts MCPProxyOpts) bool {
			if gate, gateErr := evaluateMCPUpstreamGateForMethod(r.Context(), upstreamURL, r.Method, gateOpts); gateErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream evaluation failed: %v\n", gateErr)
				emitListenerBlockDecision(mcpListenerBlockDecision{
					reason:          blockreason.ParseError,
					headerSeverity:  blockreason.SeverityCritical,
					retry:           blockreason.RetryNone,
					layer:           "mcp_contract",
					pattern:         "contract_upstream_evaluation_failed",
					target:          "mcp:contract:upstream",
					receiptSeverity: config.SeverityHigh,
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(blockRequestResponse(mcpContractBlockRequest(rpcID, mcpContractGateOutput{}, "pipelock: contract upstream evaluation failed")))
				return true
			} else if gate.Verdict == config.ActionBlock {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream denied: %s\n", gate.Reason)
				emitListenerBlockDecision(mcpListenerBlockDecision{
					reason:          mcpContractBlockReason(gate),
					headerSeverity:  blockreason.SeverityCritical,
					retry:           blockreason.RetryNone,
					layer:           "mcp_contract",
					pattern:         firstNonEmpty(gate.Reason, "contract_upstream_denied"),
					target:          "mcp:contract:upstream",
					receiptSeverity: config.SeverityHigh,
					mutateReceipt: func(opts receipt.EmitOpts) receipt.EmitOpts {
						return mcpWithContractReceipt(opts, gate)
					},
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(blockRequestResponse(mcpContractBlockRequest(rpcID, gate, "pipelock: upstream URL blocked by live-lock contract")))
				return true
			}
			return false
		}

		// GET and DELETE forward client Authorization / A2A headers to the
		// upstream, so the configured sensitive-header DLP scan that the POST
		// path runs must also run here. Otherwise an agent could leak a
		// credential-shaped header to the upstream by choosing GET or DELETE
		// over POST to dodge header DLP.
		blockedByForwardedHeaderDLP := func() bool {
			headerResult := scanMCPListenerHeadersForDLP(r.Context(), r.Header, reqScanner, opts.requestBodyCfg())
			if headerResult == nil {
				return false
			}
			pattern := patternUnknown
			if len(headerResult.matches) > 0 {
				pattern = headerResult.matches[0].PatternName
			}
			_, _ = fmt.Fprintf(safeLogW, "pipelock: DLP match in %s header: %s\n", headerResult.header, pattern)
			emitListenerBlockDecision(mcpListenerBlockDecision{
				reason:          blockreason.DLPMatch,
				headerSeverity:  blockreason.SeverityCritical,
				retry:           blockreason.RetryNone,
				layer:           mcpReceiptLayerInput,
				pattern:         pattern,
				target:          "mcp:listener-header:" + http.CanonicalHeaderKey(headerResult.header),
				receiptSeverity: config.SeverityHigh,
			})
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal(rpcError{
				JSONRPC: jsonrpc.Version,
				Error:   rpcErrorDetail{Code: -32001, Message: "pipelock: request blocked by MCP input scanning"},
			})
			_, _ = w.Write(resp)
			return true
		}
		blockedByA2AHeaders := func() bool {
			if reqA2ACfg == nil || !reqA2ACfg.Enabled {
				return false
			}
			headerResult := ScanA2AHeaders(r.Context(), r.Header, reqScanner, reqA2ACfg)
			if headerResult.Clean {
				return false
			}
			if headerResult.IsInfrastructureError() {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: a2a header scan infrastructure error: %s\n", headerResult.Reason)
			} else {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: a2a header blocked: %s\n", headerResult.Reason)
			}
			emitListenerBlockDecision(mcpListenerBlockDecision{
				reason:          a2aHeaderBlockReason(headerResult),
				headerSeverity:  blockreason.SeverityCritical,
				retry:           blockreason.RetryNone,
				layer:           mcpReceiptLayerA2A,
				pattern:         firstNonEmpty(headerResult.Reason, mcpReceiptA2AHeaderPattern),
				target:          mcpReceiptA2AHeaderTarget,
				receiptSeverity: config.SeverityHigh,
			})
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal(rpcError{
				JSONRPC: jsonrpc.Version,
				Error:   rpcErrorDetail{Code: -32001, Message: "pipelock: request blocked by A2A header scanning"},
			})
			_, _ = w.Write(resp)
			return true
		}

		if r.Method == http.MethodGet {
			if !acceptAllowsSSE(r.Header.Values("Accept")) {
				methodNotAllowed()
				return
			}
			if !validLastEventIDHeader(r.Header.Values(listenerLastEventID), 256) {
				info := blockreason.MustNew(blockreason.BadRequest, blockreason.SeverityInfo, blockreason.RetryNone)
				info.SetHeaders(w.Header())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("invalid Last-Event-ID header")))
				return
			}
			if opts.KillSwitch != nil {
				if d := opts.KillSwitch.IsActiveMCP(nil); d.Active {
					emitListenerBlockDecision(mcpListenerBlockDecision{
						reason:          blockreason.KillSwitchActive,
						headerSeverity:  blockreason.SeverityCritical,
						retry:           blockreason.RetryTransient,
						layer:           "kill_switch",
						pattern:         firstNonEmpty(d.Source, "kill_switch"),
						target:          "mcp:kill-switch",
						receiptSeverity: config.SeverityCritical,
					})
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(killswitch.ErrorResponse(nil, d.Message))
					return
				}
			}
			if blockedByUpstreamContract(nil, requestBaseOpts) {
				return
			}
			if blockedByForwardedHeaderDLP() {
				return
			}
			if blockedByA2AHeaders() {
				return
			}
			upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("upstream HTTP request failed")))
				return
			}
			for name, values := range opts.UpstreamHeaders {
				for _, value := range values {
					upReq.Header.Add(name, value)
				}
			}
			upReq.Header.Set("Accept", "text/event-stream")
			forwardListenerUpstreamHeaders(upReq, r, true)

			upResp, err := upstreamStreamClient.Do(upReq)
			if err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("upstream HTTP request failed")))
				return
			}
			defer func() { _ = upResp.Body.Close() }()

			if upResp.StatusCode >= 400 {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream HTTP %d\n", upResp.StatusCode)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("upstream HTTP request failed")))
				return
			}
			if contentEncoding := strings.Join(upResp.Header.Values("Content-Encoding"), ","); hasNonIdentityEncoding(contentEncoding) {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: blocking compressed upstream response (Content-Encoding=%q)\n", contentEncoding)
				info := blockreason.MustNew(blockreason.CompressedResponse, blockreason.SeverityWarn, blockreason.RetryPolicy)
				if withLayer, layerErr := info.WithLayer("response_scan"); layerErr == nil {
					info = withLayer
				}
				info.SetHeaders(w.Header())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("compressed response cannot be scanned")))
				return
			}
			if !isSSEContentType(upResp.Header.Get("Content-Type")) {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream GET returned non-SSE Content-Type %q\n", upResp.Header.Get("Content-Type"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("upstream HTTP request failed")))
				return
			}

			var reqRec session.Recorder
			if opts.Store != nil {
				reqRec = opts.Store.GetOrCreate(adaptiveHostFromRemoteAddr(r.RemoteAddr))
			}
			baselineRec := newMCPRequestBaselineRecorder()
			baselineOpts := requestBaseOpts
			baselineOpts.BaselineRec = baselineRec
			defer recordMCPBaselineSample(baselineOpts, nil)
			reqOpts := requestBaseOpts
			reqOpts.Rec = reqRec
			reqOpts.BaselineRec = baselineRec
			reqOpts.AdaptiveCfg = adaptiveCfg
			reqOpts.AdaptiveCfgFn = nil

			if sid := upResp.Header.Get("Mcp-Session-Id"); sid != "" {
				w.Header().Set("Mcp-Session-Id", sid)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			streamWriter := &sseMessageWriter{w: w}
			if flusher, ok := w.(http.Flusher); ok {
				streamWriter.flusher = flusher
			}
			foundInjection, scanErr := ForwardScanned(transport.NewSSEReader(upResp.Body), streamWriter, safeLogW, nil, reqOpts)
			if scanErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
			}
			if scanErr != nil && !streamWriter.Wrote() {
				w.Header().Del("Cache-Control")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("upstream SSE response failed validation")))
				return
			}
			if !streamWriter.Wrote() && !foundInjection {
				w.WriteHeader(http.StatusOK)
			}
			return
		}
		if r.Method == http.MethodDelete {
			if opts.KillSwitch != nil {
				if d := opts.KillSwitch.IsActiveMCP(nil); d.Active {
					emitListenerBlockDecision(mcpListenerBlockDecision{
						reason:          blockreason.KillSwitchActive,
						headerSeverity:  blockreason.SeverityCritical,
						retry:           blockreason.RetryTransient,
						layer:           "kill_switch",
						pattern:         firstNonEmpty(d.Source, "kill_switch"),
						target:          "mcp:kill-switch",
						receiptSeverity: config.SeverityCritical,
					})
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(killswitch.ErrorResponse(nil, d.Message))
					return
				}
			}
			if blockedByUpstreamContract(nil, requestBaseOpts) {
				return
			}
			if blockedByForwardedHeaderDLP() {
				return
			}
			if blockedByA2AHeaders() {
				return
			}
			upReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, upstreamURL, nil)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("upstream HTTP request failed")))
				return
			}
			for name, values := range opts.UpstreamHeaders {
				for _, value := range values {
					upReq.Header.Add(name, value)
				}
			}
			forwardListenerUpstreamHeaders(upReq, r, false)

			upResp, err := upstreamClient.Do(upReq)
			if err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("upstream HTTP request failed")))
				return
			}
			defer func() { _ = upResp.Body.Close() }()
			if upResp.StatusCode >= 500 {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream HTTP %d\n", upResp.StatusCode)
			}
			w.WriteHeader(upResp.StatusCode)
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed()
			return
		}

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
			host := adaptiveHostFromRemoteAddr(r.RemoteAddr)
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
			reqRec = opts.Store.GetOrCreate(adaptiveHostFromRemoteAddr(r.RemoteAddr))
		}
		baselineRec := newMCPRequestBaselineRecorder()
		baselineOpts := requestBaseOpts
		baselineOpts.BaselineRec = baselineRec
		defer recordMCPBaselineSample(baselineOpts, nil)

		warnCtx := scanner.DLPWarnContextFromCtx(r.Context())
		if warnCtx.Transport == "" {
			warnCtx.Transport = requestBaseOpts.Transport
		}
		warnCtx.Method = mcpWarnMethod
		warnCtx.Resource = r.URL.Path
		if policyHash := requestBaseOpts.receiptPolicyHash(); policyHash != "" {
			warnCtx.PolicyHash = policyHash
		}
		if warnCtx.ClientIP == "" {
			warnCtx.ClientIP = adaptiveHostFromRemoteAddr(r.RemoteAddr)
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
				// Emit a block receipt so an A2A header block leaves the same
				// policy-hash-bearing evidence as every other applicable
				// surface. Forward proxy A2A headers already did this; the
				// listener header block previously returned silently with no
				// receipt. Transport is the wire (mcp_http_listener); A2A
				// attribution lives in the layer.
				emitter := requestBaseOpts.receiptEmitter()
				v2Emitter := requestBaseOpts.v2ReceiptEmitter()
				if emitter != nil || v2Emitter != nil || requestBaseOpts.requireReceipts() {
					if _, emitErr := EmitMCPDecision(emitter, v2Emitter, nil, MCPDecision{
						Receipt: requestBaseOpts.withReceiptPolicyHash(receipt.EmitOpts{
							ActionID:  receipt.NewActionID(),
							Verdict:   config.ActionBlock,
							Layer:     mcpReceiptLayerA2A,
							Pattern:   firstNonEmpty(headerResult.Reason, mcpReceiptA2AHeaderPattern),
							Severity:  config.SeverityHigh,
							Transport: requestBaseOpts.Transport,
							// The block is on the A2A-Extensions header, not the
							// body method, so MCPMethod is left empty and the
							// target names the header surface. Layer + Pattern
							// carry the A2A-header attribution.
							Target: mcpReceiptA2AHeaderTarget,
						}),
						RequireReceipt: requestBaseOpts.requireReceipts(),
					}); emitErr != nil {
						logReceiptEmitFailure(safeLogW, emitErr, requestBaseOpts.requireReceipts(), config.ActionBlock)
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
		scanOpts := requestBaseOpts
		scanOpts.Rec = reqRec
		scanOpts.BaselineRec = baselineRec
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

		if blockedByUpstreamContract(frame.ID, scanOpts) {
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
		for name, values := range opts.UpstreamHeaders {
			for _, value := range values {
				upReq.Header.Add(name, value)
			}
		}
		upReq.Header.Set("Content-Type", "application/json")
		upReq.Header.Set("Accept", "application/json, text/event-stream")

		forwardListenerUpstreamHeaders(upReq, r, false)

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
			commitMCPToolCall(baselineRec, mcpFrameBaselineIdentity(frame))
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
		if contentEncoding := strings.Join(upResp.Header.Values("Content-Encoding"), ","); hasNonIdentityEncoding(contentEncoding) {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: blocking compressed upstream response (Content-Encoding=%q)\n", contentEncoding)
			info := blockreason.MustNew(blockreason.CompressedResponse, blockreason.SeverityWarn, blockreason.RetryPolicy)
			if withLayer, layerErr := info.WithLayer("response_scan"); layerErr == nil {
				info = withLayer
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
		reqOpts := requestBaseOpts
		reqOpts.Rec = reqRec
		reqOpts.BaselineRec = baselineRec
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
			foundInjection, scanErr := ForwardScanned(reader, streamWriter, safeLogW, nil, reqOpts)
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
			if scanErr == nil && !foundInjection {
				commitMCPToolCall(baselineRec, mcpFrameBaselineIdentity(frame))
			}
			if !streamWriter.Wrote() {
				w.WriteHeader(http.StatusAccepted)
			}
			return
		}
		foundInjection, scanErr := ForwardScanned(reader, bufWriter, safeLogW, nil, reqOpts)
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("upstream response failed validation")))
			return
		}
		if foundInjection {
			w.Header().Set("Content-Type", "application/json")
			output := bytes.TrimSpace(buf.Bytes())
			if len(output) == 0 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_, _ = w.Write(output)
			return
		}
		commitMCPToolCall(baselineRec, mcpFrameBaselineIdentity(frame))
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

func listenerIsLoopback(ln net.Listener) bool {
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	return ok && tcpAddr.IP.IsLoopback()
}

func listenerOriginAllowed(values []string, allowed []string) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	origin := values[0]
	normalized, err := normalizeListenerOrigin(origin)
	if err != nil {
		return false
	}
	for _, candidate := range allowed {
		if subtle.ConstantTimeCompare([]byte(normalized), []byte(candidate)) == 1 {
			return true
		}
	}
	return false
}

func normalizeListenerOrigins(origins []string) ([]string, error) {
	normalized := make([]string, 0, len(origins))
	for _, origin := range origins {
		value, err := normalizeListenerOrigin(origin)
		if err != nil {
			return nil, fmt.Errorf("invalid MCP listener allowed origin %q: %w", origin, err)
		}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

func normalizeListenerOrigin(origin string) (string, error) {
	if strings.TrimSpace(origin) != origin || origin == "" || origin == "null" {
		return "", fmt.Errorf("must be a serialized origin")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("must contain only scheme and host")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

func validateListenerBearerToken(token string) error {
	if token == "" {
		return nil
	}
	if len(token) > 8192 {
		return fmt.Errorf("MCP listener bearer token exceeds 8192 bytes")
	}
	for i := range len(token) {
		if token[i] < 0x21 || token[i] > 0x7e {
			return fmt.Errorf("MCP listener bearer token must contain visible ASCII without spaces")
		}
	}
	return nil
}

// forwardIfOperatorUnset copies a client header to the upstream request only
// when the operator has not already pinned it through --header/--header-file.
// Operator-configured values are policy; a client must never override them.
func forwardIfOperatorUnset(upReq, r *http.Request, name string) {
	if v := r.Header.Get(name); v != "" && upReq.Header.Get(name) == "" {
		upReq.Header.Set(name, v)
	}
}

func forwardListenerUpstreamHeaders(upReq, r *http.Request, includeLastEventID bool) {
	// Client-supplied values fill in only where the operator did not pin the
	// header via --header/--header-file. A bare Set here would let any client
	// clobber operator-pinned service headers.
	forwardIfOperatorUnset(upReq, r, "Authorization")
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}
	forwardIfOperatorUnset(upReq, r, listenerProtocolVersion)
	forwardIfOperatorUnset(upReq, r, "A2A-Extensions")
	forwardIfOperatorUnset(upReq, r, "A2A-Version")
	if includeLastEventID {
		forwardIfOperatorUnset(upReq, r, listenerLastEventID)
	}
}

func adaptiveHostFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func acceptAllowsSSE(values []string) bool {
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			if !strings.EqualFold(mediaType, "text/event-stream") {
				continue
			}
			q := strings.TrimSpace(params["q"])
			if q != "" {
				weight, err := strconv.ParseFloat(q, 64)
				if err != nil || math.IsNaN(weight) || math.IsInf(weight, 0) || weight <= 0 || weight > 1 {
					continue
				}
			}
			return true
		}
	}
	return false
}

func applyOperatorPinnedServiceHeaders(request, operator http.Header) {
	for _, name := range []string{listenerProtocolVersion, "A2A-Extensions", "A2A-Version"} {
		values := operator.Values(name)
		if len(values) == 0 {
			continue
		}
		request.Del(name)
		for _, value := range values {
			request.Add(name, value)
		}
	}
}

func listenerBearerAuthorized(values []string, token string) bool {
	if len(values) != 1 {
		return false
	}
	scheme, presented, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || presented == "" || strings.TrimSpace(presented) != presented {
		return false
	}
	want := sha256.Sum256([]byte(token))
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func listenerBearerAnyValueMatches(values []string, token string) bool {
	for _, value := range values {
		if listenerBearerAuthorized([]string{value}, token) {
			return true
		}
	}
	return false
}

func listenerBearerAuthHeader(headers http.Header, token string) (string, bool) {
	if token == "" {
		return "", true
	}
	if proxyValues := headers.Values(listenerProxyAuthorization); len(proxyValues) > 0 {
		return listenerProxyAuthorization, listenerBearerAuthorized(proxyValues, token)
	}
	return listenerAuthorization, listenerBearerAuthorized(headers.Values(listenerAuthorization), token)
}

func listenerBearerTokenForRequest(opts MCPProxyOpts) (string, error) {
	if opts.ListenerBearerTokenFn == nil {
		return opts.ListenerBearerToken, nil
	}
	token, err := opts.ListenerBearerTokenFn()
	if err != nil {
		return "", err
	}
	if err := validateListenerBearerToken(token); err != nil {
		return "", err
	}
	if token == "" {
		return "", fmt.Errorf("refreshed MCP listener bearer token is empty")
	}
	return token, nil
}

func setListenerCORSHeaders(headers http.Header, origin string) {
	headers.Set("Access-Control-Allow-Origin", origin)
	headers.Set("Access-Control-Allow-Methods", strings.Join([]string{http.MethodPost, http.MethodGet, http.MethodDelete}, ", "))
	headers.Set("Access-Control-Allow-Headers", listenerCORSAllowedHeaders)
	headers.Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
	headers.Add("Vary", "Origin")
	headers.Add("Vary", "Access-Control-Request-Method")
	headers.Add("Vary", "Access-Control-Request-Headers")
}

func listenerCORSPreflightAllowed(r *http.Request) bool {
	switch r.Header.Get("Access-Control-Request-Method") {
	case http.MethodPost, http.MethodGet, http.MethodDelete:
	default:
		return false
	}
	allowed := map[string]struct{}{}
	for name := range strings.SplitSeq(listenerCORSAllowedHeaders, ",") {
		allowed[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	for value := range strings.SplitSeq(r.Header.Get("Access-Control-Request-Headers"), ",") {
		name := strings.ToLower(strings.TrimSpace(value))
		if name == "" {
			continue
		}
		if _, ok := allowed[name]; !ok {
			return false
		}
	}
	return true
}

func validMCPSessionID(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	sessionID := values[0]
	if len(sessionID) == 0 || len(sessionID) > 256 {
		return false
	}
	for i := range len(sessionID) {
		if sessionID[i] < 0x21 || sessionID[i] > 0x7e {
			return false
		}
	}
	return true
}

func validMCPProtocolVersion(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 || len(values[0]) != len("2006-01-02") {
		return false
	}
	parsed, err := time.Parse("2006-01-02", values[0])
	return err == nil && parsed.Format("2006-01-02") == values[0]
}

func validVisibleSingletonHeader(values []string, maxBytes int) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maxBytes {
		return false
	}
	for i := range len(values[0]) {
		if values[0][i] < 0x20 || values[0][i] > 0x7e {
			return false
		}
	}
	return true
}

func validLastEventIDHeader(values []string, maxBytes int) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maxBytes || !utf8.ValidString(values[0]) {
		return false
	}
	return !strings.ContainsAny(values[0], "\x00\r\n")
}

func validA2AVersion(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if !validVisibleSingletonHeader(values, 64) {
		return false
	}
	major, minor, ok := strings.Cut(values[0], ".")
	if !ok || major == "" || minor == "" || strings.Contains(minor, ".") {
		return false
	}
	for _, component := range []string{major, minor} {
		for i := range len(component) {
			if component[i] < '0' || component[i] > '9' {
				return false
			}
		}
	}
	return true
}

func validA2AExtensions(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if !validVisibleSingletonHeader(values, 8192) {
		return false
	}
	for extension := range strings.SplitSeq(values[0], ",") {
		extension = strings.TrimSpace(extension)
		if extension == "" {
			return false
		}
		u, err := url.Parse(extension)
		if err != nil || !u.IsAbs() || u.Scheme == "" {
			return false
		}
	}
	return true
}

func a2aHeaderBlockReason(result A2AScanResult) blockreason.Reason {
	if len(result.DLPFindings) > 0 {
		return blockreason.DLPMatch
	}
	if len(result.InjectFindings) > 0 {
		return blockreason.PromptInjection
	}
	if len(result.URLFindings) > 0 {
		if result.URLFindings[0].IsInfrastructureError() {
			if result.URLFindings[0].DNSErrorKind == scanner.DNSErrorTimeout {
				return blockreason.Timeout
			}
			return blockreason.PatternUnavailable
		}
		return mcpURLBlockReason(result.URLFindings[0].Scanner)
	}
	return blockreason.ParseError
}

func validateListenerUpstreamHeaders(headers http.Header) error {
	for _, name := range []string{listenerAuthorization, listenerProtocolVersion, "A2A-Extensions", "A2A-Version"} {
		if len(headers.Values(name)) > 1 {
			return fmt.Errorf("operator upstream header %s must appear at most once", name)
		}
	}
	if !validMCPProtocolVersion(headers.Values(listenerProtocolVersion)) {
		return fmt.Errorf("operator upstream %s must be a valid YYYY-MM-DD protocol version", listenerProtocolVersion)
	}
	if values := headers.Values(listenerAuthorization); len(values) > 0 && !validVisibleSingletonHeader(values, 8192) {
		return fmt.Errorf("operator upstream %s must be a non-empty visible ASCII value of at most 8192 bytes", listenerAuthorization)
	}
	if !validA2AVersion(headers.Values("A2A-Version")) {
		return fmt.Errorf("operator upstream A2A-Version must use Major.Minor format")
	}
	if !validA2AExtensions(headers.Values("A2A-Extensions")) {
		return fmt.Errorf("operator upstream A2A-Extensions must be a comma-separated absolute URI list")
	}
	return nil
}

func canonicalizeListenerUpstreamHeaders(headers http.Header) http.Header {
	canonical := make(http.Header, len(headers))
	for name, values := range headers {
		for _, value := range values {
			canonical.Add(name, value)
		}
	}
	return canonical
}

func listenerLoopbackHostAllowed(authority string, addr net.Addr) bool {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || authority == "" {
		return false
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		// A Host without a port is only accurate for a listener on the default
		// HTTP port. Non-default browser URLs always serialize the port.
		if tcpAddr.Port != 80 || strings.Contains(authority, ":") {
			return false
		}
		host = authority
	} else if port != fmt.Sprintf("%d", tcpAddr.Port) {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
