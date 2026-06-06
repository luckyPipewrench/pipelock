// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/shield"
)

const (
	// reverseProxyMaxBodyBytes is the default max body size for reverse proxy
	// request/response scanning (1 MB). Both request and response bodies that
	// exceed this limit are blocked fail-closed to prevent scanning bypass.
	reverseProxyMaxBodyBytes = 1024 * 1024

	// scanDirectionRequest labels a DLP finding on the request body.
	scanDirectionRequest = "request"

	// scanDirectionResponse labels an injection finding on the response body.
	scanDirectionResponse = "response"
)

// ReverseProxyBlockResponse is the JSON error body returned when the reverse
// proxy blocks a request or response due to scanning findings.
type ReverseProxyBlockResponse struct {
	Error       string `json:"error"`
	Blocked     bool   `json:"blocked"`
	BlockReason string `json:"block_reason"`
	Direction   string `json:"direction"` // "request" or "response"
}

// ReverseProxyHandler is a scanning reverse proxy that forwards all requests
// to a configured upstream URL. Request bodies are scanned for DLP patterns
// (secret exfiltration) and response bodies are scanned for prompt injection.
type ReverseProxyHandler struct {
	upstream            *url.URL
	proxy               *httputil.ReverseProxy
	cfgPtr              *atomic.Pointer[config.Config]
	scPtr               *atomic.Pointer[scanner.Scanner]
	redactionRuntimePtr *atomic.Pointer[redactionRuntime]
	logger              *audit.Logger
	metrics             *metrics.Metrics
	ks                  *killswitch.Controller
	captureObs          capture.CaptureObserver
	shieldEngine        *shield.Engine
	envelopeEmitterPtr  *atomic.Pointer[envelope.Emitter]
	envelopeVerifierPtr *atomic.Pointer[envelope.Verifier]
	receiptEmitterPtr   *atomic.Pointer[receipt.Emitter]
	v2EmitterPtr        *atomic.Pointer[proxydecision.Emitter]
	contractLoaderPtr   *atomic.Pointer[contractruntime.Loader]
	reqPolicyFn         func(requestPolicyInput) requestPolicyResult                 // nil = disabled
	reqPolicyPrepareFn  func(*http.Request, *requestPolicyInput) requestPolicyResult // nil = no body pre-read
	reloadMu            *sync.RWMutex
}

// NewReverseProxy creates a reverse proxy handler that scans request and
// response bodies. The upstream URL is fixed at creation time (listener
// cannot rebind on hot-reload). Config and scanner are read via atomic
// pointers so scanning behavior updates on hot-reload.
func NewReverseProxy(
	upstream *url.URL,
	cfgPtr *atomic.Pointer[config.Config],
	scPtr *atomic.Pointer[scanner.Scanner],
	logger *audit.Logger,
	m *metrics.Metrics,
	ks *killswitch.Controller,
	captureObs capture.CaptureObserver,
	shieldEngine *shield.Engine,
) *ReverseProxyHandler {
	if captureObs == nil {
		captureObs = capture.NopObserver{}
	}
	rp := &ReverseProxyHandler{
		upstream:     upstream,
		cfgPtr:       cfgPtr,
		scPtr:        scPtr,
		logger:       logger,
		metrics:      m,
		ks:           ks,
		captureObs:   captureObs,
		shieldEngine: shieldEngine,
	}
	// redactionRuntimePtr is attached via SetRedactionRuntimePtr after
	// construction so NewReverseProxy stays under the 6-parameter rule.

	proxy := httputil.NewSingleHostReverseProxy(upstream)

	// Director rewrites the request to target the upstream.
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = cleanReversePath(req.URL.Path)
		req.URL.RawPath = ""
		req.Host = upstream.Host
	}

	// ModifyResponse scans response bodies for injection.
	proxy.ModifyResponse = rp.modifyResponse

	// ErrorHandler returns a JSON error on upstream failures.
	proxy.ErrorHandler = rp.errorHandler

	proxy.Transport = newReverseProxyTransport(rp, nil)

	rp.proxy = proxy
	return rp
}

// SetSafeDialer swaps the reverse-proxy transport's dial path for the
// supplied SSRF-safe DialContext (typically Proxy.SafeDialer()). It must be
// called before serving requests; it is not safe to call concurrently with
// ServeHTTP because it replaces proxy.Transport.
//
// The submit profile uses this so outbound dials resolve DNS and validate
// every resolved IP against internal CIDR blocks before connecting, closing
// the DNS-rebinding / TOCTOU gap the cloned default dialer leaves open. The
// rebuilt base preserves DisableCompression (so the compressed-response
// fail-closed guard in modifyResponse keeps working) and re-wraps in the
// signing round tripper so RFC 9421 @target-uri signing is unaffected.
//
// A nil dialer is a no-op: the handler keeps its default transport. This
// keeps generic reverse-proxy mode (Profile == "") on the default dialer,
// where the operator is presumed to have chosen the upstream already.
func (rp *ReverseProxyHandler) SetSafeDialer(dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	if dial == nil {
		return
	}
	rp.proxy.Transport = newReverseProxyTransport(rp, dial)
}

// newReverseProxyTransport builds the signing transport that sits between
// httputil.ReverseProxy and the base HTTP transport. The base always disables
// transparent decompression so modifyResponse can fail closed on compressed
// upstream responses instead of seeing Go's auto-decompressed body with the
// Content-Encoding header stripped.
func newReverseProxyTransport(rp *ReverseProxyHandler, dial func(ctx context.Context, network, addr string) (net.Conn, error)) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DisableCompression = true
	// Clone() inherits Proxy: http.ProxyFromEnvironment from
	// http.DefaultTransport, which would let an ambient HTTP_PROXY /
	// HTTPS_PROXY silently redirect pipelock's own upstream egress. Every
	// other egress transport (fetch proxy.go, intercept.go,
	// newTLSInterceptTransport) builds a fresh http.Transport with a nil
	// Proxy and dials the configured upstream directly. Match that parity
	// here so reverse-proxy egress is not env-steerable and always traverses
	// the SSRF-safe dialer below.
	base.Proxy = nil
	if dial != nil {
		base.DialContext = dial
	}
	return &reverseSigningRoundTripper{
		base: base,
		rp:   rp,
	}
}

// SetEnvelopeEmitter sets the atomic pointer to the envelope emitter.
// Must be called before serving requests if mediation envelopes are enabled.
func (rp *ReverseProxyHandler) SetEnvelopeEmitter(ptr *atomic.Pointer[envelope.Emitter]) {
	rp.envelopeEmitterPtr = ptr
}

// SetEnvelopeVerifier sets the atomic pointer to the inbound envelope verifier.
func (rp *ReverseProxyHandler) SetEnvelopeVerifier(ptr *atomic.Pointer[envelope.Verifier]) {
	rp.envelopeVerifierPtr = ptr
}

// SetReceiptEmitter sets the atomic pointer to the action-receipt emitter.
// When unset (or pointing at nil), emitReceipt is a no-op so deployments
// without flight-recorder signing keep their existing behavior. Wiring
// the pointer is what gives reverse-proxy block paths receipt parity with
// forward / intercept.
func (rp *ReverseProxyHandler) SetReceiptEmitter(ptr *atomic.Pointer[receipt.Emitter]) {
	rp.receiptEmitterPtr = ptr
}

// SetV2ReceiptEmitter sets the atomic pointer to the v2 proxy_decision emitter
// so reverse-proxy decisions dual-emit v2 receipts in parity with forward /
// intercept. When unset (or pointing at nil), v2 emission is a no-op.
func (rp *ReverseProxyHandler) SetV2ReceiptEmitter(ptr *atomic.Pointer[proxydecision.Emitter]) {
	rp.v2EmitterPtr = ptr
}

// SetContractLoader sets the atomic pointer to the learn-lock loader.
func (rp *ReverseProxyHandler) SetContractLoader(ptr *atomic.Pointer[contractruntime.Loader]) {
	rp.contractLoaderPtr = ptr
}

// SetRequestPolicyFn wires the request_policy evaluation into the
// reverse-proxy handler. The function is typically Proxy.applyRequestPolicy
// (a method value). When nil, request_policy is a no-op and the handler
// proceeds directly to the contract gate.
func (rp *ReverseProxyHandler) SetRequestPolicyFn(fn func(requestPolicyInput) requestPolicyResult) {
	rp.reqPolicyFn = fn
}

// SetRequestPolicyPrepareFn wires the optional request_policy body pre-reader.
// It is needed only when request_body_scanning did not already buffer a body
// and an operation predicate requires body inspection.
func (rp *ReverseProxyHandler) SetRequestPolicyPrepareFn(fn func(*http.Request, *requestPolicyInput) requestPolicyResult) {
	rp.reqPolicyPrepareFn = fn
}

// emitReceipt records a signed action receipt for a reverse-proxy
// decision. Mirrors Proxy.emitReceipt: nil emitter is a no-op, errors are
// logged but never propagated so a recorder failure cannot poison the
// hot path. Reverse-proxy receipts use Transport="reverse"; the caller
// supplies Layer/Pattern/ActionID/RequestID/Agent/Method/Target.
//
// On emit failure the wrapped error carries every receipt field so an
// operator reconstructing an enforcement decision after a missing-receipt
// incident can correlate the audit log entry to the action that was
// supposed to be attested. Plain RequestID alone is too thin for that.
func (rp *ReverseProxyHandler) emitReceipt(opts receipt.EmitOpts) {
	if rp.receiptEmitterPtr != nil {
		if e := rp.receiptEmitterPtr.Load(); e != nil {
			if err := e.Emit(opts); err != nil {
				rp.logger.LogError(audit.NewRequestLogContext(opts.RequestID),
					fmt.Errorf("emit receipt action_id=%s verdict=%s layer=%s pattern=%q transport=%s method=%s target=%s agent=%s: %w",
						opts.ActionID, opts.Verdict, opts.Layer, opts.Pattern,
						opts.Transport, opts.Method, opts.Target, opts.Agent, err))
				// v1 stays authoritative: skip v2 when v1 failed to record.
				return
			}
		}
	}
	// Dual-emit the v2 proxy_decision receipt.
	emitV2(rp.v2EmitterPtr, opts, func(err error) {
		rp.logger.LogError(audit.NewRequestLogContext(opts.RequestID),
			fmt.Errorf("emit v2 proxy_decision action_id=%s verdict=%s transport=%s: %w",
				opts.ActionID, opts.Verdict, opts.Transport, err))
	})
}

func reverseTargetURL(upstream *url.URL, r *http.Request) string {
	if upstream == nil || r == nil || r.URL == nil {
		return ""
	}
	target := *upstream
	target.Path = joinReversePaths(upstream.Path, r.URL.Path)
	target.RawPath = ""
	switch {
	case upstream.RawQuery == "":
		target.RawQuery = r.URL.RawQuery
	case r.URL.RawQuery == "":
		target.RawQuery = upstream.RawQuery
	default:
		target.RawQuery = upstream.RawQuery + "&" + r.URL.RawQuery
	}
	return target.String()
}

func joinReversePaths(basePath, reqPath string) string {
	baseSlash := strings.HasSuffix(basePath, "/")
	reqSlash := strings.HasPrefix(reqPath, "/")
	var joined string
	switch {
	case baseSlash && reqSlash:
		joined = basePath + reqPath[1:]
	case !baseSlash && !reqSlash:
		joined = basePath + "/" + reqPath
	default:
		joined = basePath + reqPath
	}
	return cleanReversePath(joined)
}

func cleanReversePath(joined string) string {
	cleaned := path.Clean(joined)
	if strings.HasSuffix(joined, "/") && cleaned != "/" {
		return cleaned + "/"
	}
	return cleaned
}

// SetReloadLock lets ServeHTTP snapshot cfg/scanner/emitter state coherently
// with Proxy.Reload publication.
func (rp *ReverseProxyHandler) SetReloadLock(mu *sync.RWMutex) {
	rp.reloadMu = mu
}

// SetRedactionRuntimePtr attaches the atomic pointer to the request-body
// redaction runtime snapshot. The pointer dereferences to nil when redaction
// is disabled, so scanRequestBody will skip the redaction step gracefully.
// Must be called before serving requests if redaction is enabled.
func (rp *ReverseProxyHandler) SetRedactionRuntimePtr(ptr *atomic.Pointer[redactionRuntime]) {
	rp.redactionRuntimePtr = ptr
}

type reverseRuntimeSnapshot struct {
	cfg              *config.Config
	sc               *scanner.Scanner
	admissionEmitter *envelope.Emitter
	inboundVerifier  *envelope.Verifier
	contractLoader   *contractruntime.Loader
}

func (rp *ReverseProxyHandler) snapshotRuntime() reverseRuntimeSnapshot {
	if rp.reloadMu != nil {
		rp.reloadMu.RLock()
		defer rp.reloadMu.RUnlock()
	}
	snap := reverseRuntimeSnapshot{
		cfg: rp.cfgPtr.Load(),
		sc:  rp.scPtr.Load(),
	}
	if rp.envelopeEmitterPtr != nil {
		snap.admissionEmitter = rp.envelopeEmitterPtr.Load()
	}
	if rp.envelopeVerifierPtr != nil {
		snap.inboundVerifier = rp.envelopeVerifierPtr.Load()
	}
	if rp.contractLoaderPtr != nil {
		snap.contractLoader = rp.contractLoaderPtr.Load()
	}
	return snap
}

// snapshotAndAcquire reads the current runtime snapshot and registers the
// loaded scanner for in-flight protection. Returns the snapshot, a
// release func (a no-op release is always safe to invoke), and ok=true
// when acquisition succeeded. Callers defer release unconditionally; on
// ok=false they MUST fail the request closed rather than scan against
// an unpinned closed instance. Three back-to-back acquisition failures
// only happen under reload thrash that publishes a successor faster
// than a request can register; surfacing that as a 503 is preferable to
// silently scanning on torn-down state.
func (rp *ReverseProxyHandler) snapshotAndAcquire() (reverseRuntimeSnapshot, func(), bool) {
	for range 3 {
		snap := rp.snapshotRuntime()
		if snap.sc == nil {
			return snap, func() {}, false
		}
		if release, ok := snap.sc.BeginUse(); ok {
			return snap, release, true
		}
	}
	return rp.snapshotRuntime(), func() {}, false
}

// ServeHTTP handles incoming requests: scan the request body for DLP,
// then forward to upstream via the reverse proxy.
func (rp *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap, releaseScanner, scOK := rp.snapshotAndAcquire()
	defer releaseScanner()
	if !scOK {
		// Reload thrash or no live scanner. Fail closed at the request
		// level rather than scan on an unpinned, possibly-closed scanner.
		// Attest the deny so an operator reconstructing the enforcement
		// timeline from receipts sees the request resolved to a verdict.
		_, requestID := requestMeta(r)
		agent, _ := r.Context().Value(ctxKeyAgent).(string)
		rp.metrics.RecordReverseProxyRequest(r.Method, "503")
		rp.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     scannerLabelUnavailable,
			Pattern:   scannerPatternUnavailable,
			Transport: "reverse",
			Method:    r.Method,
			Target:    r.URL.String(),
			RequestID: requestID,
			Agent:     agent,
		})
		writeReverseProxyBlock(w, http.StatusServiceUnavailable,
			blockInfoFor(blockreason.PatternUnavailable, scannerLabelUnavailable),
			scannerPatternUnavailable)
		return
	}
	cfg := snap.cfg
	sc := snap.sc
	admissionEmitter := snap.admissionEmitter
	clientIP, requestID := requestMeta(r)
	agent, _ := r.Context().Value(ctxKeyAgent).(string)
	if agent == "" {
		agent = edition.ResolveAgentIdentity(r, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity).Name
	}
	targetURL := reverseTargetURL(rp.upstream, r)
	var reverseGate ContractGateOutput
	withReverseContractReceipt := func(opts receipt.EmitOpts) receipt.EmitOpts {
		if reverseGate.HasContractContext() {
			opts = withContractReceipt(reverseGate, opts)
		}
		return opts
	}
	ctx := scanner.WithDLPWarnContext(r.Context(), scanner.DLPWarnContext{
		Method: r.Method, URL: targetURL, ClientIP: clientIP,
		RequestID: requestID, Agent: agent, Transport: "reverse",
	})
	ctx = context.WithValue(ctx, ctxKeyClientIP, clientIP)
	ctx = context.WithValue(ctx, ctxKeyRequestID, requestID)
	ctx = context.WithValue(ctx, ctxKeyAgent, agent)
	ctx = context.WithValue(ctx, ctxKeyReverseEnvelopeCfg, cfg)
	ctx = context.WithValue(ctx, ctxKeyReverseScanner, sc)
	r = r.WithContext(ctx)
	if cfg.ReverseProxy.Profile == config.ReverseProxyProfileSubmit && cfg.ReverseProxy.RequestTimeoutSeconds > 0 {
		timeoutCtx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.ReverseProxy.RequestTimeoutSeconds)*time.Second)
		defer cancel()
		r = r.WithContext(timeoutCtx)
	}

	if err := verifyInboundEnvelope(r, cfg, snap.inboundVerifier); err != nil {
		recordInboundEnvelopeVerify(rp.metrics, cfg, err)
		pattern := inboundEnvelopeFailurePattern(err)
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, blockLayerMediationEnvelope)
		rp.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     blockLayerMediationEnvelope,
			Pattern:   pattern,
			Transport: "reverse",
			Method:    r.Method,
			Target:    r.URL.String(),
			RequestID: requestID,
			Agent:     agent,
		})
		writeReverseProxyBlock(w, http.StatusForbidden,
			blockInfoFor(blockreason.EnvelopeVerifyFailed, blockLayerMediationEnvelope),
			"inbound mediation envelope verification failed")
		return
	}
	recordInboundEnvelopeVerify(rp.metrics, cfg, nil)
	// Strip inbound mediation envelope headers after optional trust
	// verification so forged mediation metadata cannot survive to upstreams.
	envelope.StripInbound(r.Header)

	// Kill switch: deny all traffic when active.
	if rp.ks != nil && rp.ks.IsActive() {
		gate, gateErr := EvaluateGate(ContractGateInput{
			Loader:           snap.contractLoader,
			Agent:            agent,
			URL:              targetURL,
			Method:           r.Method,
			EffectiveAction:  config.ActionAllow,
			ScannerVerdict:   config.ActionAllow,
			KillSwitchActive: true,
			Transport:        TransportReverse,
		})
		if gateErr != nil {
			rp.logger.LogBlocked(newHTTPAuditContext(rp.logger, r.Method, targetURL, clientIP, requestID, agent), "kill_switch", killSwitchActiveReason)
		}
		if gateErr == nil && gate.Verdict == config.ActionBlock {
			reverseGate = gate
			reason := gate.Reason
			if reason == "" {
				reason = gate.WinningSource
			}
			rp.logger.LogBlocked(newHTTPAuditContext(rp.logger, r.Method, targetURL, clientIP, requestID, agent), blockLayerContract, reason)
			rp.metrics.RecordReverseProxyRequest(r.Method, "403")
			rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, blockLayerContract)
			rp.metrics.RecordKillSwitchDenial("reverse_proxy", r.URL.Path)
			rp.emitReceipt(withReverseContractReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     blockLayerContract,
				Pattern:   reason,
				Transport: TransportReverse,
				Method:    r.Method,
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			}))
			writeReverseProxyBlock(w, http.StatusForbidden,
				blockInfoFor(blockreason.KillSwitchActive, "kill_switch"),
				reason)
			return
		}
		rp.metrics.RecordReverseProxyRequest(r.Method, "503")
		rp.metrics.RecordKillSwitchDenial("reverse_proxy", r.URL.Path)
		writeReverseProxyBlock(w, http.StatusServiceUnavailable,
			blockInfoFor(blockreason.KillSwitchActive, ""),
			"kill switch active")
		return
	}

	// Submit-profile gate (no-op when cfg.ReverseProxy.Profile == "").
	// Runs BEFORE URL DLP and body scanning so denied requests do not
	// consume scanner cycles and so the operator's tighter rules (method
	// allowlist, exact-path match, raw-path canonicality, body cap) are
	// applied before generic checks.
	if gate := evaluateSubmitProfileGate(cfg, r); !gate.Allowed {
		rp.metrics.RecordReverseProxyRequest(r.Method, strconv.Itoa(gate.Status))
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, scannerLabelSubmitProfile)
		writeReverseProxyBlock(w, gate.Status, gate.Block, gate.Reason)
		return
	}

	// Submit-profile upstream-URL scan (no-op when profile is empty).
	// The generic reverse proxy skips the full URL pipeline because the
	// upstream is operator-configured; submit profile tightens this so
	// the scanner still flags blocklist hits, rate-limit-blown
	// destinations, or pattern-matching anomalies on the upstream URL
	// before we forward. The target is the full upstream URL the
	// request will actually reach, not the path-only r.URL the proxy
	// sees from the client.
	if cfg.ReverseProxy.Profile == config.ReverseProxyProfileSubmit {
		urlResult := sc.Scan(r.Context(), targetURL)
		if !urlResult.Allowed {
			rp.metrics.RecordReverseProxyRequest(r.Method, "403")
			rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, scannerLabelSubmitProfile)
			reason := urlResult.Reason
			if reason == "" {
				reason = "submit profile: upstream URL scan denied"
			}
			writeReverseProxyBlock(w, http.StatusForbidden,
				blockInfo(urlResult.Scanner),
				reason)
			return
		}
	}

	// Scan request path and query for DLP patterns. Secrets embedded in
	// the URL path or query string would bypass body/header DLP without
	// this check. Intentionally not gated by RequestBodyScanning.Enabled:
	// URL-based exfiltration must always be caught even when body scanning
	// is disabled. Only the path+query are agent-controlled; the upstream
	// host is operator-configured so we skip the full URL pipeline (SSRF,
	// blocklist, rate limit) which only applies to agent-chosen destinations.
	hasFinding := false
	requestEffectiveAction := config.ActionAllow
	requestScannerVerdict := config.ActionAllow
	if pathQuery := r.URL.RequestURI(); pathQuery != "" {
		pathDLP := sc.ScanTextForDLP(r.Context(), pathQuery)

		// Capture observer: record reverse proxy URL DLP verdict for policy replay.
		{
			urlDLPAction := config.ActionAllow
			if !pathDLP.Clean {
				urlDLPAction = cfg.RequestBodyScanning.Action
				if urlDLPAction == "" {
					urlDLPAction = config.ActionBlock
				}
			}
			rp.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
				Subsurface:        "dlp_reverse_url",
				Transport:         "reverse",
				SessionID:         captureSessionKey(r.Header.Get("X-Pipelock-Agent"), reverseClientIP(r)),
				SessionIDOriginal: captureSessionKeyOriginal(r.Header.Get("X-Pipelock-Agent"), reverseClientIP(r)),
				ConfigHash:        cfg.CanonicalPolicyHash(),
				Agent:             r.Header.Get("X-Pipelock-Agent"),
				Profile:           edition.ProfileDefault,
				ActionClass:       captureHTTPActionClass(r.Method),
				Request:           capture.CaptureRequest{Method: r.Method, URL: r.URL.String()},
				TransformKind:     capture.TransformRaw,
				RawFindings:       dlpMatchesToFindings(pathDLP.Matches),
				EffectiveAction:   urlDLPAction,
				Outcome:           captureOutcome(urlDLPAction, pathDLP.Clean),
			})
		}

		if !pathDLP.Clean {
			hasFinding = true
			action := cfg.RequestBodyScanning.Action
			if action == "" {
				action = config.ActionBlock
			}
			requestEffectiveAction = action
			requestScannerVerdict = scannerVerdictForContinuingAction(action, cfg.EnforceEnabled())
			patternNames := dlpMatchNames(pathDLP.Matches)
			rp.logger.LogBodyDLP(newHTTPAuditContext(rp.logger, r.Method, r.URL.String(), clientIP, requestID, ""),
				action,
				len(patternNames), patternNames, nil)

			if action == config.ActionBlock && cfg.EnforceEnabled() {
				rp.metrics.RecordReverseProxyRequest(r.Method, "403")
				rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, "url_dlp")
				reason := fmt.Sprintf("URL DLP: %s", strings.Join(patternNames, ", "))
				writeReverseProxyBlock(w, http.StatusForbidden,
					blockInfoFor(blockreason.DLPMatch, scanner.ScannerDLP),
					reason)
				return
			}
		}
	}

	// Scan request headers for DLP patterns (secret exfiltration via headers).
	if cfg.RequestBodyScanning.Enabled && cfg.RequestBodyScanning.ScanHeaders {
		// Pass the full upstream destination (scheme://host[:port]/path) so
		// destination-scoped suppress globs (e.g. "https://api.example.com/*")
		// resolve against the URL the request will actually reach, not the
		// path-only r.URL.String() the reverse proxy sees from the client.
		dlpTarget := *rp.upstream
		dlpTarget.Path = joinReversePaths(rp.upstream.Path, r.URL.Path)
		dlpTarget.RawPath = ""
		headerResult := scanRequestHeadersForTarget(r.Context(), r.Header, cfg, sc, dlpTarget.String())
		if headerResult != nil {
			hasFinding = true
			action := cfg.RequestBodyScanning.Action
			if action == "" {
				action = config.ActionBlock
			}
			headerHardBlock := shouldHardBlockCriticalDLP(headerResult.DLPMatches, cfg.EnforceEnabled())
			if headerHardBlock {
				action = config.ActionBlock
			}
			requestEffectiveAction = action
			requestScannerVerdict = scannerVerdictForContinuingAction(action, cfg.EnforceEnabled())
			patternNames := dlpMatchNames(headerResult.DLPMatches)
			rp.logger.LogHeaderDLP(newHTTPAuditContext(rp.logger, r.Method, r.URL.String(), clientIP, requestID, ""), headerResult.HeaderName,
				action, patternNames, nil)

			if headerHardBlock || (action == config.ActionBlock && cfg.EnforceEnabled()) {
				rp.metrics.RecordReverseProxyRequest(r.Method, "403")
				rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, "header_dlp")
				reason := fmt.Sprintf("header DLP: %s", strings.Join(patternNames, ", "))
				writeReverseProxyBlock(w, http.StatusForbidden,
					blockInfoFor(blockreason.DLPMatch, scanner.ScannerDLP),
					reason)
				return
			}
		}
	}

	// Scan request body for DLP patterns (secret exfiltration).
	forwardedVerdict := config.ActionAllow
	var reverseBodyBytes []byte
	if r.Body != nil && r.ContentLength != 0 && cfg.RequestBodyScanning.Enabled {
		redaction := currentRedactionRuntimeForConfig(cfg, rp.redactionRuntimePtr, sc)
		blocked, verdict, bodyBytes, bodyFinding := rp.scanRequest(w, r, cfg, sc, redaction, reverseBlockReceiptInput{
			RequestID: requestID,
			Agent:     agent,
			Target:    targetURL,
		})
		if blocked {
			return
		}
		if bodyFinding {
			hasFinding = true
		}
		if verdict != "" {
			forwardedVerdict = verdict
		}
		if bodyFinding && verdict != "" {
			requestEffectiveAction = verdict
			requestScannerVerdict = scannerVerdictForContinuingAction(verdict, cfg.EnforceEnabled())
		}
		reverseBodyBytes = bodyBytes
	}

	// request_policy runs before the contract gate so a contract allow can
	// never suppress an operation-policy block.
	if rp.reqPolicyFn != nil {
		// Evaluate against the rewritten upstream route, not the inbound URL:
		// on the reverse path r.URL carries no host and omits the upstream
		// base-path prefix, so host- and path-scoped rules would miss the
		// actual egress destination. targetURL is the canonical egress URL.
		rpHost := rp.upstream.Hostname()
		rpPath := r.URL.EscapedPath()
		rpQuery := r.URL.RawQuery
		if u, err := url.Parse(targetURL); err == nil {
			rpHost = u.Hostname()
			rpPath = u.EscapedPath()
			rpQuery = u.RawQuery
		}
		rpInput := requestPolicyInput{
			Host:        rpHost,
			Method:      r.Method,
			Path:        rpPath,
			Query:       rpQuery,
			ContentType: r.Header.Get(headerContentType),
			Headers:     r.Header,
			Body:        reverseBodyBytes,
			BodyRead:    reverseBodyBytes != nil || r.Body == nil || r.Body == http.NoBody,
			Transport:   TransportReverse,
			Target:      targetURL,
			RequestID:   requestID,
			Agent:       agent,
			AuditCtx:    newHTTPAuditContext(rp.logger, r.Method, targetURL, clientIP, requestID, agent),
			Emit:        rp.emitReceipt,
		}
		if rp.reqPolicyPrepareFn != nil {
			if rpRes := rp.reqPolicyPrepareFn(r, &rpInput); rpRes.Block {
				rp.metrics.RecordReverseProxyRequest(r.Method, "403")
				rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, blockLayerRequestPolicy)
				writeReverseProxyBlock(w, http.StatusForbidden, rpRes.Info, "blocked by request policy: "+rpRes.Reason)
				return
			}
			reverseBodyBytes = rpInput.Body
		}
		if rpRes := rp.reqPolicyFn(rpInput); rpRes.Block {
			rp.metrics.RecordReverseProxyRequest(r.Method, "403")
			rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, blockLayerRequestPolicy)
			writeReverseProxyBlock(w, http.StatusForbidden, rpRes.Info, "blocked by request policy: "+rpRes.Reason)
			return
		}
	}

	gate, gateErr := EvaluateGate(ContractGateInput{
		Loader:          snap.contractLoader,
		Agent:           agent,
		URL:             targetURL,
		Method:          r.Method,
		EffectiveAction: requestEffectiveAction,
		ScannerVerdict:  requestScannerVerdict,
		ScannerMatched:  hasFinding,
		Transport:       TransportReverse,
	})
	if gateErr != nil {
		rp.logger.LogBlocked(newHTTPAuditContext(rp.logger, r.Method, targetURL, clientIP, requestID, agent), blockLayerContract, gateErr.Error())
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, blockLayerContract)
		rp.emitReceipt(withReverseContractReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     blockLayerContract,
			Pattern:   "contract evaluation failed",
			Transport: TransportReverse,
			Method:    r.Method,
			Target:    targetURL,
			RequestID: requestID,
			Agent:     agent,
		}))
		writeReverseProxyBlock(w, http.StatusForbidden,
			blockInfoFor(blockreason.ContractDefaultDeny, blockLayerContract),
			"contract evaluation failed")
		return
	}
	reverseGate = gate
	if gate.Verdict == config.ActionBlock {
		reason := gate.Reason
		if reason == "" {
			reason = gate.WinningSource
		}
		info, ok := contractBlockInfo(reason)
		if !ok {
			info = blockInfoFor(blockreason.ContractDefaultDeny, blockLayerContract)
		}
		rp.logger.LogBlocked(newHTTPAuditContext(rp.logger, r.Method, targetURL, clientIP, requestID, agent), blockLayerContract, reason)
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, blockLayerContract)
		rp.emitReceipt(withReverseContractReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     blockLayerContract,
			Pattern:   reason,
			Transport: TransportReverse,
			Method:    r.Method,
			Target:    targetURL,
			RequestID: requestID,
			Agent:     agent,
		}))
		writeReverseProxyBlock(w, http.StatusForbidden, info, reason)
		return
	}

	// Stash envelope build metadata on the request context so the
	// signing RoundTripper (installed on rp.proxy.Transport) can
	// attach a Pipelock-Mediation header and an RFC 9421 signature
	// AFTER httputil.ReverseProxy's Director has rewritten the URL to
	// the upstream target. Signing before Director would sign the
	// inbound-relative @target-uri and any verifier checking the
	// signature against the upstream host would reject it.
	// Snapshot the emitter at admission time so RoundTrip uses the
	// same signing decision that ServeHTTP made. Without this, a reload
	// between here and RoundTrip could flip signing on/off mid-request.
	if admissionEmitter != nil {
		actorIdentity := edition.ResolveAgentIdentity(r, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
		actor := actorIdentity.Name
		if actor == "" {
			actor = "anonymous"
		}
		opts := envelope.BuildOpts{
			ActionID:   receipt.NewActionID(),
			Action:     string(receipt.ClassifyHTTP(r.Method)),
			Verdict:    forwardedVerdict,
			SideEffect: string(receipt.SideEffectFromMethod(r.Method)),
			Actor:      actor,
			ActorAuth:  actorIdentity.Auth,
			PolicyHash: envelope.PolicyHashFromHex(cfg.CanonicalPolicyHash()),
		}
		ctx := context.WithValue(r.Context(), ctxKeyReverseEnvelopeOpts, opts)
		ctx = context.WithValue(ctx, ctxKeyReverseEnvelopeBody, reverseBodyBytes)
		ctx = context.WithValue(ctx, ctxKeyReverseEnvelopeEmitter, admissionEmitter)
		r = r.WithContext(ctx)
	}

	// Forward to upstream. Response scanning happens in modifyResponse.
	// Envelope signing happens in the signing RoundTripper wrapping
	// rp.proxy.Transport so @target-uri reflects the post-Director URL.
	rp.proxy.ServeHTTP(w, r)
}

// reverseSigningRoundTripper wraps the base transport used by
// httputil.ReverseProxy so envelope signing runs AFTER Director has
// rewritten the request URL to the upstream target. It reads the
// pre-computed envelope.BuildOpts and buffered request body from the
// request context (populated by ServeHTTP) and hands them to
// (*envelope.Emitter).InjectAndSign along with the final outbound
// *http.Request. A nil emitter or missing build opts skips signing -
// the transport is also used by reverse proxies configured without
// mediation envelopes, and must not fail in that case. Any actual
// signing failure returns a fail-closed block so sign:true never
// degrades to unsigned upstream traffic.
type reverseSigningRoundTripper struct {
	base http.RoundTripper
	rp   *ReverseProxyHandler
}

type reverseBlockReceiptInput struct {
	RequestID string
	Agent     string
	Target    string
}

// RoundTrip implements http.RoundTripper. It runs envelope injection
// and signing before handing the request off to the base transport.
// Errors from InjectAndSign fail closed and block the outbound request.
func (t *reverseSigningRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Use the emitter snapshot from admission time, not the current
	// global atomic. A reload between ServeHTTP and RoundTrip must
	// not flip the signing decision for an in-flight request.
	em, _ := req.Context().Value(ctxKeyReverseEnvelopeEmitter).(*envelope.Emitter)
	if em == nil {
		// No emitter was live at admission time - signing was off
		// for this request. Forward unsigned.
		return t.base.RoundTrip(req)
	}
	opts, ok := req.Context().Value(ctxKeyReverseEnvelopeOpts).(envelope.BuildOpts)
	if !ok {
		return nil, newEnvelopeBlockedRequest(
			fmt.Errorf("reverse proxy envelope: missing build opts on context"),
		)
	}
	body, _ := req.Context().Value(ctxKeyReverseEnvelopeBody).([]byte)

	if err := em.InjectAndSign(req, body, opts); err != nil {
		return nil, newEnvelopeBlockedRequest(err)
	}
	return t.base.RoundTrip(req)
}

// scanRequest reads and scans the request body for DLP patterns.
// Returns (blocked, verdict, bodyBytes). When blocked is true the HTTP
// response has already been written and the caller must return. When
// blocked is false, bodyBytes is the buffered body (or nil if the
// request had no scannable body) and the caller may hand it to the
// envelope signer via ctxKeyReverseEnvelopeBody so the signing
// RoundTripper can compute content-digest without a second drain.
func (rp *ReverseProxyHandler) scanRequest(w http.ResponseWriter, r *http.Request, cfg *config.Config, sc *scanner.Scanner, redaction *redactionRuntime, receiptInput reverseBlockReceiptInput) (blocked bool, verdict string, body []byte, finding bool) {
	// Skip binary content types - no secrets to scan in images/video.
	if isBinaryMIME(r.Header.Get("Content-Type")) && redaction == nil {
		return false, "", nil, false
	}

	maxBytes := cfg.RequestBodyScanning.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = reverseProxyMaxBodyBytes
	}

	bodyReq := BodyScanRequest{
		Body:            r.Body,
		Method:          r.Method,
		ContentType:     r.Header.Get("Content-Type"),
		ContentEncoding: r.Header.Get("Content-Encoding"),
		MaxBytes:        maxBytes,
		Scanner:         sc,
		Host:            rp.upstream.Hostname(),
		Path:            r.URL.Path,
		Target:          receiptInput.Target,
		Suppress:        cfg.Suppress,
	}
	applyBodyScanRedaction(&bodyReq, redaction)
	bodyBytes, result := scanRequestBody(r.Context(), bodyReq)

	// Capture observer: record reverse proxy request DLP verdict for policy replay.
	{
		bodyAction := config.ActionAllow
		if !result.Clean {
			bodyAction = result.Action
			if bodyAction == "" {
				bodyAction = cfg.RequestBodyScanning.Action
			}
			if bodyAction == "" {
				bodyAction = config.ActionBlock
			}
		}
		rp.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
			Subsurface:               "dlp_reverse_request",
			Transport:                "reverse",
			SessionID:                captureSessionKey(r.Header.Get("X-Pipelock-Agent"), reverseClientIP(r)),
			SessionIDOriginal:        captureSessionKeyOriginal(r.Header.Get("X-Pipelock-Agent"), reverseClientIP(r)),
			ConfigHash:               cfg.CanonicalPolicyHash(),
			Agent:                    r.Header.Get("X-Pipelock-Agent"),
			Profile:                  edition.ProfileDefault,
			ActionClass:              captureHTTPActionClass(r.Method),
			Request:                  capture.CaptureRequest{Method: r.Method, URL: r.URL.String()},
			TransformKind:            capture.TransformJoinedFields,
			RedactionRewritesApplied: redactionRewriteCount(result.RedactionReport),
			RawFindings:              bodyScanToFindings(result),
			EffectiveAction:          bodyAction,
			Outcome:                  captureOutcome(bodyAction, result.Clean),
		})
	}

	if result.Clean {
		recordBodyRedactionMetrics(rp.metrics, "reverse", "", result.RedactionReport)
		// Re-wrap the buffered body so the reverse proxy can forward
		// it. GetBody lets stdlib replay on redirect hops even though
		// the reverse proxy's upstream client does not follow redirects
		// by default - setting it is cheap and future-proofs the path
		// against a future Transport override that does.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
		bodyBytesCopy := bodyBytes
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytesCopy)), nil
		}
		return false, config.ActionAllow, bodyBytes, false
	}

	action := result.Action
	if action == "" {
		action = cfg.RequestBodyScanning.Action
	}
	if action == "" {
		action = config.ActionBlock
	}
	promptInjectionHardBlock := shouldHardBlockBodyPromptInjection(result, rp.upstream.Hostname(), cfg)
	dlpHardBlock := shouldHardBlockBodyCriticalDLP(result, rp.upstream.Hostname(), cfg)
	if promptInjectionHardBlock || dlpHardBlock {
		action = config.ActionBlock
	}

	// Log the DLP finding.
	patternNames := dlpMatchNames(result.DLPMatches)
	injectionNames := responseMatchNames(result.InjectionMatches)
	reason := result.Reason
	if reason == "" && len(injectionNames) > 0 {
		reason = fmt.Sprintf("prompt injection: %s", strings.Join(injectionNames, ", "))
	}
	if reason == "" && len(patternNames) > 0 {
		reason = fmt.Sprintf("DLP: %s", strings.Join(patternNames, ", "))
	}
	if reason == "" {
		reason = "request body contains secret patterns"
	}
	clientIP, _ := r.Context().Value(ctxKeyClientIP).(string)
	requestID, _ := r.Context().Value(ctxKeyRequestID).(string)
	actx := newHTTPAuditContext(rp.logger, r.Method, r.URL.String(), clientIP, requestID, "")
	if len(injectionNames) > 0 {
		rp.logger.LogBodyScan(actx, audit.EventBodyPromptInjection, action, len(injectionNames), injectionNames)
	}
	recordBodyRedactionMetrics(rp.metrics, "reverse", "", result.RedactionReport)
	if len(patternNames) > 0 {
		rp.logger.LogBodyDLP(actx, action, len(patternNames), patternNames, nil)
	}

	// Fail-closed transport errors (consumed-but-unreplayable body) and
	// redaction gate failures must block regardless of enforce mode.
	layer := "dlp"
	if result.RedactionBlockReason != "" {
		layer = scannerLabelRedaction
	} else if len(result.InjectionMatches) > 0 && len(result.DLPMatches) == 0 {
		layer = scannerLabelBodyPromptInjection
	}
	bodyBlockReason := blockreason.DLPMatch
	if result.RedactionBlockReason != "" {
		bodyBlockReason = blockreason.RedactionFailure
	} else if len(result.InjectionMatches) > 0 && len(result.DLPMatches) == 0 {
		bodyBlockReason = blockreason.PromptInjection
	}
	if promptInjectionHardBlock || dlpHardBlock || isFailClosedBodyResult(result, bodyBytes) {
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, layer)
		rp.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     layer,
			Pattern:   reason,
			Transport: TransportReverse,
			Method:    r.Method,
			Target:    receiptInput.Target,
			RequestID: receiptInput.RequestID,
			Agent:     receiptInput.Agent,
		})
		writeReverseProxyBlock(w, http.StatusForbidden,
			blockInfoFor(bodyBlockReason, layer),
			reason)
		return true, config.ActionBlock, nil, true
	}

	if action == config.ActionBlock && cfg.EnforceEnabled() {
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, layer)
		rp.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     layer,
			Pattern:   reason,
			Transport: TransportReverse,
			Method:    r.Method,
			Target:    receiptInput.Target,
			RequestID: receiptInput.RequestID,
			Agent:     receiptInput.Agent,
		})
		writeReverseProxyBlock(w, http.StatusForbidden,
			blockInfoFor(bodyBlockReason, layer),
			reason)
		return true, config.ActionBlock, nil, true
	}

	// Warn mode: re-wrap body and continue.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	bodyBytesCopy := bodyBytes
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytesCopy)), nil
	}
	return false, action, bodyBytes, true
}

// modifyResponse scans the upstream response body for prompt injection.
// Called by httputil.ReverseProxy after receiving the upstream response.
func (rp *ReverseProxyHandler) modifyResponse(resp *http.Response) error {
	cfg, _ := resp.Request.Context().Value(ctxKeyReverseEnvelopeCfg).(*config.Config)
	sc, _ := resp.Request.Context().Value(ctxKeyReverseScanner).(*scanner.Scanner)
	if cfg == nil || sc == nil {
		snap := rp.snapshotRuntime()
		if cfg == nil {
			cfg = snap.cfg
		}
		if sc == nil {
			sc = snap.sc
		}
	}
	clientIP, _ := resp.Request.Context().Value(ctxKeyClientIP).(string)
	requestID, _ := resp.Request.Context().Value(ctxKeyRequestID).(string)
	agent, _ := resp.Request.Context().Value(ctxKeyAgent).(string)
	// One actionID per response covers every receipt this path may
	// emit (compressed-body, oversize-body, read-error, SSE-stream-
	// finding blocks). Only one block path is reachable per response,
	// but the ID is also referenced from the SSE onComplete closure
	// which runs asynchronously.
	actionID := receipt.NewActionID()
	targetURL := resp.Request.URL.String()

	// Record the final client-visible status at each exit point, not here.
	// The upstream status may be rewritten to 403 by scanning decisions.

	// Scan all responses when enabled. Exempt domains are still scanned for
	// visibility but findings are pinned to warn with no adaptive scoring.
	revHost := resp.Request.URL.Hostname()
	revRespExempt := isResponseScanExempt(revHost, cfg.ResponseScanning.ExemptDomains)

	// Media policy runs regardless of response-scanning state so an
	// operator who disables response scanning for performance cannot
	// silently bypass image metadata stripping, audio/video blocks, size
	// caps, or exposure events. Must execute BEFORE the
	// ResponseScanning.Enabled short-circuit below.
	// Enter the media branch for declared media types AND generic/missing
	// Content-Types where the body might actually be an image. Without the
	// generic-type arm, an attacker who serves a JPEG as
	// application/octet-stream bypasses the entire media branch because
	// isBinaryMIME only matches image/audio/video prefixes. The content-
	// sniffing fallback inside applyMediaPolicy handles the rest, but only
	// if we enter the branch in the first place.
	mediaCT := resp.Header.Get("Content-Type")
	mediaCTCanon := canonicalContentType(mediaCT)
	if (isBinaryMIME(mediaCT) || contentTypeIsGeneric(mediaCTCanon)) && cfg.MediaPolicy.IsEnabled() {
		actx := newHTTPAuditContext(rp.logger, resp.Request.Method, resp.Request.URL.String(), clientIP, requestID, "")
		canonCT := mediaCTCanon
		isImage := strings.HasPrefix(canonCT, "image/")
		isDeclaredAudioVideo := !isImage && isBinaryMIME(mediaCT)

		// Declared audio/video: no body read required. The policy
		// decides based on content type alone, so we avoid the image-
		// sized buffer. When the verdict is Allow, the flow falls
		// through to the binary-skip short-circuit below so the
		// original streamed body passes through unmodified.
		if isDeclaredAudioVideo {
			// Close the original body before replacing it so the
			// upstream connection is released. Without this close,
			// replaceWithMediaBlockResponse overwrites resp.Body
			// while the original stream is still open, leaking the
			// upstream TCP connection.
			verdict := applyMediaPolicy(cfg, mediaCT, nil)
			logMediaExposureIfPresent(rp.logger, actx, verdict, "reverse")
			if verdict.Blocked {
				_ = resp.Body.Close()
				rp.logger.LogBlocked(actx, "media_policy", verdict.BlockReason)
				rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
				rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "media_policy")
				replaceWithMediaBlockResponse(resp, verdict.BlockReason)
				return nil
			}
			// Fall through to the isBinaryMIME skip below so the
			// original resp.Body streams to the client untouched.
		} else {
			// Image OR generic Content-Type: buffer the body so
			// applyMediaPolicy can either strip image metadata or
			// run the content-sniffing fallback for generic types
			// (application/octet-stream, empty, etc.) that might
			// actually be images.
			maxRead := cfg.MediaPolicy.EffectiveMaxImageBytes()
			if maxRead <= 0 {
				maxRead = config.DefaultMaxImageBytes
			}
			// +1 so we can detect overrun via a single comparison
			// instead of counting bytes during the read.
			limited := io.LimitReader(resp.Body, maxRead+1)
			body, err := io.ReadAll(limited)
			_ = resp.Body.Close()
			if err != nil {
				// Mirror the block-event surface of every other
				// media-policy deny path: structured audit log,
				// reverse-proxy-specific scan-blocked metric, and
				// the 403 request counter. Otherwise read failures
				// would disappear from SIEM and the media-policy
				// metric cardinality.
				rp.logger.LogBlocked(actx, "media_policy", "media response read error")
				rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
				rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "media_policy")
				replaceWithMediaBlockResponse(resp, "media response read error")
				return nil
			}
			oversize := int64(len(body)) > maxRead
			verdict := applyMediaPolicy(cfg, mediaCT, body)
			// If oversized, synthesize a block verdict with an
			// explicit exposure payload so the exposure event still
			// fires for oversize images.
			if oversize {
				verdict = MediaPolicyVerdict{
					Blocked:     true,
					BlockReason: fmt.Sprintf("media_policy: image size %d exceeds limit %d", len(body), maxRead),
					MediaType:   canonCT,
					Exposure: &MediaExposureFields{
						ContentType: canonCT,
						SizeBytes:   len(body),
						Blocked:     true,
						BlockReason: fmt.Sprintf("media_policy: image size %d exceeds limit %d", len(body), maxRead),
					},
				}
			}
			logMediaExposureIfPresent(rp.logger, actx, verdict, "reverse")
			if verdict.Blocked {
				rp.logger.LogBlocked(actx, "media_policy", verdict.BlockReason)
				rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
				rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "media_policy")
				replaceWithMediaBlockResponse(resp, verdict.BlockReason)
				return nil
			}
			if verdict.StripResult != nil && verdict.StripResult.Changed() {
				body = verdict.Body
				resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
				// Clear body-derived validators. Content-MD5
				// describes a hash of the upstream bytes - stale
				// after metadata stripping, and a validating client
				// or intermediary will reject the response.
				resp.Header.Del("ETag")
				resp.Header.Del("Digest")
				resp.Header.Del("Content-MD5")
			}
			// Media responses do not go through text injection
			// scanning - rewrap the body and return.
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
				strconv.Itoa(resp.StatusCode))
			return nil
		}
	}

	// Skip remaining binary content types (non-media application/*, etc.).
	if isBinaryMIME(mediaCT) {
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
			strconv.Itoa(resp.StatusCode))
		return nil
	}

	// Response-scanning short-circuit. Runs AFTER the media policy branch
	// above so disabling response scanning does not silently bypass image
	// metadata stripping, audio/video blocks, or exposure events.
	if !cfg.ResponseScanning.Enabled {
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
			strconv.Itoa(resp.StatusCode))
		return nil
	}
	if revRespExempt {
		actx := newHTTPAuditContext(rp.logger, resp.Request.Method, resp.Request.URL.String(), clientIP, requestID, "")
		rp.logger.LogResponseScanExempt(actx, revHost)
		rp.metrics.RecordResponseScanExempt(ExemptReasonDomain, TransportReverse)
	}

	// Fail-closed on compressed responses: regex can't match gzipped content.
	// Must check before reading body so compressed injection isn't forwarded.
	if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
		_ = resp.Body.Close()
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "compressed")
		actx := newHTTPAuditContext(rp.logger, resp.Request.Method, resp.Request.URL.String(), clientIP, requestID, "")
		rp.logger.LogResponseScan(actx, config.ActionBlock, 0, []string{"compressed_response"}, nil)
		// Reverse proxy has no session-profiling context; the taint
		// fields that forward.go threads into its EmitOpts are
		// intentionally omitted here and on the SSE / oversize / read-
		// error block paths below. Adding them would require plumbing
		// a session manager through ReverseProxyHandler, which is out
		// of scope for this fix (parity for the existing block paths).
		rp.emitReceipt(receipt.EmitOpts{
			ActionID:  actionID,
			Verdict:   config.ActionBlock,
			Layer:     LayerReverseResponseBlocked,
			Pattern:   "compressed response cannot be scanned",
			Transport: "reverse",
			Method:    resp.Request.Method,
			Target:    targetURL,
			RequestID: requestID,
			Agent:     agent,
		})
		replaceWithBlockResponse(resp, []string{"compressed response cannot be scanned"})
		return nil
	}

	// SSE streaming: hijack the response body so per-event scanning runs
	// inline. Without this the buffered path below caps SSE at the proxy
	// max-body limit and breaks per-event flushing, killing token-by-token
	// UX for any LLM SSE response (OpenAI, Anthropic, Kilo Gateway).
	// httputil.ReverseProxy auto-flushes text/event-stream per write, so
	// the pipe writer's per-event Write reaches the client immediately.
	if IsSSEContentType(resp.Header.Get("Content-Type")) {
		actx := newHTTPAuditContext(rp.logger, resp.Request.Method, resp.Request.URL.String(), clientIP, requestID, "")
		sseLayer := LayerSSEStream
		sseOpts := SSEDispatchOptions{
			IsA2A:      false,
			A2A:        &cfg.A2AScanning,
			GenericSSE: &cfg.ResponseScanning.SSEStreaming,
			Generic: mcp.GenericSSEScanOptions{
				Target:             resp.Request.URL.String(),
				Suppress:           cfg.Suppress,
				ResponseScanExempt: revRespExempt,
				OnFinding: func(err error) {
					rp.logger.LogResponseScan(actx, config.ActionWarn, 0, []string{sseLayer + ": " + err.Error()}, nil)
				},
			},
		}
		onComplete := func(err error) {
			if err == nil {
				return
			}
			// Only an actual scan finding (DLP / injection / oversize /
			// invalid-UTF-8) counts as an sse_stream block in audit. The
			// fixes that landed earlier in this PR - writeSSEEvent now
			// returns errors and the ctx-cancel watcher closes the
			// upstream body - surface client disconnects and broken-pipe
			// errors here too. Misclassifying those as sse_stream blocks
			// would inflate the block metric and write misleading audit
			// lines for what are normal stream-end conditions.
			if !IsSSEStreamFinding(err) {
				rp.logger.LogError(actx, err)
				return
			}
			// Signed receipt for SSE stream findings. Mirrors
			// forward.go (L1366) and intercept.go (L1158) for parity
			// across transports - one decision receipt per finding,
			// reusing the actionID generated at modifyResponse entry so
			// downstream chain analysis sees a coherent decision graph.
			rp.logger.LogResponseScan(actx, config.ActionBlock, 0, []string{sseLayer + ": " + err.Error()}, nil)
			rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, sseLayer)
			rp.emitReceipt(receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     sseLayer,
				Pattern:   err.Error(),
				Transport: "reverse",
				Method:    resp.Request.Method,
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			})
		}
		resp.Body = HijackResponseForSSE(resp.Request.Context(), resp, sc, sseOpts, onComplete)
		// SSE is open-ended; the upstream Content-Length (if any) becomes
		// meaningless once we strip events through the pipe. -1 instructs
		// httputil.ReverseProxy to chunk the response.
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method, strconv.Itoa(resp.StatusCode))
		return nil
	}

	// Read response body with size limit. Use a separate limited reader
	// so the original body remains open for oversized passthrough.
	maxBytes := reverseProxyMaxBodyBytes
	limited := io.LimitReader(resp.Body, int64(maxBytes)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		// Fail-closed: can't read body, can't scan it.
		_ = resp.Body.Close()
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "read_error")
		actx := newHTTPAuditContext(rp.logger, resp.Request.Method, resp.Request.URL.String(), clientIP, requestID, "")
		rp.logger.LogResponseScan(actx, config.ActionBlock, 0, []string{"response_read_error"}, nil)
		rp.emitReceipt(receipt.EmitOpts{
			ActionID:  actionID,
			Verdict:   config.ActionBlock,
			Layer:     LayerReverseResponseBlocked,
			Pattern:   "response read error",
			Transport: "reverse",
			Method:    resp.Request.Method,
			Target:    targetURL,
			RequestID: requestID,
			Agent:     agent,
		})
		replaceWithBlockResponse(resp, []string{"response read error"})
		return nil
	}

	// Oversized body: fail-closed block. An attacker controlling the upstream
	// can pad the first maxBytes and place injection text after the scanning
	// window. This matches request-side behavior (bodyscan.go blocks oversized
	// requests) and ensures response scanning cannot be bypassed by size.
	if len(body) > maxBytes {
		_ = resp.Body.Close()
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "oversized")
		actx := newHTTPAuditContext(rp.logger, resp.Request.Method, resp.Request.URL.String(), clientIP, requestID, "")
		rp.logger.LogResponseScan(actx, config.ActionBlock, 0, []string{"oversized_response"}, nil)
		rp.emitReceipt(receipt.EmitOpts{
			ActionID:  actionID,
			Verdict:   config.ActionBlock,
			Layer:     LayerReverseResponseBlocked,
			Pattern:   "response exceeds scanning limit",
			Transport: "reverse",
			Method:    resp.Request.Method,
			Target:    targetURL,
			RequestID: requestID,
			Agent:     agent,
		})
		replaceWithBlockResponse(resp, []string{"response exceeds scanning limit"})
		return nil
	}

	// Body fully read - close the original.
	_ = resp.Body.Close()

	// Empty body: nothing to scan.
	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = 0
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
			strconv.Itoa(resp.StatusCode))
		return nil
	}

	// Browser Shield on reverse proxy responses - uses shared pipeline.
	shieldChanged := false
	if rp.shieldEngine != nil && cfg.BrowserShield.Enabled {
		revHost := resp.Request.URL.Hostname()
		if !isShieldExempt(revHost, cfg.BrowserShield.ExemptDomains) {
			if cfg.BrowserShield.MaxShieldBytes <= 0 || len(body) <= cfg.BrowserShield.MaxShieldBytes {
				originalBodyBytes := len(body)
				var summary *receipt.ShieldSummary
				body, summary = runShieldPipelineSharedResult(rp.shieldEngine, body, resp.Header.Get("Content-Type"), resp.Header, &cfg.BrowserShield, rp.metrics, "reverse")
				if summary != nil {
					shieldChanged = true
					summary.BodyBytes = originalBodyBytes
					summary.ScannedBytes = originalBodyBytes
					// Reverse proxy currently has no session manager
					// context, so it reports the configured cap but
					// records zero adaptive signals.
					summary.AdaptiveSignalsRecorded = 0
					summary.AdaptiveSignalMaxPerBody = browserShieldAdaptiveSignalCap
					rp.emitReceipt(receipt.EmitOpts{
						ActionID:       receipt.NewActionID(),
						ParentActionID: actionID,
						Verdict:        config.ActionAllow,
						Layer:          browserShieldLayer,
						Pattern:        browserShieldPattern,
						Severity:       browserShieldSeverity,
						Shield:         summary,
						Transport:      "reverse",
						Method:         resp.Request.Method,
						Target:         shieldReceiptTarget(resp.Request.URL.String()),
						RequestID:      requestID,
						Agent:          agent,
					})
				}
			}
		}
	}
	if shieldChanged {
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		resp.Header.Del("ETag")
		resp.Header.Del("Content-MD5")
		resp.Header.Del("Digest")
	}

	// Scan the response text for injection patterns.
	text := string(body)
	result := sc.ScanResponse(resp.Request.Context(), text)

	// Filter out suppressed findings (parity with fetch proxy).
	if !result.Clean && len(cfg.Suppress) > 0 {
		var kept []scanner.ResponseMatch
		for _, m := range result.Matches {
			if !config.IsSuppressed(m.PatternName, resp.Request.URL.String(), cfg.Suppress) {
				kept = append(kept, m)
			} else {
				rp.metrics.RecordResponseScanExempt(ExemptReasonSuppress, TransportReverse)
			}
		}
		result.Matches = kept
		result.Clean = len(kept) == 0
	}

	// Capture observer: record reverse proxy response scan verdict for policy replay.
	// Runs after suppression so the recorded action matches runtime.
	{
		revAction := cfg.ResponseScanning.Action
		if revRespExempt {
			revAction = config.ActionWarn
		}
		if result.Clean {
			revAction = config.ActionAllow
		}
		rp.captureObs.ObserveResponseVerdict(resp.Request.Context(), &capture.ResponseVerdictRecord{
			Subsurface:        "response_reverse",
			Transport:         "reverse",
			SessionID:         captureSessionKey(resp.Request.Header.Get("X-Pipelock-Agent"), reverseClientIP(resp.Request)),
			SessionIDOriginal: captureSessionKeyOriginal(resp.Request.Header.Get("X-Pipelock-Agent"), reverseClientIP(resp.Request)),
			ConfigHash:        cfg.CanonicalPolicyHash(),
			Agent:             resp.Request.Header.Get("X-Pipelock-Agent"),
			Profile:           edition.ProfileDefault,
			ActionClass:       captureHTTPActionClass(resp.Request.Method),
			Request:           capture.CaptureRequest{Method: resp.Request.Method, URL: resp.Request.URL.String()},
			TransformKind:     capture.TransformRaw,
			RawFindings:       responseMatchesToFindings(result.Matches, revAction),
			EffectiveFindings: responseMatchesToFindings(result.Matches, revAction),
			EffectiveAction:   revAction,
			Outcome:           captureOutcome(revAction, result.Clean),
		})
	}

	if result.Clean {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
			strconv.Itoa(resp.StatusCode))
		return nil
	}

	action := cfg.ResponseScanning.Action
	// Exempt domains: pin to warn for visibility without blocking.
	if revRespExempt {
		action = config.ActionWarn
	}

	var patternNames []string
	for _, m := range result.Matches {
		patternNames = append(patternNames, m.PatternName)
	}
	actx := newHTTPAuditContext(rp.logger, resp.Request.Method, resp.Request.URL.String(), clientIP, requestID, "")
	rp.logger.LogResponseScan(actx, action, len(patternNames), patternNames, nil)

	// block and ask: unconditional block regardless of enforce mode.
	// ask has no approver on the reverse proxy (no terminal), so it
	// fails closed to block. This matches forward/fetch behavior where
	// block and ask are in the same switch case (forward.go:835-840).
	if action == config.ActionBlock || action == config.ActionAsk {
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "injection")
		replaceWithBlockResponse(resp, patternNames)
		return nil
	}

	if action == config.ActionStrip {
		if result.TransformedContent != "" {
			// Replace body with redacted content. Remove body-derived
			// validators that no longer match the stripped content
			// (matches forward.go:860-863).
			stripped := []byte(result.TransformedContent)
			resp.Body = io.NopCloser(bytes.NewReader(stripped))
			resp.ContentLength = int64(len(stripped))
			resp.Header.Set("Content-Length", strconv.Itoa(len(stripped)))
			resp.Header.Del("Etag")
			resp.Header.Del("Content-Md5")
			resp.Header.Del("Digest")
			rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
				strconv.Itoa(resp.StatusCode))
			return nil
		}
		// Strip failed: detection came from a transformed pass (vowel-fold,
		// leetspeak, etc.) where the scanner can't produce a redacted version.
		// Unconditional block regardless of enforce - forwarding injected
		// content is a security bypass. Matches forward.go:865-869.
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "injection")
		replaceWithBlockResponse(resp, patternNames)
		return nil
	}

	// Warn mode: pass through unchanged.
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
		strconv.Itoa(resp.StatusCode))
	return nil
}

// errorHandler writes a JSON error when the upstream is unreachable.
// The concrete error is logged server-side but not exposed to the client
// to avoid leaking internal topology (dial addresses, TLS state, DNS).
func (rp *ReverseProxyHandler) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	clientIP, _ := r.Context().Value(ctxKeyClientIP).(string)
	requestID, _ := r.Context().Value(ctxKeyRequestID).(string)
	actx := newHTTPAuditContext(rp.logger, r.Method, r.URL.String(), clientIP, requestID, "")
	if blockedErr, ok := blockedRequestErrorFrom(err); ok {
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, blockedErr.layer)
		rp.logger.LogBlocked(actx, blockedErr.layer, blockedErr.detail)
		writeReverseProxyBlock(w, http.StatusForbidden,
			blockInfoFor(blockreason.EnvelopeVerifyFailed, blockedErr.layer),
			blockedErr.reason)
		return
	}

	rp.metrics.RecordReverseProxyRequest(r.Method, "502")
	rp.logger.LogError(actx, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	resp := ReverseProxyBlockResponse{
		Error:   "upstream unavailable",
		Blocked: false,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// writeReverseProxyBlock writes a JSON block response for request-side blocks
// (DLP, kill switch, fail-closed). Response-side blocks use replaceWithBlockResponse.
//
// Sets the X-Pipelock-Block-Reason header set from info BEFORE WriteHeader so
// agents can react intelligently. Every caller MUST supply a non-zero info.
func writeReverseProxyBlock(w http.ResponseWriter, status int, info blockreason.Info, reason string) {
	info.SetHeaders(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := ReverseProxyBlockResponse{
		Error:       "blocked by pipelock",
		Blocked:     true,
		BlockReason: reason,
		Direction:   scanDirectionRequest,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// replaceWithBlockResponse replaces the upstream response with a 403 JSON
// block body. Used for block, ask (fail-closed), and strip-failed paths.
// Scrubs ALL upstream headers to prevent leaking Set-Cookie, Content-Encoding,
// Etag, and other upstream headers through a synthetic block response. The
// forward proxy avoids this by never copying headers on block; since
// httputil.ReverseProxy copies them before ModifyResponse, we clear them.
// replaceWithMediaBlockResponse replaces the upstream response with a 403
// JSON body tagged as a media-policy block. Separate from
// replaceWithBlockResponse because that builder hardcodes the
// "injection: ..." block reason prefix - media-policy blocks are not
// injection findings, and reporting them that way would mislead the
// client about what the proxy rejected.
func replaceWithMediaBlockResponse(resp *http.Response, reason string) {
	blockResp := ReverseProxyBlockResponse{
		Error:       "response blocked by pipelock",
		Blocked:     true,
		BlockReason: reason,
		Direction:   scanDirectionResponse,
	}
	blockBody, _ := json.Marshal(blockResp)
	resp.Body = io.NopCloser(bytes.NewReader(blockBody))
	resp.ContentLength = int64(len(blockBody))
	resp.StatusCode = http.StatusForbidden
	resp.Status = http.StatusText(http.StatusForbidden)
	for k := range resp.Header {
		delete(resp.Header, k)
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(blockBody)))
}

func replaceWithBlockResponse(resp *http.Response, patternNames []string) {
	blockResp := ReverseProxyBlockResponse{
		Error:       "response blocked by pipelock",
		Blocked:     true,
		BlockReason: fmt.Sprintf("injection: %s", strings.Join(patternNames, ", ")),
		Direction:   scanDirectionResponse,
	}
	blockBody, _ := json.Marshal(blockResp)
	resp.Body = io.NopCloser(bytes.NewReader(blockBody))
	resp.ContentLength = int64(len(blockBody))
	resp.StatusCode = http.StatusForbidden
	resp.Status = http.StatusText(http.StatusForbidden)
	// Clear all upstream headers. The blocked response is entirely
	// synthetic - no upstream header should survive.
	for k := range resp.Header {
		delete(resp.Header, k)
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(blockBody)))
}

// isBinaryMIME returns true for content types that are clearly binary
// (images, audio, video) and should not be scanned for text patterns.
func isBinaryMIME(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, _ := mime.ParseMediaType(ct)
	return strings.HasPrefix(mediaType, "image/") ||
		strings.HasPrefix(mediaType, "audio/") ||
		strings.HasPrefix(mediaType, "video/")
}

// reverseClientIP extracts a client IP for capture session keying. Falls
// back to RemoteAddr when SplitHostPort fails (e.g., raw IP without port
// from a unix socket or test fixture).
func reverseClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
