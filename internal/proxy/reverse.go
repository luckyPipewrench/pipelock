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
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
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
		req.Host = upstream.Host
	}

	// ModifyResponse scans response bodies for injection.
	proxy.ModifyResponse = rp.modifyResponse

	// ErrorHandler returns a JSON error on upstream failures.
	proxy.ErrorHandler = rp.errorHandler

	// Signing transport: sits between httputil.ReverseProxy and
	// http.DefaultTransport. Runs envelope injection + RFC 9421 signing
	// on the post-Director request so @target-uri matches the upstream
	// URL the transport is actually about to dial. A nil envelope
	// emitter short-circuits to the base transport.
	proxy.Transport = &reverseSigningRoundTripper{
		base: http.DefaultTransport,
		rp:   rp,
	}

	rp.proxy = proxy
	return rp
}

// SetEnvelopeEmitter sets the atomic pointer to the envelope emitter.
// Must be called before serving requests if mediation envelopes are enabled.
func (rp *ReverseProxyHandler) SetEnvelopeEmitter(ptr *atomic.Pointer[envelope.Emitter]) {
	rp.envelopeEmitterPtr = ptr
}

// SetRedactionRuntimePtr attaches the atomic pointer to the request-body
// redaction runtime snapshot. The pointer dereferences to nil when redaction
// is disabled, so scanRequestBody will skip the redaction step gracefully.
// Must be called before serving requests if redaction is enabled.
func (rp *ReverseProxyHandler) SetRedactionRuntimePtr(ptr *atomic.Pointer[redactionRuntime]) {
	rp.redactionRuntimePtr = ptr
}

// ServeHTTP handles incoming requests: scan the request body for DLP,
// then forward to upstream via the reverse proxy.
func (rp *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip inbound mediation envelope headers to prevent forgery.
	envelope.StripInbound(r.Header)

	cfg := rp.cfgPtr.Load()
	sc := rp.scPtr.Load()
	clientIP, requestID := requestMeta(r)
	agent, _ := r.Context().Value(ctxKeyAgent).(string)
	ctx := scanner.WithDLPWarnContext(r.Context(), scanner.DLPWarnContext{
		Method: r.Method, URL: r.URL.String(), ClientIP: clientIP,
		RequestID: requestID, Agent: agent, Transport: "reverse",
	})
	ctx = context.WithValue(ctx, ctxKeyClientIP, clientIP)
	ctx = context.WithValue(ctx, ctxKeyRequestID, requestID)
	r = r.WithContext(ctx)

	// Kill switch: deny all traffic when active.
	if rp.ks != nil && rp.ks.IsActive() {
		rp.metrics.RecordReverseProxyRequest(r.Method, "503")
		rp.metrics.RecordKillSwitchDenial("reverse_proxy", r.URL.Path)
		writeReverseProxyBlock(w, http.StatusServiceUnavailable,
			"kill switch active")
		return
	}

	// Scan request path and query for DLP patterns. Secrets embedded in
	// the URL path or query string would bypass body/header DLP without
	// this check. Intentionally not gated by RequestBodyScanning.Enabled:
	// URL-based exfiltration must always be caught even when body scanning
	// is disabled. Only the path+query are agent-controlled; the upstream
	// host is operator-configured so we skip the full URL pipeline (SSRF,
	// blocklist, rate limit) which only applies to agent-chosen destinations.
	if pathQuery := r.URL.RequestURI(); pathQuery != "" {
		pathDLP := sc.ScanTextForDLP(r.Context(), pathQuery)

		// Capture observer: record reverse proxy URL DLP verdict for policy replay.
		{
			urlDLPAction := ""
			if !pathDLP.Clean {
				urlDLPAction = cfg.RequestBodyScanning.Action
				if urlDLPAction == "" {
					urlDLPAction = config.ActionBlock
				}
			}
			rp.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
				Subsurface:      "dlp_reverse_url",
				Transport:       "reverse",
				Request:         capture.CaptureRequest{Method: r.Method, URL: r.URL.String()},
				TransformKind:   capture.TransformRaw,
				RawFindings:     dlpMatchesToFindings(pathDLP.Matches),
				EffectiveAction: urlDLPAction,
				Outcome:         captureOutcome(urlDLPAction, pathDLP.Clean),
			})
		}

		if !pathDLP.Clean {
			action := cfg.RequestBodyScanning.Action
			if action == "" {
				action = config.ActionBlock
			}
			patternNames := dlpMatchNames(pathDLP.Matches)
			rp.logger.LogBodyDLP(newHTTPAuditContext(rp.logger, r.Method, r.URL.String(), clientIP, requestID, ""),
				action,
				len(patternNames), patternNames, nil)

			if action == config.ActionBlock && cfg.EnforceEnabled() {
				rp.metrics.RecordReverseProxyRequest(r.Method, "403")
				rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, "url_dlp")
				reason := fmt.Sprintf("URL DLP: %s", strings.Join(patternNames, ", "))
				writeReverseProxyBlock(w, http.StatusForbidden, reason)
				return
			}
		}
	}

	// Scan request headers for DLP patterns (secret exfiltration via headers).
	if cfg.RequestBodyScanning.Enabled && cfg.RequestBodyScanning.ScanHeaders {
		headerResult := scanRequestHeaders(r.Context(), r.Header, cfg, sc)
		if headerResult != nil {
			action := cfg.RequestBodyScanning.Action
			if action == "" {
				action = config.ActionBlock
			}
			patternNames := dlpMatchNames(headerResult.DLPMatches)
			rp.logger.LogHeaderDLP(newHTTPAuditContext(rp.logger, r.Method, r.URL.String(), clientIP, requestID, ""), headerResult.HeaderName,
				action, patternNames, nil)

			if action == config.ActionBlock && cfg.EnforceEnabled() {
				rp.metrics.RecordReverseProxyRequest(r.Method, "403")
				rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, "header_dlp")
				reason := fmt.Sprintf("header DLP: %s", strings.Join(patternNames, ", "))
				writeReverseProxyBlock(w, http.StatusForbidden, reason)
				return
			}
		}
	}

	// Scan request body for DLP patterns (secret exfiltration).
	forwardedVerdict := config.ActionAllow
	var reverseBodyBytes []byte
	if r.Body != nil && r.ContentLength != 0 && cfg.RequestBodyScanning.Enabled {
		var redaction *redactionRuntime
		if rp.redactionRuntimePtr != nil {
			redaction = rp.redactionRuntimePtr.Load()
		}
		blocked, verdict, bodyBytes := rp.scanRequest(w, r, cfg, sc, redaction)
		if blocked {
			return
		}
		if verdict != "" {
			forwardedVerdict = verdict
		}
		reverseBodyBytes = bodyBytes
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
	var admissionEmitter *envelope.Emitter
	if rp.envelopeEmitterPtr != nil {
		admissionEmitter = rp.envelopeEmitterPtr.Load()
	}
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
		ctx = context.WithValue(ctx, ctxKeyReverseEnvelopeCfg, cfg)
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
// *http.Request. A nil emitter or missing build opts skips signing —
// the transport is also used by reverse proxies configured without
// mediation envelopes, and must not fail in that case. Any actual
// signing failure returns a fail-closed block so sign:true never
// degrades to unsigned upstream traffic.
type reverseSigningRoundTripper struct {
	base http.RoundTripper
	rp   *ReverseProxyHandler
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
		// No emitter was live at admission time — signing was off
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
func (rp *ReverseProxyHandler) scanRequest(w http.ResponseWriter, r *http.Request, cfg *config.Config, sc *scanner.Scanner, redaction *redactionRuntime) (blocked bool, verdict string, body []byte) {
	// Skip binary content types — no secrets to scan in images/video.
	if isBinaryMIME(r.Header.Get("Content-Type")) {
		return false, "", nil
	}

	maxBytes := cfg.RequestBodyScanning.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = reverseProxyMaxBodyBytes
	}

	bodyReq := BodyScanRequest{
		Body:            r.Body,
		ContentType:     r.Header.Get("Content-Type"),
		ContentEncoding: r.Header.Get("Content-Encoding"),
		MaxBytes:        maxBytes,
		Scanner:         sc,
		Host:            rp.upstream.Hostname(),
	}
	applyBodyScanRedaction(&bodyReq, redaction)
	bodyBytes, result := scanRequestBody(r.Context(), bodyReq)

	// Capture observer: record reverse proxy request DLP verdict for policy replay.
	{
		bodyAction := ""
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
			Subsurface:      "dlp_reverse_request",
			Transport:       "reverse",
			Request:         capture.CaptureRequest{Method: r.Method, URL: r.URL.String()},
			TransformKind:   capture.TransformJoinedFields,
			RawFindings:     bodyScanToFindings(result),
			EffectiveAction: bodyAction,
			Outcome:         captureOutcome(bodyAction, result.Clean),
		})
	}

	if result.Clean {
		// Re-wrap the buffered body so the reverse proxy can forward
		// it. GetBody lets stdlib replay on redirect hops even though
		// the reverse proxy's upstream client does not follow redirects
		// by default — setting it is cheap and future-proofs the path
		// against a future Transport override that does.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
		bodyBytesCopy := bodyBytes
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytesCopy)), nil
		}
		return false, config.ActionAllow, bodyBytes
	}

	action := result.Action
	if action == "" {
		action = cfg.RequestBodyScanning.Action
	}
	if action == "" {
		action = config.ActionBlock
	}

	// Log the DLP finding.
	patternNames := dlpMatchNames(result.DLPMatches)
	reason := result.Reason
	if reason == "" && len(patternNames) > 0 {
		reason = fmt.Sprintf("DLP: %s", strings.Join(patternNames, ", "))
	}
	if reason == "" {
		reason = "request body contains secret patterns"
	}
	clientIP, _ := r.Context().Value(ctxKeyClientIP).(string)
	requestID, _ := r.Context().Value(ctxKeyRequestID).(string)
	actx := newHTTPAuditContext(rp.logger, r.Method, r.URL.String(), clientIP, requestID, "")
	rp.logger.LogBodyDLP(actx, action, len(patternNames), patternNames, nil)

	// Fail-closed transport errors (consumed-but-unreplayable body) and
	// redaction gate failures must block regardless of enforce mode.
	if isFailClosedBodyResult(result, bodyBytes) {
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, "dlp")
		writeReverseProxyBlock(w, http.StatusForbidden, reason)
		return true, config.ActionBlock, nil
	}

	if action == config.ActionBlock && cfg.EnforceEnabled() {
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, "dlp")
		writeReverseProxyBlock(w, http.StatusForbidden, reason)
		return true, config.ActionBlock, nil
	}

	// Warn mode: re-wrap body and continue.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	bodyBytesCopy := bodyBytes
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytesCopy)), nil
	}
	return false, action, bodyBytes
}

// modifyResponse scans the upstream response body for prompt injection.
// Called by httputil.ReverseProxy after receiving the upstream response.
func (rp *ReverseProxyHandler) modifyResponse(resp *http.Response) error {
	cfg := rp.cfgPtr.Load()
	sc := rp.scPtr.Load()
	clientIP, _ := resp.Request.Context().Value(ctxKeyClientIP).(string)
	requestID, _ := resp.Request.Context().Value(ctxKeyRequestID).(string)

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
				// describes a hash of the upstream bytes — stale
				// after metadata stripping, and a validating client
				// or intermediary will reject the response.
				resp.Header.Del("ETag")
				resp.Header.Del("Digest")
				resp.Header.Del("Content-MD5")
			}
			// Media responses do not go through text injection
			// scanning — rewrap the body and return.
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
		replaceWithBlockResponse(resp, []string{"compressed response cannot be scanned"})
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
		replaceWithBlockResponse(resp, []string{"response exceeds scanning limit"})
		return nil
	}

	// Body fully read — close the original.
	_ = resp.Body.Close()

	// Empty body: nothing to scan.
	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = 0
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
			strconv.Itoa(resp.StatusCode))
		return nil
	}

	// Browser Shield on reverse proxy responses — uses shared pipeline.
	if rp.shieldEngine != nil && cfg.BrowserShield.Enabled {
		revHost := resp.Request.URL.Hostname()
		if !isShieldExempt(revHost, cfg.BrowserShield.ExemptDomains) {
			if cfg.BrowserShield.MaxShieldBytes <= 0 || len(body) <= cfg.BrowserShield.MaxShieldBytes {
				body = runShieldPipelineShared(rp.shieldEngine, body, resp.Header.Get("Content-Type"), resp.Header, &cfg.BrowserShield, rp.metrics, "reverse")
			}
		}
	}

	// Scan the response text for injection patterns.
	text := string(body)
	result := sc.ScanResponse(resp.Request.Context(), text)

	// Capture observer: record reverse proxy response scan verdict for policy replay.
	// Apply exempt override before capture so the recorded action matches runtime.
	{
		revAction := cfg.ResponseScanning.Action
		if revRespExempt {
			revAction = config.ActionWarn
		}
		if result.Clean {
			revAction = ""
		}
		rp.captureObs.ObserveResponseVerdict(resp.Request.Context(), &capture.ResponseVerdictRecord{
			Subsurface:        "response_reverse",
			Transport:         "reverse",
			Request:           capture.CaptureRequest{Method: resp.Request.Method, URL: resp.Request.URL.String()},
			TransformKind:     capture.TransformRaw,
			RawFindings:       responseMatchesToFindings(result.Matches, revAction),
			EffectiveFindings: responseMatchesToFindings(result.Matches, revAction),
			EffectiveAction:   revAction,
			Outcome:           captureOutcome(revAction, result.Clean),
		})
	}

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
		// Unconditional block regardless of enforce — forwarding injected
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
		writeReverseProxyBlock(w, http.StatusForbidden, blockedErr.reason)
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
func writeReverseProxyBlock(w http.ResponseWriter, status int, reason string) {
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
// "injection: ..." block reason prefix — media-policy blocks are not
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
	// synthetic — no upstream header should survive.
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
