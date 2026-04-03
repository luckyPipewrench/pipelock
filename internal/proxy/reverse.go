// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
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
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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
	upstream   *url.URL
	proxy      *httputil.ReverseProxy
	cfgPtr     *atomic.Pointer[config.Config]
	scPtr      *atomic.Pointer[scanner.Scanner]
	logger     *audit.Logger
	metrics    *metrics.Metrics
	ks         *killswitch.Controller
	captureObs capture.CaptureObserver
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
) *ReverseProxyHandler {
	if captureObs == nil {
		captureObs = capture.NopObserver{}
	}
	rp := &ReverseProxyHandler{
		upstream:   upstream,
		cfgPtr:     cfgPtr,
		scPtr:      scPtr,
		logger:     logger,
		metrics:    m,
		ks:         ks,
		captureObs: captureObs,
	}

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

	rp.proxy = proxy
	return rp
}

// ServeHTTP handles incoming requests: scan the request body for DLP,
// then forward to upstream via the reverse proxy.
func (rp *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := rp.cfgPtr.Load()
	sc := rp.scPtr.Load()

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
			rp.logger.LogBodyDLP(audit.LogContext{Method: r.Method, URL: r.URL.String()}, action,
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
			rp.logger.LogHeaderDLP(audit.LogContext{Method: r.Method, URL: r.URL.String()}, headerResult.HeaderName,
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
	if r.Body != nil && r.ContentLength != 0 && cfg.RequestBodyScanning.Enabled {
		if blocked := rp.scanRequest(w, r, cfg, sc); blocked {
			return
		}
	}

	// Forward to upstream. Response scanning happens in modifyResponse.
	rp.proxy.ServeHTTP(w, r)
}

// scanRequest reads and scans the request body for DLP patterns.
// Returns true if the request was blocked (response already written).
func (rp *ReverseProxyHandler) scanRequest(w http.ResponseWriter, r *http.Request, cfg *config.Config, sc *scanner.Scanner) bool {
	// Skip binary content types — no secrets to scan in images/video.
	if isBinaryMIME(r.Header.Get("Content-Type")) {
		return false
	}

	maxBytes := cfg.RequestBodyScanning.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = reverseProxyMaxBodyBytes
	}

	bodyBytes, result := scanRequestBody(r.Context(), BodyScanRequest{
		Body:            r.Body,
		ContentType:     r.Header.Get("Content-Type"),
		ContentEncoding: r.Header.Get("Content-Encoding"),
		MaxBytes:        maxBytes,
		Scanner:         sc,
	})

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
		// Re-wrap the buffered body so the reverse proxy can forward it.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
		return false
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
	actx := audit.LogContext{
		Method: r.Method,
		URL:    r.URL.String(),
	}
	rp.logger.LogBodyDLP(actx, action, len(patternNames), patternNames, nil)

	// Fail-closed: when bodyBytes is nil the body was consumed but couldn't
	// be buffered (oversize, compressed, read error, multipart parse error).
	// Always block regardless of action/enforce — forwarding an empty body
	// corrupts the upstream request and is a DLP bypass.
	if bodyBytes == nil {
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, "dlp")
		writeReverseProxyBlock(w, http.StatusForbidden, reason)
		return true
	}

	if action == config.ActionBlock && cfg.EnforceEnabled() {
		rp.metrics.RecordReverseProxyRequest(r.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionRequest, "dlp")
		writeReverseProxyBlock(w, http.StatusForbidden, reason)
		return true
	}

	// Warn mode: re-wrap body and continue.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	return false
}

// modifyResponse scans the upstream response body for prompt injection.
// Called by httputil.ReverseProxy after receiving the upstream response.
func (rp *ReverseProxyHandler) modifyResponse(resp *http.Response) error {
	cfg := rp.cfgPtr.Load()
	sc := rp.scPtr.Load()

	// Record the final client-visible status at each exit point, not here.
	// The upstream status may be rewritten to 403 by scanning decisions.

	// Scan all responses when enabled. Exempt domains are still scanned for
	// visibility but findings are pinned to warn with no adaptive scoring.
	revHost := resp.Request.URL.Hostname()
	revRespExempt := isResponseScanExempt(revHost, cfg.ResponseScanning.ExemptDomains)
	if !cfg.ResponseScanning.Enabled {
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
			strconv.Itoa(resp.StatusCode))
		return nil
	}
	if revRespExempt {
		actx := audit.LogContext{
			Method: resp.Request.Method,
			URL:    resp.Request.URL.String(),
		}
		rp.logger.LogResponseScanExempt(actx, revHost)
	}

	// Skip binary content types.
	if isBinaryMIME(resp.Header.Get("Content-Type")) {
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method,
			strconv.Itoa(resp.StatusCode))
		return nil
	}

	// Fail-closed on compressed responses: regex can't match gzipped content.
	// Must check before reading body so compressed injection isn't forwarded.
	if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
		_ = resp.Body.Close()
		rp.metrics.RecordReverseProxyRequest(resp.Request.Method, "403")
		rp.metrics.RecordReverseProxyScanBlocked(scanDirectionResponse, "compressed")
		actx := audit.LogContext{
			Method: resp.Request.Method,
			URL:    resp.Request.URL.String(),
		}
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
		actx := audit.LogContext{
			Method: resp.Request.Method,
			URL:    resp.Request.URL.String(),
		}
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
	actx := audit.LogContext{
		Method: resp.Request.Method,
		URL:    resp.Request.URL.String(),
	}
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
	rp.metrics.RecordReverseProxyRequest(r.Method, "502")
	actx := audit.LogContext{
		Method: r.Method,
		URL:    r.URL.String(),
	}
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
