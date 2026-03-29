// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// recEscalationLevel returns the live escalation level from a session recorder.
// Returns 0 (normal) when rec is nil (profiling disabled).
func recEscalationLevel(rec session.Recorder) int {
	if rec != nil {
		return rec.EscalationLevel()
	}
	return 0
}

// interceptRecordSignal records an adaptive threat signal on the session recorder
// for the intercepted request. Handles nil rec, disabled adaptive config, and
// escalation transitions (log, audit, metrics gauge updates). Used by
// newInterceptHandler to feed signals back to the adaptive system.
func interceptRecordSignal(rec session.Recorder, sig session.SignalType, cfg *config.Config, logger *audit.Logger, _ *metrics.Metrics, p *Proxy, clientIP, agent, requestID string) {
	if rec == nil || !cfg.AdaptiveEnforcement.Enabled {
		return
	}
	sessionKey := clientIP
	if agent != "" && agent != agentAnonymous {
		sessionKey = agent + "|" + clientIP
	}
	var m *metrics.Metrics
	if p != nil {
		m = p.metrics
	}
	decide.RecordEscalation(rec, sig, decide.EscalationParams{
		Threshold: cfg.AdaptiveEnforcement.EscalationThreshold,
		Logger:    logger,
		Metrics:   m,
		Session:   sessionKey,
		ClientIP:  clientIP,
		RequestID: requestID,
	})
}

// interceptReadHeaderTimeout is the maximum time to read request headers on an
// intercepted TLS connection. 30 seconds is generous for local proxy traffic.
const interceptReadHeaderTimeout = 30 * time.Second

// scannerLabelA2A is the scanner label for A2A protocol findings in logs and
// metrics. Distinguishes A2A-specific scanning from generic body_dlp or
// response_scan findings.
const scannerLabelA2A = "a2a_scan"

// interceptHandshakeTimeout is the maximum time for the client-side TLS
// handshake during interception. Prevents goroutine/semaphore exhaustion
// from malicious clients that stall during the handshake.
const interceptHandshakeTimeout = 30 * time.Second

// interceptDefaultMaxResp is the fallback maximum response size for scanning.
// Should not be reached since Validate() enforces max_response_bytes > 0,
// but provides a fail-safe for direct callers that bypass validation.
const interceptDefaultMaxResp = 5 * 1024 * 1024 // 5MB

// bufferedConn wraps a net.Conn with a bufio.Reader so that any bytes
// already buffered (e.g. from SNI peeking) are read before falling through
// to the underlying connection. This prevents data loss when passing a
// connection from verifySNI to interceptTunnel.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// wrapBuffered returns a net.Conn that reads from the bufio.Reader first
// (draining any buffered bytes from SNI peeking), then falls through to
// the underlying connection. If nothing is buffered, returns conn as-is.
func wrapBuffered(conn net.Conn, r *bufio.Reader) net.Conn {
	if r.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: r}
	}
	return conn
}

// dialFunc is a function signature for dialing TCP connections.
// The proxy passes its SSRF-safe dialer to prevent DNS rebinding TOCTOU.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// interceptTunnel performs TLS MITM on a hijacked CONNECT tunnel.
// It terminates TLS with the client using a forged cert, creates an
// http.Server to read inner requests, scans them, and forwards to
// upstream via the provided RoundTripper (or a new http.Transport).
// The ctx controls the overall tunnel lifetime including the TLS handshake.
// The safeDial parameter provides SSRF-safe TCP dialing for the upstream
// connection, preventing DNS rebinding between the scanner check and dial.
func interceptTunnel(
	ctx context.Context,
	clientConn net.Conn,
	targetHost, targetPort string,
	cfg *config.Config,
	sc *scanner.Scanner,
	cache *certgen.CertCache,
	logger *audit.Logger,
	m *metrics.Metrics,
	clientIP, requestID, agent string,
	upstreamRT http.RoundTripper,
	safeDial dialFunc,
	et *scanner.EntropyTracker,
	fb *scanner.FragmentBuffer,
	sm *SessionManager,
	p *Proxy, // when non-nil, CEE state resolved per-request (avoids stale pointers after reload)
	rec session.Recorder, // live escalation level; nil when profiling disabled
) error {
	// Client-side TLS config with forged cert from cache.
	tlsCfg := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := cache.Get(targetHost)
			if err == nil {
				m.SetTLSCertCacheSize(float64(cache.Size()))
			}
			return cert, err
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}

	// TLS handshake with client. Set a deadline to prevent goroutine
	// accumulation from clients that stall during the handshake.
	handshakeDeadline := time.Now().Add(interceptHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(handshakeDeadline) {
		handshakeDeadline = ctxDeadline
	}
	if err := clientConn.SetDeadline(handshakeDeadline); err != nil {
		m.RecordTLSIntercept("deadline_error")
		return fmt.Errorf("set handshake deadline: %w", err)
	}

	tlsConn := tls.Server(clientConn, tlsCfg)
	handshakeStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		m.RecordTLSIntercept("handshake_error")
		logger.LogBlocked("CONNECT", targetHost, "tls_handshake_error", err.Error(), clientIP, requestID, agent)
		return fmt.Errorf("client TLS handshake: %w", err)
	}
	m.RecordTLSHandshake("client", time.Since(handshakeStart))

	// Clear the handshake deadline so it doesn't affect request serving.
	_ = clientConn.SetDeadline(time.Time{})
	defer tlsConn.Close() //nolint:errcheck // best effort

	// Create upstream transport if not provided (tests inject mock).
	if upstreamRT == nil {
		upstream := &http.Transport{
			DialTLSContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
				addr := net.JoinHostPort(targetHost, targetPort)
				// Use SSRF-safe dialer for the TCP connection to prevent
				// DNS rebinding TOCTOU between the scanner check and dial.
				var rawConn net.Conn
				var dialErr error
				if safeDial != nil {
					rawConn, dialErr = safeDial(dialCtx, network, addr)
				} else {
					// Fallback for tests that don't provide a dialer.
					rawConn, dialErr = (&net.Dialer{}).DialContext(dialCtx, network, addr)
				}
				if dialErr != nil {
					return nil, dialErr
				}
				// Layer TLS on top of the SSRF-validated TCP connection.
				tlsCfg := &tls.Config{
					ServerName: targetHost,
					NextProtos: []string{"h2", "http/1.1"},
					MinVersion: tls.VersionTLS12,
				}
				start := time.Now()
				tlsUpstream := tls.Client(rawConn, tlsCfg)
				if err := tlsUpstream.HandshakeContext(dialCtx); err != nil {
					_ = rawConn.Close()
					return nil, err
				}
				m.RecordTLSHandshake("upstream", time.Since(start))
				return tlsUpstream, nil
			},
			ForceAttemptHTTP2:  true, // required with custom DialTLSContext for h2
			DisableCompression: true, // force identity encoding for scanning
		}
		defer upstream.CloseIdleConnections()
		upstreamRT = upstream
	}

	// Serve via http.Server on single-connection listener.
	// http.Server handles HTTP/2 when negotiated via ALPN.
	ln := newSingleConnListener(tlsConn)
	handler := newInterceptHandler(targetHost, targetPort, upstreamRT, cfg, sc, logger, m, clientIP, requestID, agent, et, fb, sm, p, rec)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: interceptReadHeaderTimeout,
		ConnState: func(_ net.Conn, state http.ConnState) {
			// Close the listener when the connection finishes so Serve()
			// exits promptly instead of blocking on Accept() forever.
			if state == http.StateClosed {
				_ = ln.Close()
			}
		},
	}

	// Shut down the server when the context expires (tunnel deadline) to
	// prevent goroutine leaks from srv.Serve blocking on Accept forever.
	// The done channel stops this goroutine when Serve returns normally,
	// preventing accumulation under high CONNECT throughput.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = srv.Close()
		case <-done:
		}
	}()

	// Serve blocks until the connection closes or the server is shut down.
	// Normal termination returns http.ErrServerClosed (from srv.Close above)
	// or net.ErrClosed (from listener). Both are expected.
	err := srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// newInterceptHandler returns an http.Handler that scans and forwards
// intercepted requests. It enforces authority matching, body/header DLP,
// and response injection scanning.
func newInterceptHandler(
	targetHost, targetPort string,
	upstream http.RoundTripper,
	cfg *config.Config,
	sc *scanner.Scanner,
	logger *audit.Logger,
	m *metrics.Metrics,
	clientIP, requestID, agent string,
	et *scanner.EntropyTracker,
	fb *scanner.FragmentBuffer,
	sm *SessionManager,
	p *Proxy, // when non-nil, CEE state resolved per-request (avoids stale pointers after reload)
	rec session.Recorder, // live escalation level; nil when profiling disabled
) http.Handler {
	target := net.JoinHostPort(targetHost, targetPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqStart := time.Now()

		// Authority check: Host must match CONNECT target (host:port).
		// Prevents domain fronting where the agent CONNECTs to allowed.com
		// but sends Host: evil.com inside the encrypted tunnel. Also prevents
		// port mismatch (e.g. Host: example.com:8443 inside tunnel to :443).
		reqHost, reqPort, splitErr := net.SplitHostPort(r.Host)
		if splitErr != nil {
			// No port in Host header: treat as default HTTPS port.
			reqHost = r.Host
			reqPort = "443"
		}
		if !strings.EqualFold(reqHost, targetHost) || reqPort != targetPort {
			mismatch := r.Host + " vs " + target
			logger.LogBlocked(r.Method, r.URL.Path, "tls_authority_mismatch", "authority mismatch: "+mismatch, clientIP, requestID, agent)
			m.RecordTLSRequestBlocked("authority_mismatch")
			http.Error(w, "authority mismatch: blocked", http.StatusForbidden)
			return
		}

		// URL reconstruction: origin-form to absolute.
		r.URL.Scheme = schemeHTTPS
		r.URL.Host = target
		r.RequestURI = "" // required for http.Transport

		// Track whether any finding occurred (URL, body DLP, or response scan).
		// RecordClean is only applied when the request was fully clean so that
		// warn/strip findings do not contribute to score decay.
		hasFinding := false

		// Scan the full URL through the DLP pipeline. The CONNECT handler only
		// scans the synthetic host URL; inside the intercepted tunnel we have
		// the real path and query, which may contain exfiltrated secrets.
		targetURL := r.URL.String()
		urlResult := sc.Scan(r.Context(), targetURL)

		// Capture observer: record intercept URL verdict for policy replay.
		if p != nil {
			findings := urlResultToFindings(urlResult)
			action := ""
			if !urlResult.Allowed {
				action = config.ActionBlock
			}
			p.captureObs.ObserveURLVerdict(r.Context(), &capture.URLVerdictRecord{
				Subsurface:        "intercept_url",
				Transport:         "connect",
				RequestID:         requestID,
				Agent:             agent,
				Request:           capture.CaptureRequest{Method: r.Method, URL: targetURL},
				RawFindings:       findings,
				EffectiveFindings: findings,
				EffectiveAction:   action,
				Outcome:           captureOutcome(action, urlResult.Allowed),
			})
		}

		if !urlResult.Allowed && !urlResult.IsProtective() {
			hasFinding = true
			status := http.StatusForbidden
			if urlResult.Scanner == scanner.ScannerRateLimit {
				status = http.StatusTooManyRequests
			}
			if cfg.EnforceEnabled() {
				// Record SignalBlock for adaptive enforcement scoring.
				interceptRecordSignal(rec, session.SignalBlock, cfg, logger, m, p, clientIP, agent, requestID)
				logger.LogBlocked(r.Method, targetURL, urlResult.Scanner, urlResult.Reason, clientIP, requestID, agent)
				m.RecordTLSRequestBlocked("url_scan")
				if cfg.ExplainBlocksEnabled() && urlResult.Hint != "" {
					w.Header().Set("X-Pipelock-Hint", urlResult.Hint)
				}
				http.Error(w, "blocked: "+urlResult.Reason, status)
				return
			}
			// Audit mode: base action is "warn". Adaptive escalation may upgrade to block.
			baseAction := config.ActionWarn
			effectiveAction := decide.UpgradeAction(baseAction, recEscalationLevel(rec), &cfg.AdaptiveEnforcement)
			if effectiveAction == config.ActionBlock {
				sessionKey := clientIP
				if agent != "" && agent != agentAnonymous {
					sessionKey = agent + "|" + clientIP
				}
				logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(recEscalationLevel(rec)), baseAction, effectiveAction, urlResult.Scanner, clientIP, requestID)
				if p != nil {
					p.metrics.RecordAdaptiveUpgrade(baseAction, effectiveAction, session.EscalationLabel(recEscalationLevel(rec)))
				}
				interceptRecordSignal(rec, session.SignalBlock, cfg, logger, m, p, clientIP, agent, requestID)
				logger.LogBlocked(r.Method, targetURL, urlResult.Scanner, urlResult.Reason+" (escalated)", clientIP, requestID, agent)
				m.RecordTLSRequestBlocked("url_scan")
				http.Error(w, "blocked: "+urlResult.Reason+" (escalated)", status)
				return
			}
			// Audit mode near-miss: URL was flagged but allowed.
			interceptRecordSignal(rec, session.SignalNearMiss, cfg, logger, m, p, clientIP, agent, requestID)
			logger.LogAnomaly(r.Method, targetURL, urlResult.Scanner, urlResult.Reason, clientIP, requestID, agent, urlResult.Score)
		}

		// A2A protocol detection: check path and Content-Type for A2A traffic.
		// When detected, field-aware scanning replaces generic body DLP with
		// protocol-specific classification (URL/text/secret/opaque per leaf).
		isA2A := cfg.A2AScanning.Enabled && mcp.IsA2ARequest(r.URL.Path, r.Header.Get("Content-Type"))

		// A2A header scanning: scan A2A-Extensions URIs through SSRF pipeline.
		// Runs before body scan so header exfiltration is caught early.
		if isA2A {
			a2aHdrResult := mcp.ScanA2AHeaders(r.Context(), r.Header, sc, &cfg.A2AScanning)
			if !a2aHdrResult.Clean {
				hasFinding = true
				action := a2aHdrResult.Action
				if action == "" {
					action = cfg.A2AScanning.Action
				}
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if action == config.ActionAsk || (action == config.ActionBlock && cfg.EnforceEnabled()) {
					interceptRecordSignal(rec, session.SignalBlock, cfg, logger, m, p, clientIP, agent, requestID)
					logger.LogBlocked(r.Method, r.URL.String(), scannerLabelA2A, a2aHdrResult.Reason, clientIP, requestID, agent)
					m.RecordTLSRequestBlocked(scannerLabelA2A)
					http.Error(w, "blocked: "+a2aHdrResult.Reason, http.StatusForbidden)
					return
				}
				// Audit/warn mode: log finding but continue.
				logger.LogAnomaly(r.Method, r.URL.String(), scannerLabelA2A, a2aHdrResult.Reason, clientIP, requestID, agent, 0.8)
			}
		}

		// Strip Accept-Encoding to force identity encoding upstream.
		// This ensures responses arrive uncompressed so we can scan them.
		r.Header.Del("Accept-Encoding")

		// Request body DLP scanning.
		if cfg.RequestBodyScanning.Enabled && r.Body != nil && r.Body != http.NoBody {
			bodyBytes, result := scanRequestBody(
				r.Context(),
				r.Body,
				r.Header.Get("Content-Type"),
				r.Header.Get("Content-Encoding"),
				cfg.RequestBodyScanning.MaxBodyBytes,
				sc,
				agent,
			)

			// Capture observer: record intercept body DLP verdict for policy replay.
			if p != nil {
				bodyAction := ""
				if !result.Clean {
					bodyAction = result.Action
					if bodyAction == "" {
						bodyAction = cfg.RequestBodyScanning.Action
					}
				}
				p.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
					Subsurface:      "dlp_body_intercept",
					Transport:       "connect",
					RequestID:       requestID,
					Agent:           agent,
					Request:         capture.CaptureRequest{Method: r.Method, URL: targetURL},
					TransformKind:   capture.TransformJoinedFields,
					RawFindings:     bodyScanToFindings(result),
					EffectiveAction: bodyAction,
					Outcome:         captureOutcome(bodyAction, result.Clean),
				})
			}

			if !result.Clean {
				hasFinding = true
				action := result.Action
				if action == "" {
					action = cfg.RequestBodyScanning.Action
				}

				// Determine scanner label: address_protection vs body_dlp.
				scannerLabel := scannerLabelBodyDLP
				if len(result.AddressFindings) > 0 && len(result.DLPMatches) == 0 {
					scannerLabel = scannerLabelAddressProtection
				}

				reason := result.Reason
				if reason == "" {
					patternNames := dlpMatchNames(result.DLPMatches)
					reason = fmt.Sprintf("request body contains secret: %s", strings.Join(patternNames, ", "))
				}

				// DLP-only exemption: DLP pattern findings on adaptive-exempt
				// destinations should not feed escalation scoring or get action
				// upgrades. Separate from api_allowlist (reachability) to avoid
				// weakening scoring on general allowlisted hosts like github.com.
				// Address protection findings and fail-closed body errors are NOT
				// exempted — only DLP pattern matches.
				dlpExempt := scannerLabel == scannerLabelBodyDLP &&
					len(result.DLPMatches) > 0 &&
					isAdaptiveExempt(r.URL.Hostname(), cfg.AdaptiveEnforcement.ExemptDomains)

				// Adaptive enforcement: upgrade the body action.
				// Skip upgrade for DLP-exempt destinations — prevents
				// legitimate LLM traffic from cascading into session blocks.
				originalBodyAction := action
				if !dlpExempt {
					action = decide.UpgradeAction(action, recEscalationLevel(rec), &cfg.AdaptiveEnforcement)
				}
				if action != originalBodyAction {
					sessionKey := clientIP
					if agent != "" && agent != agentAnonymous {
						sessionKey = agent + "|" + clientIP
					}
					logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(recEscalationLevel(rec)), originalBodyAction, action, scannerLabel, clientIP, requestID)
					if p != nil {
						p.metrics.RecordAdaptiveUpgrade(originalBodyAction, action, session.EscalationLabel(recEscalationLevel(rec)))
					}
				}

				// Fail-closed: nil bodyBytes means body was consumed but couldn't
				// be buffered (oversize, compressed, read error). Always block
				// regardless of enforce mode to prevent forwarding an empty body.
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if bodyBytes == nil || action == config.ActionAsk || (action == config.ActionBlock && cfg.EnforceEnabled()) {
					if !dlpExempt {
						interceptRecordSignal(rec, session.SignalBlock, cfg, logger, m, p, clientIP, agent, requestID)
					}
					logger.LogBlocked(r.Method, r.URL.String(), scannerLabel, reason, clientIP, requestID, agent)
					m.RecordTLSRequestBlocked(scannerLabel)
					http.Error(w, "blocked: "+reason, http.StatusForbidden)
					return
				}
				// Escalation can upgrade to block even in audit mode, but only
				// when the upgrade actually changed the action (i.e. it wasn't
				// already block from the scanner config). Without this guard,
				// a base action that was already "block" would fire here even
				// without any escalation, which is not the intent.
				if action == config.ActionBlock && action != originalBodyAction && !cfg.EnforceEnabled() {
					if !dlpExempt {
						interceptRecordSignal(rec, session.SignalBlock, cfg, logger, m, p, clientIP, agent, requestID)
					}
					logger.LogBlocked(r.Method, r.URL.String(), scannerLabel, reason+" (escalated)", clientIP, requestID, agent)
					m.RecordTLSRequestBlocked(scannerLabel)
					http.Error(w, "blocked: "+reason+" (escalated)", http.StatusForbidden)
					return
				}
				// Audit/warn mode: log finding but forward the request.
				logger.LogAnomaly(r.Method, r.URL.String(), scannerLabel, reason, clientIP, requestID, agent, 0.8)
			}

			// A2A request body scanning: field-aware classification of JSON
			// leaves. Runs after generic DLP so both scanners see the body.
			if isA2A && bodyBytes != nil {
				a2aBodyResult := mcp.ScanA2ARequestBody(r.Context(), bodyBytes, sc, &cfg.A2AScanning)
				if !a2aBodyResult.Clean {
					hasFinding = true
					action := a2aBodyResult.Action
					if action == "" {
						action = cfg.A2AScanning.Action
					}
					reason := a2aBodyResult.Reason
					if reason == "" {
						reason = "a2a: request body finding"
					}
					// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
					if action == config.ActionAsk || (action == config.ActionBlock && cfg.EnforceEnabled()) {
						interceptRecordSignal(rec, session.SignalBlock, cfg, logger, m, p, clientIP, agent, requestID)
						logger.LogBlocked(r.Method, r.URL.String(), scannerLabelA2A, reason, clientIP, requestID, agent)
						m.RecordTLSRequestBlocked(scannerLabelA2A)
						http.Error(w, "blocked: "+reason, http.StatusForbidden)
						return
					}
					// Audit/warn mode: log finding but forward the request.
					logger.LogAnomaly(r.Method, r.URL.String(), scannerLabelA2A, reason, clientIP, requestID, agent, 0.8)
				}
			}

			// Re-wrap body so the forwarded request gets the buffered bytes.
			// Always re-wrap after scanning since the original body was consumed.
			if bodyBytes != nil {
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				r.ContentLength = int64(len(bodyBytes))
			}
		}

		// Request header DLP scanning.
		if cfg.RequestBodyScanning.Enabled && cfg.RequestBodyScanning.ScanHeaders {
			headerResult := scanRequestHeaders(r.Context(), r.Header, cfg, sc)

			// Capture observer: record intercept header DLP verdict for policy replay.
			if p != nil {
				hdrHasFinding := headerResult != nil && !headerResult.Clean
				hdrAction := ""
				if hdrHasFinding {
					hdrAction = cfg.RequestBodyScanning.Action
				}
				p.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
					Subsurface:      "dlp_header_intercept",
					Transport:       "connect",
					RequestID:       requestID,
					Agent:           agent,
					Request:         capture.CaptureRequest{Method: r.Method, URL: targetURL},
					TransformKind:   capture.TransformHeaderValue,
					EffectiveAction: hdrAction,
					Outcome:         captureOutcome(hdrAction, !hdrHasFinding),
				})
			}

			if headerResult != nil && !headerResult.Clean {
				hasFinding = true
				action := cfg.RequestBodyScanning.Action
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if action == config.ActionAsk || (action == config.ActionBlock && cfg.EnforceEnabled()) {
					logger.LogBlocked(r.Method, r.URL.String(), "header_dlp", "request header contains secret", clientIP, requestID, agent)
					m.RecordTLSRequestBlocked("header_dlp")
					http.Error(w, "blocked: request header contains secret", http.StatusForbidden)
					return
				}
				// Audit mode: log but forward.
				logger.LogAnomaly(r.Method, r.URL.String(), "header_dlp", "request header contains secret", clientIP, requestID, agent, 0.8) // 0.8: high confidence DLP match
			}
		}

		// CEE pre-forward admission for intercepted requests. The intercepted
		// request has full body, headers, and URL available for entropy and
		// fragment analysis. When p is non-nil, resolve CEE objects per-request
		// so hot-reloads during long-lived CONNECT tunnels use fresh state.
		ceeCfg := ceeEffectiveConfig(cfg.CrossRequestDetection, cfg.EnforceEnabled())
		if ceeCfg.Enabled {
			ceeET, ceeFB, ceeSM := et, fb, sm
			if p != nil {
				ceeET = p.entropyTrackerPtr.Load()
				ceeFB = p.fragmentBufferPtr.Load()
				ceeSM = p.sessionMgrPtr.Load()
			}

			sessionKey := CeeSessionKey(agent, clientIP)
			outbound := extractOutboundPayload(r)
			keys := queryParamKeys(r.URL)

			ceeRes := ceeAdmit(r.Context(), sessionKey, outbound, keys, r.URL.String(), agent, clientIP, requestID,
				ceeCfg, ceeET, ceeFB, sc, logger, m)

			// Capture observer: record intercept CEE verdict for policy replay.
			if p != nil {
				ceeFindings := ceeResultToFindings(ceeRes)
				ceeAction := ""
				if ceeRes.Blocked {
					ceeAction = config.ActionBlock
				} else if ceeRes.EntropyHit || ceeRes.FragmentHit {
					ceeAction = config.ActionWarn
				}
				p.captureObs.ObserveCEEVerdict(r.Context(), &capture.CEERecord{
					Subsurface:        "cee_intercept",
					Transport:         "connect",
					RequestID:         requestID,
					Agent:             agent,
					Request:           capture.CaptureRequest{Method: r.Method, URL: r.URL.String()},
					TransformKind:     capture.TransformCEEWindow,
					RawFindings:       ceeFindings,
					EffectiveFindings: ceeFindings,
					EffectiveAction:   ceeAction,
					Outcome:           captureOutcome(ceeAction, !ceeRes.Blocked && !ceeRes.EntropyHit && !ceeRes.FragmentHit),
				})
			}

			if ceeSM != nil && cfg.AdaptiveEnforcement.Enabled {
				ceeRecordSignals(ceeRes, ceeSM, sessionKey, cfg.AdaptiveEnforcement.EscalationThreshold, logger, m, clientIP, requestID)
			}

			if ceeRes.Blocked {
				m.RecordTLSRequestBlocked("cross_request")
				http.Error(w, "blocked: "+ceeRes.Reason, http.StatusForbidden)
				return
			}
		}

		// On-entry de-escalation for intercepted CONNECT requests.
		var interceptMetrics *metrics.Metrics
		if p != nil {
			interceptMetrics = p.metrics
		}
		if changed, fromLabel, toLabel := trySessionRecovery(rec, &cfg.AdaptiveEnforcement, interceptMetrics); changed {
			sessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				sessionKey = agent + "|" + clientIP
			}
			if logger != nil {
				logger.LogAdaptiveEscalation(sessionKey, fromLabel, toLabel, clientIP, requestID, rec.ThreatScore())
			}
		}

		// block_all enforcement: deny ALL traffic (including clean) when the
		// session is at an escalation level with block_all=true.
		if rec != nil && decide.UpgradeAction("", recEscalationLevel(rec), &cfg.AdaptiveEnforcement) == config.ActionBlock {
			sessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				sessionKey = agent + "|" + clientIP
			}
			logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(recEscalationLevel(rec)), "", config.ActionBlock, "session_deny", clientIP, requestID)
			if p != nil {
				p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(recEscalationLevel(rec)))
			}
			m.RecordTLSRequestBlocked("session_deny")
			http.Error(w, "blocked: session escalation level "+session.EscalationLabel(recEscalationLevel(rec)), http.StatusForbidden)
			return
		}

		// Remove hop-by-hop headers before forwarding.
		removeHopByHopHeaders(r.Header)

		// Forward to upstream.
		resp, err := upstream.RoundTrip(r)
		if err != nil {
			logger.LogError(r.Method, r.URL.String(), clientIP, requestID, agent, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck // response body

		// Fail-closed on compressed responses: DLP regex can't match
		// compressed content. Block rather than forward unscanned data.
		if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
			logger.LogBlocked(r.Method, r.URL.String(), "tls_response_blocked", "compressed response cannot be scanned", clientIP, requestID, agent)
			m.RecordTLSResponseBlocked("compressed")
			http.Error(w, "blocked: compressed response cannot be scanned", http.StatusForbidden)
			return
		}

		// A2A SSE streaming: scan events inline with per-event field-aware
		// scanning and rolling-tail cross-event injection detection. Clean
		// events are flushed immediately; detection terminates the stream.
		// Defense-in-depth: explicitly reject compressed SSE streams even
		// though the general compression guard above catches them. This
		// ensures A2A SSE scanning never processes compressed data if the
		// code is restructured.
		if isA2A && strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
				logger.LogBlocked(r.Method, r.URL.String(), scannerLabelA2A, "compressed A2A stream cannot be scanned", clientIP, requestID, agent)
				m.RecordTLSResponseBlocked(scannerLabelA2A)
				http.Error(w, "blocked: compressed A2A stream cannot be scanned", http.StatusForbidden)
				return
			}
			// Copy response headers to client before streaming.
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			removeHopByHopHeaders(w.Header())
			w.WriteHeader(resp.StatusCode)

			flusher, _ := w.(http.Flusher)
			streamErr := mcp.ScanA2AStream(r.Context(), resp.Body, w, flusher, sc, &cfg.A2AScanning)
			if streamErr != nil {
				// Distinguish scanning findings from internal/IO errors. In
				// warn mode, findings are logged as anomalies but don't
				// terminate the stream (events have already been forwarded).
				if errors.Is(streamErr, mcp.ErrA2AStreamFinding) && cfg.A2AScanning.Action == config.ActionWarn {
					logger.LogAnomaly(r.Method, r.URL.String(), scannerLabelA2A, streamErr.Error(), clientIP, requestID, agent, 0)
				} else {
					logger.LogBlocked(r.Method, r.URL.String(), scannerLabelA2A, streamErr.Error(), clientIP, requestID, agent)
					m.RecordTLSResponseBlocked(scannerLabelA2A)
				}
			}
			return
		}

		// Buffer response for scanning (scan-then-send, fail-closed).
		maxResp := cfg.TLSInterception.MaxResponseBytes
		if maxResp <= 0 {
			maxResp = interceptDefaultMaxResp
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResp+1))
		if readErr != nil {
			logger.LogError(r.Method, r.URL.String(), clientIP, requestID, agent, readErr)
			m.RecordTLSResponseBlocked("read_error")
			http.Error(w, "blocked: response read error", http.StatusForbidden)
			return
		}
		if int64(len(respBody)) > maxResp {
			logger.LogBlocked(r.Method, r.URL.String(), "tls_response_blocked", "response too large for scanning", clientIP, requestID, agent)
			m.RecordTLSResponseBlocked("oversized")
			http.Error(w, "blocked: response too large for scanning", http.StatusForbidden)
			return
		}

		// A2A response body scanning: field-aware classification replaces
		// generic response scanning for A2A traffic. Agent Card paths route
		// through drift detection; all other A2A responses use the walker.
		if isA2A {
			var a2aRespResult mcp.A2AScanResult
			if mcp.IsAgentCardPath(r.URL.Path) {
				cardKey := mcp.CardCacheKeyFromRequest(r.URL.String(), r.Header.Get("Authorization"))
				var baseline *mcp.CardBaseline
				if p != nil {
					baseline = p.a2aCardBaseline
				}
				cardResult := mcp.ScanAgentCard(r.Context(), respBody, sc, baseline, cardKey, &cfg.A2AScanning)
				a2aRespResult = cardResult.Findings
				a2aRespResult.Clean = cardResult.Clean
				// Promote card-level findings to the result.
				if !cardResult.Clean {
					if a2aRespResult.Action == "" {
						a2aRespResult.Action = cardResult.Action
					}
					if a2aRespResult.Reason == "" {
						a2aRespResult.Reason = cardResult.Reason
					}
				}
			} else {
				a2aRespResult = mcp.ScanA2AResponseBody(r.Context(), respBody, sc, &cfg.A2AScanning)
			}
			if !a2aRespResult.Clean {
				hasFinding = true
				action := a2aRespResult.Action
				if action == "" {
					action = cfg.A2AScanning.Action
				}
				reason := a2aRespResult.Reason
				if reason == "" {
					reason = "a2a: response body finding"
				}
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if action == config.ActionAsk || (action == config.ActionBlock && cfg.EnforceEnabled()) {
					interceptRecordSignal(rec, session.SignalBlock, cfg, logger, m, p, clientIP, agent, requestID)
					logger.LogBlocked(r.Method, r.URL.String(), scannerLabelA2A, reason, clientIP, requestID, agent)
					m.RecordTLSResponseBlocked(scannerLabelA2A)
					http.Error(w, "blocked: "+reason, http.StatusForbidden)
					return
				}
				// Audit/warn mode: log finding but forward response.
				logger.LogAnomaly(r.Method, r.URL.String(), scannerLabelA2A, reason, clientIP, requestID, agent, 0.8)
			}
		}

		// Response injection scanning.
		// Skip for response-exempt domains (e.g. trusted LLM providers).
		interceptRespExempt := isResponseScanExempt(r.URL.Hostname(), cfg.ResponseScanning.ExemptDomains)
		if sc.ResponseScanningEnabled() && interceptRespExempt {
			logger.LogResponseScanExempt(r.Method, r.URL.String(), r.URL.Hostname(), clientIP, requestID, agent)
		}
		if sc.ResponseScanningEnabled() && !interceptRespExempt {
			scanResult := sc.ScanResponse(r.Context(), string(respBody))

			// Capture observer: record intercept response scan verdict for policy replay.
			if p != nil {
				iRespAction := sc.ResponseAction()
				if scanResult.Clean {
					iRespAction = ""
				}
				p.captureObs.ObserveResponseVerdict(r.Context(), &capture.ResponseVerdictRecord{
					Subsurface:        "response_intercept",
					Transport:         "connect",
					RequestID:         requestID,
					Agent:             agent,
					Request:           capture.CaptureRequest{Method: r.Method, URL: targetURL},
					TransformKind:     capture.TransformRaw,
					RawFindings:       responseMatchesToFindings(scanResult.Matches, iRespAction),
					EffectiveFindings: responseMatchesToFindings(scanResult.Matches, iRespAction),
					EffectiveAction:   iRespAction,
					Outcome:           captureOutcome(iRespAction, scanResult.Clean),
				})
			}

			// Filter out suppressed findings (parity with fetch proxy).
			if !scanResult.Clean && len(cfg.Suppress) > 0 {
				var kept []scanner.ResponseMatch
				for _, m := range scanResult.Matches {
					if !config.IsSuppressed(m.PatternName, r.URL.String(), cfg.Suppress) {
						kept = append(kept, m)
					}
				}
				scanResult.Matches = kept
				scanResult.Clean = len(kept) == 0
			}
			if !scanResult.Clean {
				hasFinding = true
				action := sc.ResponseAction()
				// Adaptive enforcement: upgrade the response action before the switch.
				originalAction := action
				action = decide.UpgradeAction(action, recEscalationLevel(rec), &cfg.AdaptiveEnforcement)
				if action != originalAction {
					sessionKey := clientIP
					if agent != "" && agent != agentAnonymous {
						sessionKey = agent + "|" + clientIP
					}
					logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(recEscalationLevel(rec)), originalAction, action, "response_scan", clientIP, requestID)
					if p != nil {
						p.metrics.RecordAdaptiveUpgrade(originalAction, action, session.EscalationLabel(recEscalationLevel(rec)))
					}
				}
				patternNames := make([]string, len(scanResult.Matches))
				for i, match := range scanResult.Matches {
					patternNames[i] = match.PatternName
				}
				bundleRules := responseBundleRules(scanResult.Matches)
				reason := fmt.Sprintf("response injection: %s", strings.Join(patternNames, ", "))

				switch action {
				case config.ActionBlock, config.ActionAsk:
					// ActionAsk: no HITL terminal available inside intercepted tunnels,
					// so fail-closed to block (consistent with HITL non-terminal default).
					interceptRecordSignal(rec, session.SignalBlock, cfg, logger, m, p, clientIP, agent, requestID)
					logger.LogBlocked(r.Method, r.URL.String(), "response_scan", reason, clientIP, requestID, agent)
					m.RecordTLSResponseBlocked("injection")
					http.Error(w, "blocked: response contains injection", http.StatusForbidden)
					return
				case config.ActionStrip:
					// Record SignalStrip for adaptive enforcement scoring.
					if sm != nil && cfg.AdaptiveEnforcement.Enabled {
						ceeSM := sm
						if p != nil {
							ceeSM = p.sessionMgrPtr.Load()
						}
						if ceeSM != nil {
							sessionKey := clientIP
							if agent != "" && agent != agentAnonymous {
								sessionKey = agent + "|" + clientIP
							}
							sess := ceeSM.GetOrCreate(sessionKey)
							var stripMetrics *metrics.Metrics
							if p != nil {
								stripMetrics = p.metrics
							}
							decide.RecordEscalation(sess, session.SignalStrip, decide.EscalationParams{
								Threshold: cfg.AdaptiveEnforcement.EscalationThreshold,
								Logger:    logger,
								Metrics:   stripMetrics,
								Session:   sessionKey,
								ClientIP:  clientIP,
								RequestID: requestID,
							})
						}
					}
					respBody = []byte(scanResult.TransformedContent)
					// Update Content-Length to match stripped body; prevents HTTP/1.1
					// framing errors from a stale upstream Content-Length header.
					resp.Header.Set("Content-Length", strconv.Itoa(len(respBody)))
					logger.LogResponseScan(r.URL.String(), clientIP, requestID, agent, config.ActionStrip, len(scanResult.Matches), patternNames, bundleRules)
				default:
					// warn/forward: log and forward unmodified.
					logger.LogResponseScan(r.URL.String(), clientIP, requestID, agent, action, len(scanResult.Matches), patternNames, bundleRules)
				}
			}
		}

		// Record clean request for adaptive score decay. Only apply decay when no
		// finding was detected; warn/strip paths indicate suspicious traffic and
		// must not contribute to score decay.
		if rec != nil && cfg.AdaptiveEnforcement.Enabled && !hasFinding {
			rec.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
		}

		// Record response size for per-domain data budget tracking.
		sc.RecordRequest(strings.ToLower(targetHost), len(respBody))

		// Count intercepted request in stats so /stats reflects CONNECT traffic.
		// Use agentAnonymous (bounded cardinality) since intercept handler
		// doesn't resolve agent profiles — avoids Prometheus label explosion.
		m.RecordAllowed(time.Since(reqStart), agentAnonymous)

		// Forward response to client.
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		removeHopByHopHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
	})
}

// isPassthrough checks if a hostname matches the passthrough domain list.
// Supports exact match and wildcard prefix (*.example.com matches any subdomain depth).
func isPassthrough(host string, domains []string) bool {
	host = strings.ToLower(host)
	for _, pattern := range domains {
		pattern = strings.ToLower(pattern)
		if pattern == host {
			return true
		}
		// Wildcard: *.example.com matches sub.example.com and deep.sub.example.com.
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // .example.com
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

// singleConnListener yields one connection then blocks until closed.
// Used to serve a single hijacked TLS connection via http.Server.
// The channel is NOT closed in the constructor because http.Server.Serve
// must not exit until the handler goroutine completes. Instead, call
// Close() (typically via srv.Close/Shutdown) to unblock the accept loop.
type singleConnListener struct {
	ch        chan net.Conn
	addr      net.Addr
	closeOnce sync.Once
}

func newSingleConnListener(conn net.Conn) net.Listener {
	ln := &singleConnListener{
		ch:   make(chan net.Conn, 1),
		addr: conn.LocalAddr(),
	}
	ln.ch <- conn
	return ln
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *singleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.ch) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}
