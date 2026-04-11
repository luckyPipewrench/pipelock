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
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
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

// InterceptContext carries shared state for TLS-intercepted tunnel processing.
// Groups parameters that flow through interceptTunnel → newInterceptHandler → interceptRecordSignal.
type InterceptContext struct {
	TargetHost string
	TargetPort string

	Config    *config.Config
	Scanner   *scanner.Scanner
	CertCache *certgen.CertCache
	Logger    *audit.Logger
	Metrics   *metrics.Metrics

	ClientIP  string
	RequestID string
	Agent     string
	ActorAuth envelope.ActorAuth

	UpstreamRT http.RoundTripper
	SafeDial   dialFunc

	EntropyTracker *scanner.EntropyTracker
	FragmentBuffer *scanner.FragmentBuffer
	SessionMgr     *SessionManager
	Proxy          *Proxy
	Recorder       session.Recorder
	KillSwitch     *killswitch.Controller
}

// Validate checks that required fields are set. Returns an error if any
// enforcement-critical field is nil/empty, preventing panic-on-dereference
// in the intercept pipeline. Called at entry to interceptTunnel.
func (ic *InterceptContext) Validate() error {
	if ic == nil {
		return errors.New("InterceptContext: nil receiver")
	}
	switch {
	case ic.TargetHost == "":
		return errors.New("InterceptContext: TargetHost is required")
	case ic.TargetPort == "":
		return errors.New("InterceptContext: TargetPort is required")
	case ic.Config == nil:
		return errors.New("InterceptContext: Config is required")
	case ic.Scanner == nil:
		return errors.New("InterceptContext: Scanner is required")
	case ic.CertCache == nil:
		return errors.New("InterceptContext: CertCache is required")
	case ic.Logger == nil:
		return errors.New("InterceptContext: Logger is required")
	case ic.Metrics == nil:
		return errors.New("InterceptContext: Metrics is required")
	}
	return nil
}

// interceptRecordSignal records an adaptive threat signal on the session recorder
// for the intercepted request. Handles nil rec (via decide.RecordSignal),
// disabled adaptive config, and escalation transitions (log, audit, metrics
// gauge updates). Used by newInterceptHandler to feed signals back to the
// adaptive system.
func interceptRecordSignal(ic *InterceptContext, sig session.SignalType) {
	if !ic.Config.AdaptiveEnforcement.Enabled {
		return
	}
	sessionKey := ic.ClientIP
	if ic.Agent != "" && ic.Agent != agentAnonymous {
		sessionKey = ic.Agent + "|" + ic.ClientIP
	}
	var m *metrics.Metrics
	if ic.Proxy != nil {
		m = ic.Proxy.metrics
	}
	decide.RecordSignal(ic.Recorder, sig, decide.EscalationParams{
		Threshold: ic.Config.AdaptiveEnforcement.EscalationThreshold,
		Logger:    ic.Logger,
		Metrics:   m,
		Session:   sessionKey,
		ClientIP:  ic.ClientIP,
		RequestID: ic.RequestID,
	})
}

// interceptEmitReceipt emits a signed action receipt for a TLS-intercepted request.
// Loads the emitter from ic.Proxy at call time so long-lived tunnels always use
// the current emitter (including after key rotation on reload).
func interceptEmitReceipt(ic *InterceptContext, opts receipt.EmitOpts) {
	if ic.Proxy == nil {
		return
	}
	e := ic.Proxy.receiptEmitterPtr.Load()
	if e == nil {
		return
	}
	if err := e.Emit(opts); err != nil && ic.Logger != nil {
		ic.Logger.LogError(audit.NewRequestLogContext(opts.RequestID), err)
	}
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
	ic *InterceptContext,
) error {
	if err := ic.Validate(); err != nil {
		return fmt.Errorf("intercept setup: %w", err)
	}

	// Client-side TLS config with forged cert from cache.
	tlsCfg := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := ic.CertCache.Get(ic.TargetHost)
			if err == nil {
				ic.Metrics.SetTLSCertCacheSize(float64(ic.CertCache.Size()))
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
		ic.Metrics.RecordTLSIntercept("deadline_error")
		return fmt.Errorf("set handshake deadline: %w", err)
	}

	ictx := newConnectAuditContext(ic.Logger, net.JoinHostPort(ic.TargetHost, ic.TargetPort), ic.ClientIP, ic.RequestID, ic.Agent)

	tlsConn := tls.Server(clientConn, tlsCfg)
	handshakeStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		ic.Metrics.RecordTLSIntercept("handshake_error")
		ic.Logger.LogBlocked(ictx, "tls_handshake_error", err.Error())
		return fmt.Errorf("client TLS handshake: %w", err)
	}
	ic.Metrics.RecordTLSHandshake("client", time.Since(handshakeStart))

	// Clear the handshake deadline so it doesn't affect request serving.
	_ = clientConn.SetDeadline(time.Time{})
	defer tlsConn.Close() //nolint:errcheck // best effort

	// Create upstream transport if not provided (tests inject mock).
	upstreamRT := ic.UpstreamRT
	if upstreamRT == nil {
		upstream := &http.Transport{
			DialTLSContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
				addr := net.JoinHostPort(ic.TargetHost, ic.TargetPort)
				// Use SSRF-safe dialer for the TCP connection to prevent
				// DNS rebinding TOCTOU between the scanner check and dial.
				var rawConn net.Conn
				var dialErr error
				if ic.SafeDial != nil {
					rawConn, dialErr = ic.SafeDial(dialCtx, network, addr)
				} else {
					// Fallback for tests that don't provide a dialer.
					rawConn, dialErr = (&net.Dialer{}).DialContext(dialCtx, network, addr)
				}
				if dialErr != nil {
					return nil, dialErr
				}
				// Layer TLS on top of the SSRF-validated TCP connection.
				tlsCfg := &tls.Config{
					ServerName: ic.TargetHost,
					NextProtos: []string{"h2", "http/1.1"},
					MinVersion: tls.VersionTLS12,
				}
				start := time.Now()
				tlsUpstream := tls.Client(rawConn, tlsCfg)
				if err := tlsUpstream.HandshakeContext(dialCtx); err != nil {
					_ = rawConn.Close()
					return nil, err
				}
				ic.Metrics.RecordTLSHandshake("upstream", time.Since(start))
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
	handler := newInterceptHandler(ic, upstreamRT)
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
	ic *InterceptContext,
	upstream http.RoundTripper,
) http.Handler {
	target := net.JoinHostPort(ic.TargetHost, ic.TargetPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqStart := time.Now()

		// Strip inbound mediation envelope headers to prevent forgery.
		envelope.StripInbound(r.Header)

		// Pre-generate a single ActionID for correlation between envelope and receipt.
		actionID := receipt.NewActionID()

		// Kill switch re-check for intercepted CONNECT tunnels.
		// Raw relay (relay.go) polls this per copy iteration. Intercepted
		// tunnels must check per inner request. Use IsActiveForIP (not
		// IsActiveHTTP) because inner request paths belong to the upstream
		// origin — /health and /metrics exemptions must not apply here.
		if ic.KillSwitch != nil {
			d := ic.KillSwitch.IsActiveForIP(ic.ClientIP)
			if d.Active {
				ic.Metrics.RecordKillSwitchDenial("intercept", r.URL.Path)
				http.Error(w, "kill switch active", http.StatusServiceUnavailable)
				return
			}
		}

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
		if !strings.EqualFold(reqHost, ic.TargetHost) || reqPort != ic.TargetPort {
			mismatch := r.Host + " vs " + target
			mismatchURL := schemeHTTPS + "://" + net.JoinHostPort(reqHost, reqPort) + r.URL.RequestURI()
			ic.Logger.LogBlocked(newHTTPAuditContext(ic.Logger, r.Method, mismatchURL, ic.ClientIP, ic.RequestID, ic.Agent), "tls_authority_mismatch", "authority mismatch: "+mismatch)
			ic.Metrics.RecordTLSRequestBlocked("authority_mismatch")
			interceptEmitReceipt(ic, receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     "tls_authority_mismatch",
				Pattern:   "authority mismatch: " + mismatch,
				Transport: "intercept",
				Method:    r.Method,
				Target:    r.Host + r.URL.Path,
				RequestID: ic.RequestID,
				Agent:     ic.Agent,
			})
			http.Error(w, "authority mismatch: blocked", http.StatusForbidden)
			return
		}

		// Airlock classification of the inner request method.
		if interceptSess, ok := ic.Recorder.(*SessionState); ok && interceptSess != nil {
			tier := interceptSess.Airlock().Tier()
			if tier != config.AirlockTierNone {
				allowed, reason := ClassifyAction(tier, r.Method, TransportConnect, true)
				if !allowed {
					interceptSess.Airlock().ExtendTimer()
					ic.Logger.LogAirlockDeny(interceptSess.key, tier, TransportConnect, r.Method, ic.ClientIP, ic.RequestID)
					ic.Metrics.RecordAirlockDenial(tier, TransportConnect, r.Method)
					ic.Metrics.RecordTLSRequestBlocked("airlock")
					http.Error(w, "airlock: "+reason, http.StatusForbidden)
					return
				}
			}
		}

		// URL reconstruction: origin-form to absolute.
		r.URL.Scheme = schemeHTTPS
		r.URL.Host = target
		r.RequestURI = "" // required for http.Transport

		// Build shared audit context AFTER URL reconstruction so actx.URL
		// contains the full intercepted URL, not just the origin-form path.
		actx := newHTTPAuditContext(ic.Logger, r.Method, r.URL.String(), ic.ClientIP, ic.RequestID, ic.Agent)

		// Track whether any finding occurred (URL, body DLP, or response scan).
		// RecordClean is only applied when the request was fully clean so that
		// warn/strip findings do not contribute to score decay.
		hasFinding := false

		// Scan the full URL through the DLP pipeline. The CONNECT handler only
		// scans the synthetic host URL; inside the intercepted tunnel we have
		// the real path and query, which may contain exfiltrated secrets.
		targetURL := r.URL.String()
		urlResult := ic.Scanner.Scan(r.Context(), targetURL)

		// Capture observer: record intercept URL verdict for policy replay.
		if ic.Proxy != nil {
			findings := urlResultToFindings(urlResult)
			action := ""
			if !urlResult.Allowed {
				action = config.ActionBlock
			}
			ic.Proxy.captureObs.ObserveURLVerdict(r.Context(), &capture.URLVerdictRecord{
				Subsurface:        "intercept_url",
				Transport:         "connect",
				RequestID:         ic.RequestID,
				Agent:             ic.Agent,
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
			if ic.Config.EnforceEnabled() {
				// Config-mismatch: bounded signal (NearMiss) instead of full
				// block signal. Prevents death spiral while keeping visibility.
				if urlResult.IsConfigMismatch() {
					interceptRecordSignal(ic, session.SignalNearMiss)
				} else {
					interceptRecordSignal(ic, session.SignalBlock)
				}
				ic.Logger.LogBlocked(actx, urlResult.Scanner, urlResult.Reason)
				ic.Metrics.RecordTLSRequestBlocked("url_scan")
				interceptEmitReceipt(ic, receipt.EmitOpts{
					ActionID:  actionID,
					Verdict:   config.ActionBlock,
					Layer:     urlResult.Scanner,
					Pattern:   urlResult.Reason,
					Transport: "intercept",
					Method:    r.Method,
					Target:    targetURL,
					RequestID: ic.RequestID,
					Agent:     ic.Agent,
				})
				if ic.Config.ExplainBlocksEnabled() && urlResult.Hint != "" {
					w.Header().Set("X-Pipelock-Hint", urlResult.Hint)
				}
				http.Error(w, "blocked: "+urlResult.Reason, status)
				return
			}
			// Audit mode: base action is "warn". Adaptive escalation may upgrade to block.
			baseAction := config.ActionWarn
			effectiveAction := decide.UpgradeAction(baseAction, recEscalationLevel(ic.Recorder), &ic.Config.AdaptiveEnforcement)
			if effectiveAction == config.ActionBlock {
				sessionKey := ic.ClientIP
				if ic.Agent != "" && ic.Agent != agentAnonymous {
					sessionKey = ic.Agent + "|" + ic.ClientIP
				}
				ic.Logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(recEscalationLevel(ic.Recorder)), baseAction, effectiveAction, urlResult.Scanner, ic.ClientIP, ic.RequestID)
				if ic.Proxy != nil {
					ic.Proxy.metrics.RecordAdaptiveUpgrade(baseAction, effectiveAction, session.EscalationLabel(recEscalationLevel(ic.Recorder)))
				}
				if urlResult.IsConfigMismatch() {
					interceptRecordSignal(ic, session.SignalNearMiss)
				} else {
					interceptRecordSignal(ic, session.SignalBlock)
				}
				ic.Logger.LogBlocked(actx, urlResult.Scanner, urlResult.Reason+" (escalated)")
				ic.Metrics.RecordTLSRequestBlocked("url_scan")
				interceptEmitReceipt(ic, receipt.EmitOpts{
					ActionID:  actionID,
					Verdict:   config.ActionBlock,
					Layer:     urlResult.Scanner,
					Pattern:   urlResult.Reason + " (escalated)",
					Transport: "intercept",
					Method:    r.Method,
					Target:    targetURL,
					RequestID: ic.RequestID,
					Agent:     ic.Agent,
				})
				http.Error(w, "blocked: "+urlResult.Reason+" (escalated)", status)
				return
			}
			// Audit mode near-miss: URL was flagged but allowed.
			interceptRecordSignal(ic, session.SignalNearMiss)
			ic.Logger.LogAnomaly(actx, urlResult.Scanner, urlResult.Reason, urlResult.Score)
		}

		// A2A protocol detection: check path and Content-Type for A2A traffic.
		// When detected, field-aware scanning replaces generic body DLP with
		// protocol-specific classification (URL/text/secret/opaque per leaf).
		isA2A := ic.Config.A2AScanning.Enabled && mcp.IsA2ARequest(r.URL.Path, r.Header.Get("Content-Type"))

		// A2A header scanning: scan A2A-Extensions URIs through SSRF pipeline.
		// Runs before body scan so header exfiltration is caught early.
		if isA2A {
			a2aHdrResult := mcp.ScanA2AHeaders(r.Context(), r.Header, ic.Scanner, &ic.Config.A2AScanning)
			if !a2aHdrResult.Clean {
				hasFinding = true
				action := a2aHdrResult.Action
				if action == "" {
					action = ic.Config.A2AScanning.Action
				}
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if action == config.ActionAsk || (action == config.ActionBlock && ic.Config.EnforceEnabled()) {
					if a2aHdrResult.IsConfigMismatch() {
						interceptRecordSignal(ic, session.SignalNearMiss)
					} else {
						interceptRecordSignal(ic, session.SignalBlock)
					}
					ic.Logger.LogBlocked(actx, scannerLabelA2A, a2aHdrResult.Reason)
					ic.Metrics.RecordTLSRequestBlocked(scannerLabelA2A)
					interceptEmitReceipt(ic, receipt.EmitOpts{
						ActionID:  actionID,
						Verdict:   config.ActionBlock,
						Layer:     scannerLabelA2A,
						Pattern:   a2aHdrResult.Reason,
						Transport: "intercept",
						Method:    r.Method,
						Target:    targetURL,
						RequestID: ic.RequestID,
						Agent:     ic.Agent,
					})
					http.Error(w, "blocked: "+a2aHdrResult.Reason, http.StatusForbidden)
					return
				}
				// Audit/warn mode: log finding but continue.
				ic.Logger.LogAnomaly(actx, scannerLabelA2A, a2aHdrResult.Reason, 0.8)
			}
		}

		// Strip Accept-Encoding to force identity encoding upstream.
		// This ensures responses arrive uncompressed so we can scan them.
		r.Header.Del("Accept-Encoding")

		// Request body DLP scanning.
		if ic.Config.RequestBodyScanning.Enabled && r.Body != nil && r.Body != http.NoBody {
			bodyBytes, result := scanRequestBody(r.Context(), BodyScanRequest{
				Body:            r.Body,
				ContentType:     r.Header.Get("Content-Type"),
				ContentEncoding: r.Header.Get("Content-Encoding"),
				MaxBytes:        ic.Config.RequestBodyScanning.MaxBodyBytes,
				Scanner:         ic.Scanner,
				AgentID:         ic.Agent,
			})

			// Capture observer: record intercept body DLP verdict for policy replay.
			if ic.Proxy != nil {
				bodyAction := ""
				if !result.Clean {
					bodyAction = result.Action
					if bodyAction == "" {
						bodyAction = ic.Config.RequestBodyScanning.Action
					}
				}
				ic.Proxy.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
					Subsurface:      "dlp_body_intercept",
					Transport:       "connect",
					RequestID:       ic.RequestID,
					Agent:           ic.Agent,
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
					action = ic.Config.RequestBodyScanning.Action
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
					isAdaptiveExempt(r.URL.Hostname(), ic.Config.AdaptiveEnforcement.ExemptDomains)

				// Adaptive enforcement: upgrade the body action.
				// Skip upgrade for DLP-exempt destinations — prevents
				// legitimate LLM traffic from cascading into session blocks.
				originalBodyAction := action
				if !dlpExempt {
					action = decide.UpgradeAction(action, recEscalationLevel(ic.Recorder), &ic.Config.AdaptiveEnforcement)
				}
				if action != originalBodyAction {
					sessionKey := ic.ClientIP
					if ic.Agent != "" && ic.Agent != agentAnonymous {
						sessionKey = ic.Agent + "|" + ic.ClientIP
					}
					ic.Logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(recEscalationLevel(ic.Recorder)), originalBodyAction, action, scannerLabel, ic.ClientIP, ic.RequestID)
					if ic.Proxy != nil {
						ic.Proxy.metrics.RecordAdaptiveUpgrade(originalBodyAction, action, session.EscalationLabel(recEscalationLevel(ic.Recorder)))
					}
				}

				// Fail-closed: nil bodyBytes means body was consumed but couldn't
				// be buffered (oversize, compressed, read error). Always block
				// regardless of enforce mode to prevent forwarding an empty body.
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if bodyBytes == nil || action == config.ActionAsk || (action == config.ActionBlock && ic.Config.EnforceEnabled()) {
					if !dlpExempt {
						interceptRecordSignal(ic, session.SignalBlock)
					}
					ic.Logger.LogBlocked(actx, scannerLabel, reason)
					ic.Metrics.RecordTLSRequestBlocked(scannerLabel)
					interceptEmitReceipt(ic, receipt.EmitOpts{
						ActionID:  actionID,
						Verdict:   config.ActionBlock,
						Layer:     scannerLabel,
						Pattern:   reason,
						Transport: "intercept",
						Method:    r.Method,
						Target:    targetURL,
						RequestID: ic.RequestID,
						Agent:     ic.Agent,
					})
					http.Error(w, "blocked: "+reason, http.StatusForbidden)
					return
				}
				// Escalation can upgrade to block even in audit mode, but only
				// when the upgrade actually changed the action (i.e. it wasn't
				// already block from the scanner config). Without this guard,
				// a base action that was already "block" would fire here even
				// without any escalation, which is not the intent.
				if action == config.ActionBlock && action != originalBodyAction && !ic.Config.EnforceEnabled() {
					if !dlpExempt {
						interceptRecordSignal(ic, session.SignalBlock)
					}
					ic.Logger.LogBlocked(actx, scannerLabel, reason+" (escalated)")
					ic.Metrics.RecordTLSRequestBlocked(scannerLabel)
					interceptEmitReceipt(ic, receipt.EmitOpts{
						ActionID:  actionID,
						Verdict:   config.ActionBlock,
						Layer:     scannerLabel,
						Pattern:   reason + " (escalated)",
						Transport: "intercept",
						Method:    r.Method,
						Target:    targetURL,
						RequestID: ic.RequestID,
						Agent:     ic.Agent,
					})
					http.Error(w, "blocked: "+reason+" (escalated)", http.StatusForbidden)
					return
				}
				// Audit/warn mode: log finding but forward the request.
				ic.Logger.LogAnomaly(actx, scannerLabel, reason, 0.8)
			}

			// A2A request body scanning: field-aware classification of JSON
			// leaves. Runs after generic DLP so both scanners see the body.
			if isA2A && bodyBytes != nil {
				a2aBodyResult := mcp.ScanA2ARequestBody(r.Context(), bodyBytes, ic.Scanner, &ic.Config.A2AScanning)
				if !a2aBodyResult.Clean {
					hasFinding = true
					action := a2aBodyResult.Action
					if action == "" {
						action = ic.Config.A2AScanning.Action
					}
					reason := a2aBodyResult.Reason
					if reason == "" {
						reason = "a2a: request body finding"
					}
					// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
					if action == config.ActionAsk || (action == config.ActionBlock && ic.Config.EnforceEnabled()) {
						if a2aBodyResult.IsConfigMismatch() {
							interceptRecordSignal(ic, session.SignalNearMiss)
						} else {
							interceptRecordSignal(ic, session.SignalBlock)
						}
						ic.Logger.LogBlocked(actx, scannerLabelA2A, reason)
						ic.Metrics.RecordTLSRequestBlocked(scannerLabelA2A)
						interceptEmitReceipt(ic, receipt.EmitOpts{
							ActionID:  actionID,
							Verdict:   config.ActionBlock,
							Layer:     scannerLabelA2A,
							Pattern:   reason,
							Transport: "intercept",
							Method:    r.Method,
							Target:    targetURL,
							RequestID: ic.RequestID,
							Agent:     ic.Agent,
						})
						http.Error(w, "blocked: "+reason, http.StatusForbidden)
						return
					}
					// Audit/warn mode: log finding but forward the request.
					ic.Logger.LogAnomaly(actx, scannerLabelA2A, reason, 0.8)
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
		if ic.Config.RequestBodyScanning.Enabled && ic.Config.RequestBodyScanning.ScanHeaders {
			headerResult := scanRequestHeaders(r.Context(), r.Header, ic.Config, ic.Scanner)

			// Capture observer: record intercept header DLP verdict for policy replay.
			if ic.Proxy != nil {
				hdrHasFinding := headerResult != nil && !headerResult.Clean
				hdrAction := ""
				if hdrHasFinding {
					hdrAction = ic.Config.RequestBodyScanning.Action
				}
				ic.Proxy.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
					Subsurface:      "dlp_header_intercept",
					Transport:       "connect",
					RequestID:       ic.RequestID,
					Agent:           ic.Agent,
					Request:         capture.CaptureRequest{Method: r.Method, URL: targetURL},
					TransformKind:   capture.TransformHeaderValue,
					EffectiveAction: hdrAction,
					Outcome:         captureOutcome(hdrAction, !hdrHasFinding),
				})
			}

			if headerResult != nil && !headerResult.Clean {
				hasFinding = true
				action := ic.Config.RequestBodyScanning.Action
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if action == config.ActionAsk || (action == config.ActionBlock && ic.Config.EnforceEnabled()) {
					ic.Logger.LogBlocked(actx, "header_dlp", "request header contains secret")
					ic.Metrics.RecordTLSRequestBlocked("header_dlp")
					interceptEmitReceipt(ic, receipt.EmitOpts{
						ActionID:  actionID,
						Verdict:   config.ActionBlock,
						Layer:     "header_dlp",
						Pattern:   "request header contains secret",
						Transport: "intercept",
						Method:    r.Method,
						Target:    targetURL,
						RequestID: ic.RequestID,
						Agent:     ic.Agent,
					})
					http.Error(w, "blocked: request header contains secret", http.StatusForbidden)
					return
				}
				// Audit mode: log but forward.
				ic.Logger.LogAnomaly(actx, "header_dlp", "request header contains secret", 0.8) // 0.8: high confidence DLP match
			}
		}

		// CEE pre-forward admission for intercepted requests. The intercepted
		// request has full body, headers, and URL available for entropy and
		// fragment analysis. When p is non-nil, resolve CEE objects per-request
		// so hot-reloads during long-lived CONNECT tunnels use fresh state.
		ceeCfg := ceeEffectiveConfig(ic.Config.CrossRequestDetection, ic.Config.EnforceEnabled())
		if ceeCfg.Enabled {
			ceeET, ceeFB, ceeSM := ic.EntropyTracker, ic.FragmentBuffer, ic.SessionMgr
			if ic.Proxy != nil {
				ceeET = ic.Proxy.entropyTrackerPtr.Load()
				ceeFB = ic.Proxy.fragmentBufferPtr.Load()
				ceeSM = ic.Proxy.sessionMgrPtr.Load()
			}

			sessionKey := CeeSessionKey(ic.Agent, ic.ClientIP)
			outbound := extractOutboundPayload(r)
			keys := queryParamKeys(r.URL)

			ceeRes := ceeAdmit(r.Context(), sessionKey, outbound, keys, r.URL.String(), ic.Agent, ic.ClientIP, ic.RequestID,
				ceeCfg, ceeET, ceeFB, ic.Scanner, ic.Logger, ic.Metrics)

			// Capture observer: record intercept CEE verdict for policy replay.
			if ic.Proxy != nil {
				ceeFindings := ceeResultToFindings(ceeRes)
				ceeAction := ""
				if ceeRes.Blocked {
					ceeAction = config.ActionBlock
				} else if ceeRes.EntropyHit || ceeRes.FragmentHit {
					ceeAction = config.ActionWarn
				}
				ic.Proxy.captureObs.ObserveCEEVerdict(r.Context(), &capture.CEERecord{
					Subsurface:        "cee_intercept",
					Transport:         "connect",
					RequestID:         ic.RequestID,
					Agent:             ic.Agent,
					Request:           capture.CaptureRequest{Method: r.Method, URL: r.URL.String()},
					TransformKind:     capture.TransformCEEWindow,
					RawFindings:       ceeFindings,
					EffectiveFindings: ceeFindings,
					EffectiveAction:   ceeAction,
					Outcome:           captureOutcome(ceeAction, !ceeRes.Blocked && !ceeRes.EntropyHit && !ceeRes.FragmentHit),
				})
			}

			if ceeSM != nil && ic.Config.AdaptiveEnforcement.Enabled {
				ceeRecordSignals(ceeRes, ceeSM, sessionKey, ic.Config.AdaptiveEnforcement.EscalationThreshold, ic.Logger, ic.Metrics, ic.ClientIP, ic.RequestID)
			}

			if ceeRes.Blocked {
				ic.Metrics.RecordTLSRequestBlocked("cross_request")
				interceptEmitReceipt(ic, receipt.EmitOpts{
					ActionID:  actionID,
					Verdict:   config.ActionBlock,
					Layer:     "cross_request",
					Pattern:   ceeRes.Reason,
					Transport: "intercept",
					Method:    r.Method,
					Target:    targetURL,
					RequestID: ic.RequestID,
					Agent:     ic.Agent,
				})
				http.Error(w, "blocked: "+ceeRes.Reason, http.StatusForbidden)
				return
			}
		}

		// On-entry de-escalation for intercepted CONNECT requests.
		var interceptMetrics *metrics.Metrics
		if ic.Proxy != nil {
			interceptMetrics = ic.Proxy.metrics
		}
		if changed, fromLabel, toLabel := trySessionRecovery(ic.Recorder, &ic.Config.AdaptiveEnforcement, interceptMetrics); changed {
			sessionKey := ic.ClientIP
			if ic.Agent != "" && ic.Agent != agentAnonymous {
				sessionKey = ic.Agent + "|" + ic.ClientIP
			}
			if ic.Logger != nil {
				ic.Logger.LogAdaptiveEscalation(sessionKey, fromLabel, toLabel, ic.ClientIP, ic.RequestID, ic.Recorder.ThreatScore())
			}
		}

		// block_all enforcement: deny ALL traffic (including clean) when the
		// session is at an escalation level with block_all=true.
		if ic.Recorder != nil && decide.UpgradeAction("", recEscalationLevel(ic.Recorder), &ic.Config.AdaptiveEnforcement) == config.ActionBlock {
			sessionKey := ic.ClientIP
			if ic.Agent != "" && ic.Agent != agentAnonymous {
				sessionKey = ic.Agent + "|" + ic.ClientIP
			}
			ic.Logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(recEscalationLevel(ic.Recorder)), "", config.ActionBlock, "session_deny", ic.ClientIP, ic.RequestID)
			if ic.Proxy != nil {
				ic.Proxy.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(recEscalationLevel(ic.Recorder)))
			}
			ic.Metrics.RecordTLSRequestBlocked("session_deny")
			interceptEmitReceipt(ic, receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     "session_deny",
				Pattern:   "session escalation level " + session.EscalationLabel(recEscalationLevel(ic.Recorder)),
				Transport: "intercept",
				Method:    r.Method,
				Target:    targetURL,
				RequestID: ic.RequestID,
				Agent:     ic.Agent,
			})
			http.Error(w, "blocked: session escalation level "+session.EscalationLabel(recEscalationLevel(ic.Recorder)), http.StatusForbidden)
			return
		}

		// Remove hop-by-hop headers before forwarding.
		removeHopByHopHeaders(r.Header)

		// Inject mediation envelope before forwarding on allow path.
		if ic.Proxy != nil {
			if envEmitter := ic.Proxy.envelopeEmitterPtr.Load(); envEmitter != nil {
				if envErr := envEmitter.InjectHTTPEnvelope(r.Header, envelope.BuildOpts{
					ActionID:   actionID,
					Action:     string(receipt.ClassifyHTTP(r.Method)),
					Verdict:    config.ActionAllow,
					SideEffect: string(receipt.SideEffectFromMethod(r.Method)),
					Actor:      ic.Agent,
					ActorAuth:  ic.ActorAuth,
				}); envErr != nil {
					ic.Logger.LogAnomaly(actx, "", fmt.Sprintf("mediation envelope injection failed: %v", envErr), 0.1)
				}
			}
		}

		// Forward to upstream.
		resp, err := upstream.RoundTrip(r)
		if err != nil {
			ic.Logger.LogError(actx, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck // response body

		// Fail-closed on compressed responses: DLP regex can't match
		// compressed content. Block rather than forward unscanned data.
		if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
			ic.Logger.LogBlocked(actx, "tls_response_blocked", "compressed response cannot be scanned")
			ic.Metrics.RecordTLSResponseBlocked("compressed")
			interceptEmitReceipt(ic, receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     "tls_response_blocked",
				Pattern:   "compressed response cannot be scanned",
				Transport: "intercept",
				Method:    r.Method,
				Target:    targetURL,
				RequestID: ic.RequestID,
				Agent:     ic.Agent,
			})
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
				ic.Logger.LogBlocked(actx, scannerLabelA2A, "compressed A2A stream cannot be scanned")
				ic.Metrics.RecordTLSResponseBlocked(scannerLabelA2A)
				interceptEmitReceipt(ic, receipt.EmitOpts{
					ActionID:  actionID,
					Verdict:   config.ActionBlock,
					Layer:     scannerLabelA2A,
					Pattern:   "compressed A2A stream cannot be scanned",
					Transport: "intercept",
					Method:    r.Method,
					Target:    targetURL,
					RequestID: ic.RequestID,
					Agent:     ic.Agent,
				})
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
			streamErr := mcp.ScanA2AStream(r.Context(), resp.Body, w, flusher, ic.Scanner, &ic.Config.A2AScanning)
			if streamErr != nil {
				// Distinguish scanning findings from internal/IO errors. In
				// warn mode, findings are logged as anomalies but don't
				// terminate the stream (events have already been forwarded).
				if errors.Is(streamErr, mcp.ErrA2AStreamFinding) && ic.Config.A2AScanning.Action == config.ActionWarn {
					ic.Logger.LogAnomaly(actx, scannerLabelA2A, streamErr.Error(), 0)
				} else {
					ic.Logger.LogBlocked(actx, scannerLabelA2A, streamErr.Error())
					ic.Metrics.RecordTLSResponseBlocked(scannerLabelA2A)
					interceptEmitReceipt(ic, receipt.EmitOpts{
						ActionID:  actionID,
						Verdict:   config.ActionBlock,
						Layer:     scannerLabelA2A,
						Pattern:   streamErr.Error(),
						Transport: "intercept",
						Method:    r.Method,
						Target:    targetURL,
						RequestID: ic.RequestID,
						Agent:     ic.Agent,
					})
				}
			}
			// Emit receipt for completed A2A SSE stream (clean or warn-only).
			if streamErr == nil || (errors.Is(streamErr, mcp.ErrA2AStreamFinding) && ic.Config.A2AScanning.Action == config.ActionWarn) {
				interceptEmitReceipt(ic, receipt.EmitOpts{
					ActionID:  actionID,
					Verdict:   config.ActionAllow,
					Transport: "intercept",
					Method:    r.Method,
					Target:    targetURL,
					RequestID: ic.RequestID,
					Agent:     ic.Agent,
				})
			}
			return
		}

		// Buffer response for scanning (scan-then-send, fail-closed).
		maxResp := ic.Config.TLSInterception.MaxResponseBytes
		if maxResp <= 0 {
			maxResp = interceptDefaultMaxResp
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResp+1))
		if readErr != nil {
			ic.Logger.LogError(actx, readErr)
			ic.Metrics.RecordTLSResponseBlocked("read_error")
			interceptEmitReceipt(ic, receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     "tls_response_blocked",
				Pattern:   "response read error",
				Transport: "intercept",
				Method:    r.Method,
				Target:    targetURL,
				RequestID: ic.RequestID,
				Agent:     ic.Agent,
			})
			http.Error(w, "blocked: response read error", http.StatusForbidden)
			return
		}
		if int64(len(respBody)) > maxResp {
			ic.Logger.LogBlocked(actx, "tls_response_blocked", "response too large for scanning")
			ic.Metrics.RecordTLSResponseBlocked("oversized")
			interceptEmitReceipt(ic, receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     "tls_response_blocked",
				Pattern:   "response too large for scanning",
				Transport: "intercept",
				Method:    r.Method,
				Target:    targetURL,
				RequestID: ic.RequestID,
				Agent:     ic.Agent,
			})
			http.Error(w, "blocked: response too large for scanning", http.StatusForbidden)
			return
		}

		// Browser Shield on intercepted response body.
		if ic.Proxy != nil {
			originalLen := len(respBody)
			var shieldBlocked bool
			respBody, shieldBlocked = ic.Proxy.applyShield(respBody, resp.Header.Get("Content-Type"), ic.TargetHost, resp.Header, ic.Config, actx, ic.ClientIP, ic.RequestID, TransportConnect)
			if shieldBlocked {
				ic.Metrics.RecordTLSResponseBlocked("shield_oversize")
				http.Error(w, "blocked: response body exceeds browser shield size limit", http.StatusForbidden)
				return
			}
			// If shield modified the body, update Content-Length to prevent
			// browser/client mismatch. Remove ETag and Digest since the
			// body is no longer the original.
			if len(respBody) != originalLen {
				resp.Header.Set("Content-Length", strconv.Itoa(len(respBody)))
				resp.Header.Del("ETag")
				resp.Header.Del("Digest")
			}
		}

		// Media policy on intercepted TLS responses. Runs after shield so
		// HTML/JS rewriting happens on the original body and image/audio/
		// video responses get transport-agnostic enforcement.
		mediaVerdict := applyMediaPolicy(ic.Config, resp.Header.Get("Content-Type"), respBody)
		logMediaExposureIfPresent(ic.Logger, actx, mediaVerdict, "connect")
		if mediaVerdict.Blocked {
			interceptRecordSignal(ic, session.SignalBlock)
			ic.Logger.LogBlocked(actx, "media_policy", mediaVerdict.BlockReason)
			ic.Metrics.RecordTLSResponseBlocked("media_policy")
			// Reuse the envelope/request actionID so the block receipt
			// correlates with the allow envelope already injected on
			// this request. A fresh ID here would orphan the evidence
			// pair and break downstream causality reconstruction.
			interceptEmitReceipt(ic, receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     "media_policy",
				Pattern:   mediaVerdict.BlockReason,
				Transport: "intercept",
				Method:    r.Method,
				Target:    targetURL,
				RequestID: ic.RequestID,
				Agent:     ic.Agent,
			})
			http.Error(w, "blocked: "+mediaVerdict.BlockReason, http.StatusForbidden)
			return
		}
		if mediaVerdict.StripResult != nil && mediaVerdict.StripResult.Changed() {
			respBody = mediaVerdict.Body
			resp.Header.Set("Content-Length", strconv.Itoa(len(respBody)))
			// Delete body-derived validators. Content-MD5 is often
			// set alongside ETag and describes a hash of the upstream
			// bytes — stale after metadata stripping, and a client or
			// intermediary that validates it will reject the response.
			resp.Header.Del("ETag")
			resp.Header.Del("Digest")
			resp.Header.Del("Content-MD5")
		}

		// A2A response body scanning: field-aware classification replaces
		// generic response scanning for A2A traffic. Agent Card paths route
		// through drift detection; all other A2A responses use the walker.
		if isA2A {
			var a2aRespResult mcp.A2AScanResult
			if mcp.IsAgentCardPath(r.URL.Path) {
				cardKey := mcp.CardCacheKeyFromRequest(r.URL.String(), r.Header.Get("Authorization"))
				var baseline *mcp.CardBaseline
				if ic.Proxy != nil {
					baseline = ic.Proxy.a2aCardBaseline
				}
				cardResult := mcp.ScanAgentCard(r.Context(), respBody, ic.Scanner, baseline, cardKey, &ic.Config.A2AScanning)
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
				a2aRespResult = mcp.ScanA2AResponseBody(r.Context(), respBody, ic.Scanner, &ic.Config.A2AScanning)
			}
			if !a2aRespResult.Clean {
				hasFinding = true
				action := a2aRespResult.Action
				if action == "" {
					action = ic.Config.A2AScanning.Action
				}
				reason := a2aRespResult.Reason
				if reason == "" {
					reason = "a2a: response body finding"
				}
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if action == config.ActionAsk || (action == config.ActionBlock && ic.Config.EnforceEnabled()) {
					if a2aRespResult.IsConfigMismatch() {
						interceptRecordSignal(ic, session.SignalNearMiss)
					} else {
						interceptRecordSignal(ic, session.SignalBlock)
					}
					ic.Logger.LogBlocked(actx, scannerLabelA2A, reason)
					ic.Metrics.RecordTLSResponseBlocked(scannerLabelA2A)
					interceptEmitReceipt(ic, receipt.EmitOpts{
						ActionID:  actionID,
						Verdict:   config.ActionBlock,
						Layer:     scannerLabelA2A,
						Pattern:   reason,
						Transport: "intercept",
						Method:    r.Method,
						Target:    targetURL,
						RequestID: ic.RequestID,
						Agent:     ic.Agent,
					})
					http.Error(w, "blocked: "+reason, http.StatusForbidden)
					return
				}
				// Audit/warn mode: log finding but forward response.
				ic.Logger.LogAnomaly(actx, scannerLabelA2A, reason, 0.8)
			}
		}

		// Response injection scanning.
		// Skip for response-exempt domains (e.g. trusted LLM providers).
		interceptRespExempt := isResponseScanExempt(r.URL.Hostname(), ic.Config.ResponseScanning.ExemptDomains)
		if ic.Scanner.ResponseScanningEnabled() && interceptRespExempt {
			ic.Logger.LogResponseScanExempt(actx, r.URL.Hostname())
		}
		if ic.Scanner.ResponseScanningEnabled() {
			scanResult := ic.Scanner.ScanResponse(r.Context(), string(respBody))

			// Capture observer: record intercept response scan verdict for policy replay.
			// Apply exempt override before capture so the recorded action matches runtime.
			if ic.Proxy != nil {
				iRespAction := ic.Scanner.ResponseAction()
				if interceptRespExempt {
					iRespAction = config.ActionWarn
				}
				if scanResult.Clean {
					iRespAction = ""
				}
				ic.Proxy.captureObs.ObserveResponseVerdict(r.Context(), &capture.ResponseVerdictRecord{
					Subsurface:        "response_intercept",
					Transport:         "connect",
					RequestID:         ic.RequestID,
					Agent:             ic.Agent,
					Request:           capture.CaptureRequest{Method: r.Method, URL: targetURL},
					TransformKind:     capture.TransformRaw,
					RawFindings:       responseMatchesToFindings(scanResult.Matches, iRespAction),
					EffectiveFindings: responseMatchesToFindings(scanResult.Matches, iRespAction),
					EffectiveAction:   iRespAction,
					Outcome:           captureOutcome(iRespAction, scanResult.Clean),
				})
			}

			// Filter out suppressed findings (parity with fetch proxy).
			if !scanResult.Clean && len(ic.Config.Suppress) > 0 {
				var kept []scanner.ResponseMatch
				for _, m := range scanResult.Matches {
					if !config.IsSuppressed(m.PatternName, r.URL.String(), ic.Config.Suppress) {
						kept = append(kept, m)
					}
				}
				scanResult.Matches = kept
				scanResult.Clean = len(kept) == 0
			}
			if !scanResult.Clean {
				hasFinding = true
				action := ic.Scanner.ResponseAction()
				// Exempt domains: pin to warn, skip adaptive scoring/upgrade.
				if interceptRespExempt {
					action = config.ActionWarn
				}
				// Adaptive enforcement: upgrade the response action before the switch.
				// Exempt domains skip upgrade — operator's trust decision overrides escalation.
				originalAction := action
				if !interceptRespExempt {
					action = decide.UpgradeAction(action, recEscalationLevel(ic.Recorder), &ic.Config.AdaptiveEnforcement)
				}
				if action != originalAction {
					sessionKey := ic.ClientIP
					if ic.Agent != "" && ic.Agent != agentAnonymous {
						sessionKey = ic.Agent + "|" + ic.ClientIP
					}
					ic.Logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(recEscalationLevel(ic.Recorder)), originalAction, action, "response_scan", ic.ClientIP, ic.RequestID)
					if ic.Proxy != nil {
						ic.Proxy.metrics.RecordAdaptiveUpgrade(originalAction, action, session.EscalationLabel(recEscalationLevel(ic.Recorder)))
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
					if !interceptRespExempt {
						interceptRecordSignal(ic, session.SignalBlock)
					}
					ic.Logger.LogBlocked(actx, "response_scan", reason)
					ic.Metrics.RecordTLSResponseBlocked("injection")
					interceptEmitReceipt(ic, receipt.EmitOpts{
						ActionID:  actionID,
						Verdict:   config.ActionBlock,
						Layer:     "response_scan",
						Pattern:   reason,
						Transport: "intercept",
						Method:    r.Method,
						Target:    targetURL,
						RequestID: ic.RequestID,
						Agent:     ic.Agent,
					})
					http.Error(w, "blocked: response contains injection", http.StatusForbidden)
					return
				case config.ActionStrip:
					// Record SignalStrip for adaptive enforcement scoring.
					// Exempt domains skip scoring — findings are logged but don't escalate.
					if !interceptRespExempt && ic.SessionMgr != nil && ic.Config.AdaptiveEnforcement.Enabled {
						ceeSM := ic.SessionMgr
						if ic.Proxy != nil {
							ceeSM = ic.Proxy.sessionMgrPtr.Load()
						}
						if ceeSM != nil {
							sessionKey := ic.ClientIP
							if ic.Agent != "" && ic.Agent != agentAnonymous {
								sessionKey = ic.Agent + "|" + ic.ClientIP
							}
							sess := ceeSM.GetOrCreate(sessionKey)
							var stripMetrics *metrics.Metrics
							if ic.Proxy != nil {
								stripMetrics = ic.Proxy.metrics
							}
							decide.RecordSignal(sess, session.SignalStrip, decide.EscalationParams{
								Threshold: ic.Config.AdaptiveEnforcement.EscalationThreshold,
								Logger:    ic.Logger,
								Metrics:   stripMetrics,
								Session:   sessionKey,
								ClientIP:  ic.ClientIP,
								RequestID: ic.RequestID,
							})
						}
					}
					respBody = []byte(scanResult.TransformedContent)
					// Update Content-Length to match stripped body; prevents HTTP/1.1
					// framing errors from a stale upstream Content-Length header.
					resp.Header.Set("Content-Length", strconv.Itoa(len(respBody)))
					ic.Logger.LogResponseScan(actx, config.ActionStrip, len(scanResult.Matches), patternNames, bundleRules)
				default:
					// warn/forward: log and forward unmodified.
					ic.Logger.LogResponseScan(actx, action, len(scanResult.Matches), patternNames, bundleRules)
				}
			}
		}

		// Record clean request for adaptive score decay. Only apply decay when no
		// finding was detected; warn/strip paths indicate suspicious traffic and
		// must not contribute to score decay.
		if ic.Recorder != nil && ic.Config.AdaptiveEnforcement.Enabled && !hasFinding {
			ic.Recorder.RecordClean(ic.Config.AdaptiveEnforcement.DecayPerCleanRequest)
		}

		// Record response size for per-domain data budget tracking.
		ic.Scanner.RecordRequest(strings.ToLower(ic.TargetHost), len(respBody))

		// Count intercepted request in stats so /stats reflects CONNECT traffic.
		// Use agentAnonymous (bounded cardinality) since intercept handler
		// doesn't resolve agent profiles — avoids Prometheus label explosion.
		ic.Metrics.RecordAllowed(time.Since(reqStart), agentAnonymous)
		interceptEmitReceipt(ic, receipt.EmitOpts{
			ActionID:  actionID,
			Verdict:   config.ActionAllow,
			Transport: "intercept",
			Method:    r.Method,
			Target:    targetURL,
			RequestID: ic.RequestID,
			Agent:     ic.Agent,
		})

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
