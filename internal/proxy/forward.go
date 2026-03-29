// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	maxConcurrentTunnels = 1024
	tunnelBufSize        = 32 * 1024 // 32KB copy buffer
)

// hopByHopHeaders are RFC 7230 section 6.1 hop-by-hop headers that must be
// removed when forwarding requests/responses through a proxy.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// tunnelSemaphore limits concurrent CONNECT tunnels.
type tunnelSemaphore struct {
	ch chan struct{}
}

func newTunnelSemaphore(capacity int) *tunnelSemaphore {
	return &tunnelSemaphore{ch: make(chan struct{}, capacity)}
}

func (s *tunnelSemaphore) TryAcquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *tunnelSemaphore) Release() {
	<-s.ch
}

// tunnelSem is the global semaphore for concurrent CONNECT tunnels.
// Initialized lazily on first use to avoid allocation when forward proxy is disabled.
var (
	tunnelSem     *tunnelSemaphore
	tunnelSemOnce sync.Once
)

func getTunnelSemaphore() *tunnelSemaphore {
	tunnelSemOnce.Do(func() {
		tunnelSem = newTunnelSemaphore(maxConcurrentTunnels)
	})
	return tunnelSem
}

// handleConnect handles HTTP CONNECT tunnel requests. It scans the target
// hostname through the full scanner pipeline, establishes a TCP connection
// via the SSRF-safe dialer, and relays data bidirectionally.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	clientIP, requestID := requestMeta(r)

	// Resolve per-agent config and scanner from a single registry snapshot.
	// This prevents TOCTOU races during hot-reload where knownProfiles()
	// and resolveAgent() could read different registries.
	resolved, id := p.resolveAgentFromRequest(r)
	cfg := resolved.Config
	sc := resolved.Scanner
	agent := id.Name
	if agent == "" {
		agent = agentAnonymous
	}
	agentLabel := id.Profile // bounded cardinality for Prometheus labels

	target := r.Host
	if target == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}

	// Ensure target has a port. CONNECT targets are always host:port.
	// Strip brackets from bare IPv6 literals before JoinHostPort adds them back.
	if _, _, err := net.SplitHostPort(target); err != nil {
		bare := strings.TrimPrefix(strings.TrimSuffix(target, "]"), "[")
		target = net.JoinHostPort(bare, "443")
	}

	// Synthesize a URL for scanner pipeline. The scanner expects a full URL,
	// but CONNECT only gives us host:port. Use https:// as the tunnel is
	// typically used for TLS traffic.
	host, _, _ := net.SplitHostPort(target)
	syntheticHost := host
	if strings.Contains(host, ":") { // IPv6 literal needs brackets in URL
		syntheticHost = "[" + host + "]"
	}
	syntheticURL := "https://" + syntheticHost + "/"

	// Scan through all layers (URL pipeline).
	result := sc.Scan(r.Context(), syntheticURL)

	// Capture observer: record CONNECT URL verdict for policy replay.
	{
		findings := urlResultToFindings(result)
		action := ""
		if !result.Allowed {
			action = config.ActionBlock
		}
		p.captureObs.ObserveURLVerdict(r.Context(), &capture.URLVerdictRecord{
			Subsurface:        "connect_url",
			Transport:         "connect",
			RequestID:         requestID,
			Agent:             agent,
			Request:           capture.CaptureRequest{Method: http.MethodConnect, URL: syntheticURL},
			RawFindings:       findings,
			EffectiveFindings: findings,
			EffectiveAction:   action,
			Outcome:           captureOutcome(action, result.Allowed),
		})
	}

	connectSessionKey := CeeSessionKey(agent, clientIP)
	var connectRec session.Recorder
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		connectRec = sm.GetOrCreate(connectSessionKey)
	}

	// Scan CONNECT request headers for DLP patterns. The CONNECT handshake
	// can carry Proxy-Authorization, Authorization, or custom headers that
	// may contain secrets. Tunneled HTTP headers are only visible with TLS
	// interception; this covers the handshake itself.
	connectHeaderBlocked, connectHeaderHadFinding := p.evalHeaderDLP(r.Context(), r.Header, cfg, sc, p.logger, http.MethodConnect, syntheticURL, host, clientIP, requestID, agent, start)
	if connectHeaderHadFinding && !connectHeaderBlocked && cfg.AdaptiveEnforcement.Enabled {
		// Audit/warn mode: header DLP found something but did not block.
		// Record a near-miss signal. Blocked findings go through
		// recordSessionActivity(allowed=false) which fires SignalBlock.
		// Skip signal recording for adaptive-exempt destinations — auth
		// headers to trusted services are expected and should not feed
		// escalation. Uses exempt_domains (trust), not api_allowlist (reachability).
		if connectRec != nil && !isAdaptiveExempt(host, cfg.AdaptiveEnforcement.ExemptDomains) {
			decide.RecordEscalation(connectRec, session.SignalNearMiss, decide.EscalationParams{
				Threshold: cfg.AdaptiveEnforcement.EscalationThreshold,
				Logger:    p.logger,
				Metrics:   p.metrics,
				Session:   connectSessionKey,
				ClientIP:  clientIP,
				RequestID: requestID,
			})
		}
	}
	if connectHeaderBlocked {
		// Record session activity so adaptive enforcement sees header-DLP blocks.
		// For adaptive-exempt destinations, record as allowed with deferClean=true
		// so session profiling tracks the domain but neither escalation signals nor
		// clean-decay fire. Blocked exempt traffic is score-neutral.
		if isAdaptiveExempt(host, cfg.AdaptiveEnforcement.ExemptDomains) {
			p.recordSessionActivity(clientIP, agent, host, requestID, scanner.Result{Allowed: true}, cfg, p.logger, true)
		} else {
			p.recordSessionActivity(clientIP, agent, host, requestID, scanner.Result{Allowed: false, Score: 0.9}, cfg, p.logger, false)
		}
		p.metrics.RecordTunnelBlocked(agentLabel)
		http.Error(w, "CONNECT blocked: header DLP match", http.StatusForbidden)
		return
	}

	// Session profiling: record BEFORE the enforce-mode early return so adaptive
	// signals (SignalBlock) fire even for blocked requests. Pass deferClean=true
	// so a warn-only header or CEE finding on the same CONNECT request does not
	// get offset by a clean decay from the URL stage.
	sr := p.recordSessionActivity(clientIP, agent, host, requestID, result, cfg, p.logger, true)
	hasFinding := (!result.Allowed && !result.IsProtective()) || connectHeaderHadFinding

	if !result.Allowed {
		status := http.StatusForbidden
		if result.Scanner == scanner.ScannerRateLimit {
			status = http.StatusTooManyRequests
		}
		if cfg.EnforceEnabled() {
			p.logger.LogBlocked(http.MethodConnect, target, result.Scanner, result.Reason, clientIP, requestID, agent)
			p.metrics.RecordTunnelBlocked(agentLabel)
			if cfg.ExplainBlocksEnabled() && result.Hint != "" {
				w.Header().Set("X-Pipelock-Hint", result.Hint)
			}
			http.Error(w, "CONNECT blocked: "+result.Reason, status)
			return
		}
		// Audit mode: base action is "warn". Adaptive escalation may upgrade to block.
		baseAction := config.ActionWarn
		effectiveAction := decide.UpgradeAction(baseAction, sr.Level, &cfg.AdaptiveEnforcement)
		if effectiveAction == config.ActionBlock {
			sessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				sessionKey = agent + "|" + clientIP
			}
			p.logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), baseAction, effectiveAction, result.Scanner, clientIP, requestID)
			p.metrics.RecordAdaptiveUpgrade(baseAction, effectiveAction, session.EscalationLabel(sr.Level))
			p.logger.LogBlocked(http.MethodConnect, target, result.Scanner, result.Reason+" (escalated)", clientIP, requestID, agent)
			p.metrics.RecordTunnelBlocked(agentLabel)
			http.Error(w, "CONNECT blocked: "+result.Reason+" (escalated)", status)
			return
		}
		p.logger.LogAnomaly(http.MethodConnect, target, result.Scanner,
			result.Reason, clientIP, requestID, agent, result.Score)
	}

	if sr.Blocked {
		http.Error(w, sr.Detail, http.StatusForbidden)
		return
	}

	// block_all enforcement: deny ALL traffic (including clean) when the
	// session is at an escalation level with block_all=true.
	if sr.Level > 0 && decide.UpgradeAction("", sr.Level, &cfg.AdaptiveEnforcement) == config.ActionBlock {
		sessionKey := clientIP
		if agent != "" && agent != agentAnonymous {
			sessionKey = agent + "|" + clientIP
		}
		p.logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), "", config.ActionBlock, "session_deny", clientIP, requestID)
		p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(sr.Level))
		p.metrics.RecordTunnelBlocked(agentLabel)
		http.Error(w, "CONNECT blocked: session escalation level "+session.EscalationLabel(sr.Level), http.StatusForbidden)
		return
	}

	// Budget admission check: enforce request count and domain limits.
	if err := resolved.Budget.CheckAdmission(strings.ToLower(host)); err != nil {
		reason := err.Error()
		p.logger.LogBlocked(http.MethodConnect, target, "budget", reason, clientIP, requestID, agent)
		p.metrics.RecordTunnelBlocked(agentLabel)
		http.Error(w, "CONNECT blocked: "+reason, http.StatusTooManyRequests)
		return
	}

	// CEE for opaque CONNECT tunnels. Fragment buffering is not useful
	// without body data. Hostname entropy tracking is DISABLED for CONNECT
	// because the hostname is the destination, not exfiltration data.
	// Repeated polling to the same host (e.g. Telegram bot getUpdates)
	// was exhausting the entropy budget and triggering adaptive escalation
	// to block_all, permanently locking out legitimate agents.
	// DLP, SSRF, and per-request entropy checks still run on the hostname.
	if ceeCfg := ceeEffectiveConfig(cfg.CrossRequestDetection, cfg.EnforceEnabled()); ceeCfg.Enabled {
		sessionKey := CeeSessionKey(agent, clientIP)
		if et := p.entropyTrackerPtr.Load(); et != nil && ceeCfg.EntropyBudget.Enabled {
			// Skip: CONNECT hostname is NOT recorded to entropy budget.
			// Only query values, request bodies, and MCP args contribute.
			if et.BudgetExceeded(sessionKey) {
				hasFinding = true
				p.metrics.RecordCrossRequestEntropyExceeded()
				detail := fmt.Sprintf("entropy budget exceeded: %.0f/%.0f bits",
					et.CurrentUsage(sessionKey), et.Budget())
				if sm := p.sessionMgrPtr.Load(); sm != nil && cfg.AdaptiveEnforcement.Enabled {
					ceeRecordSignals(ceeResult{EntropyHit: true}, sm, sessionKey,
						cfg.AdaptiveEnforcement.EscalationThreshold, p.logger, p.metrics, clientIP, requestID)
				}
				ceeAction := ceeCfg.EntropyBudget.Action
				originalCEEAction := ceeAction
				ceeAction = decide.UpgradeAction(ceeAction, sr.Level, &cfg.AdaptiveEnforcement)
				if ceeAction != originalCEEAction {
					p.logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), originalCEEAction, ceeAction, "cross_request_entropy", clientIP, requestID)
					p.metrics.RecordAdaptiveUpgrade(originalCEEAction, ceeAction, session.EscalationLabel(sr.Level))
				}
				if ceeAction == config.ActionBlock {
					p.logger.LogBlocked(http.MethodConnect, target, "cross_request_entropy", detail, clientIP, requestID, agent)
					p.metrics.RecordTunnelBlocked(agentLabel)
					http.Error(w, "CONNECT blocked: cross-request entropy budget exceeded", http.StatusForbidden)
					return
				}
				p.logger.LogAnomaly(http.MethodConnect, target, "cross_request_entropy", detail, clientIP, requestID, agent, 0)
			}
		}
	}

	// Re-check block_all after CONNECT CEE may have escalated the session. The
	// CEE block above may fire ceeRecordSignals without blocking (e.g. entropy
	// budget exceeded but action=warn), pushing the session to a block_all level.
	// Use the live recorder for an up-to-date escalation level.
	if cfg.AdaptiveEnforcement.Enabled {
		if connectRec != nil {
			if decide.UpgradeAction("", connectRec.EscalationLevel(), &cfg.AdaptiveEnforcement) == config.ActionBlock {
				p.logger.LogAdaptiveUpgrade(connectSessionKey, session.EscalationLabel(connectRec.EscalationLevel()), "", config.ActionBlock, "session_deny", clientIP, requestID)
				p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(connectRec.EscalationLevel()))
				p.metrics.RecordTunnelBlocked(agentLabel)
				http.Error(w, "CONNECT blocked: session escalation level "+session.EscalationLabel(connectRec.EscalationLevel()), http.StatusForbidden)
				return
			}
		}
	}

	if connectRec != nil && cfg.AdaptiveEnforcement.Enabled && !hasFinding {
		connectRec.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
	}

	// WebSocket redirect hint: if the target host matches the redirect list
	// and WebSocket proxy is enabled, suggest using /ws instead of CONNECT.
	// Checked BEFORE dial to avoid wasting a TCP connection.
	if cfg.WebSocketProxy.Enabled && len(cfg.ForwardProxy.RedirectWebSocketHosts) > 0 {
		if isHostAllowlisted(host, cfg.ForwardProxy.RedirectWebSocketHosts) {
			p.metrics.RecordWSRedirectHint()
			p.logger.LogAnomaly(http.MethodConnect, target, "",
				fmt.Sprintf("hint: %s supports WebSocket; consider using /ws endpoint for frame-level scanning", host),
				clientIP, requestID, agent, 0.2)
		}
	}

	// Check tunnel capacity
	sem := getTunnelSemaphore()
	if !sem.TryAcquire() {
		http.Error(w, "too many active tunnels", http.StatusServiceUnavailable)
		return
	}
	defer sem.Release()

	// Compute absolute deadline once from start. This covers both dial and
	// relay so the total tunnel lifetime never exceeds max_tunnel_seconds.
	maxDuration := time.Duration(cfg.ForwardProxy.MaxTunnelSeconds) * time.Second
	deadline := start.Add(maxDuration)
	dialCtx, dialCancel := context.WithDeadline(r.Context(), deadline)
	defer dialCancel()

	targetConn, err := p.ssrfSafeDialContext(dialCtx, "tcp", target)
	if err != nil {
		p.logger.LogError(http.MethodConnect, target, clientIP, requestID, agent, err)
		http.Error(w, "tunnel dial failed", http.StatusBadGateway)
		return
	}
	defer func() {
		if targetConn != nil {
			_ = targetConn.Close()
		}
	}()

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.LogError(http.MethodConnect, target, clientIP, requestID, agent,
			fmt.Errorf("response writer does not support hijacking"))
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		p.logger.LogError(http.MethodConnect, target, clientIP, requestID, agent, err)
		return
	}
	defer clientConn.Close() //nolint:errcheck // best effort

	// Send 200 Connection Established
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// SNI verification: read ClientHello via Peek, check SNI matches CONNECT
	// target. Peek() leaves bytes in the buffer for the relay to forward.
	// verifySNI may return a resized reader if the TLS record exceeds the
	// default 4KB bufio buffer (common with large extension sets).
	clientReader := buf.Reader
	if cfg.ForwardProxy.SNIVerificationEnabled() {
		resized, sniHost, category, sniErr := verifySNI(clientReader, clientConn, host, sniReadTimeoutDefault)
		clientReader = resized
		p.metrics.RecordSNI(category, agentLabel)
		if sniErr != nil {
			p.logger.LogSNIMismatch(host, sniHost, clientIP, requestID, agent, category)
			return // close both connections via deferred Close()
		}
	}

	// TLS interception: decrypt tunnel and scan body/headers/responses.
	// Branch here after SNI verification but before raw splice. If interception
	// is enabled and the host is not on the passthrough list, interceptTunnel
	// takes over the client connection and handles the full request lifecycle.
	_, port, _ := net.SplitHostPort(target)
	if cfg.TLSInterception.Enabled && !isPassthrough(host, cfg.TLSInterception.PassthroughDomains) {
		certCache := p.certCachePtr.Load()
		if certCache == nil {
			// Fail-closed: TLS interception is enabled but cert cache is missing.
			// Connection is already hijacked, so close both sides (deferred).
			p.logger.LogError(http.MethodConnect, host, clientIP, requestID, agent, fmt.Errorf("TLS interception enabled but cert cache unavailable"))
			p.metrics.RecordTLSIntercept("failed")
			return
		}
		// Close the pre-established upstream TCP connection since interceptTunnel
		// creates its own via the SSRF-safe dialer. This prevents a dangling connection.
		_ = targetConn.Close()
		targetConn = nil
		p.metrics.RecordTLSIntercept("intercepted")
		p.logger.LogAnomaly(http.MethodConnect, host, "tls_intercept", "TLS MITM interception active", clientIP, requestID, agent, 0) // 0: informational, not anomalous
		// Wrap clientConn with buffered reader so any bytes peeked during
		// SNI verification (ClientHello) are available to the TLS server.
		interceptConn := wrapBuffered(clientConn, clientReader)
		interceptCtx, interceptCancel := context.WithDeadline(r.Context(), deadline)
		defer interceptCancel()
		// Obtain a live session recorder for the tunnel. This provides live
		// escalation level lookups instead of a stale snapshot from sr.Level.
		var interceptRec session.Recorder
		if sm := p.sessionMgrPtr.Load(); sm != nil {
			interceptSessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				interceptSessionKey = agent + "|" + clientIP
			}
			interceptRec = sm.GetOrCreate(interceptSessionKey)
		}
		if err := interceptTunnel(interceptCtx, interceptConn, host, port, cfg, sc, certCache, p.logger, p.metrics, clientIP, requestID, agent, p.tlsTransport, p.ssrfSafeDialContext, p.entropyTrackerPtr.Load(), p.fragmentBufferPtr.Load(), p.sessionMgrPtr.Load(), p, interceptRec); err != nil {
			p.logger.LogError(http.MethodConnect, host, clientIP, requestID, agent, err)
		}
		return
	}

	// Flush any buffered data from the HTTP parsing layer
	if clientReader.Buffered() > 0 {
		buffered := make([]byte, clientReader.Buffered())
		_, _ = clientReader.Read(buffered)
		_, _ = targetConn.Write(buffered)
	}

	p.metrics.IncrActiveTunnels()
	p.logger.LogTunnelOpen(target, clientIP, requestID, agent)

	// Bidirectional relay with idle timeout
	idleTimeout := time.Duration(cfg.ForwardProxy.IdleTimeoutSeconds) * time.Second
	totalBytes := bidirectionalCopy(clientConn, targetConn, idleTimeout, deadline, p.ks)

	p.metrics.DecrActiveTunnels()
	duration := time.Since(start)
	p.metrics.RecordTunnel(duration, totalBytes, agentLabel)
	// Count successful tunnels in request totals so /stats reflects CONNECT traffic.
	p.metrics.RecordAllowed(duration, agentLabel)
	p.logger.LogTunnelClose(target, clientIP, requestID, agent, totalBytes, duration)

	// Record data budget for the target domain
	sc.RecordRequest(strings.ToLower(host), int(totalBytes))

	// Record tunnel bytes for per-agent budget tracking. CONNECT tunnels
	// are streaming: bytes are tracked after close and enforced on the next
	// admission check, not mid-stream (can't un-send tunnel data).
	_ = resolved.Budget.RecordBytes(totalBytes)
}

// bidirectionalCopy relays data between two connections with idle timeout.
// The deadline is an absolute time computed once in handleConnect so the total
// tunnel lifetime (including dial) never exceeds max_tunnel_seconds.
// When ks is non-nil, the kill switch is checked after each read so activation
// mid-stream terminates already-open tunnels immediately.
// Returns the total bytes transferred in both directions.
func bidirectionalCopy(client, target net.Conn, idleTimeout time.Duration, deadline time.Time, ks *killswitch.Controller) int64 {
	_ = client.SetDeadline(deadline)
	_ = target.SetDeadline(deadline)

	var clientToTarget, targetToClient int64
	done := make(chan struct{})

	go func() {
		clientToTarget = copyWithIdleTimeout(target, client, idleTimeout, deadline, ks)
		// Half-close: signal target that no more data is coming
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		close(done)
	}()

	targetToClient = copyWithIdleTimeout(client, target, idleTimeout, deadline, ks)
	// Half-close: signal client that no more data is coming
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	<-done
	return clientToTarget + targetToClient
}

// copyWithIdleTimeout copies from src to dst, resetting the read deadline
// on src after each successful read. The per-read deadline is capped at the
// absolute deadline so tunnels cannot exceed max_tunnel_seconds while active.
// When ks is non-nil, the kill switch is checked after each successful read
// so activation mid-tunnel terminates the connection immediately.
// Returns total bytes copied.
func copyWithIdleTimeout(dst, src net.Conn, idleTimeout time.Duration, deadline time.Time, ks *killswitch.Controller) int64 {
	buf := make([]byte, tunnelBufSize)
	var total int64
	for {
		// Kill switch: terminate tunnel immediately when activated mid-stream.
		if ks != nil && ks.IsActive() {
			return total
		}

		rd := time.Now().Add(idleTimeout)
		if rd.After(deadline) {
			rd = deadline
		}
		_ = src.SetReadDeadline(rd)
		n, err := src.Read(buf)
		if n > 0 {
			written, wErr := dst.Write(buf[:n])
			total += int64(written)
			if wErr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}

// handleForwardHTTP handles forward proxy requests with absolute URIs
// (e.g., GET http://example.com/path). Scans the URL, forwards the
// request, and streams the raw response back to the client.
func (p *Proxy) handleForwardHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	clientIP, requestID := requestMeta(r)

	// Resolve per-agent config and scanner from a single registry snapshot.
	// This prevents TOCTOU races during hot-reload where knownProfiles()
	// and resolveAgent() could read different registries.
	resolved, id := p.resolveAgentFromRequest(r)
	cfg := resolved.Config
	sc := resolved.Scanner
	agent := id.Name
	if agent == "" {
		agent = agentAnonymous
	}
	agentLabel := id.Profile // bounded cardinality for Prometheus labels

	targetURL := r.URL.String()

	// Scan through all layers (URL pipeline)
	result := sc.Scan(r.Context(), targetURL)

	// A2A protocol detection: check path and Content-Type before deeper scanning.
	isA2A := cfg.A2AScanning.Enabled && mcp.IsA2ARequest(r.URL.Path, r.Header.Get("Content-Type"))

	// A2A header scanning: scan A2A-Extensions header for blocked URIs.
	if isA2A {
		hdrResult := mcp.ScanA2AHeaders(r.Context(), r.Header, sc, &cfg.A2AScanning)
		if !hdrResult.Clean {
			action := hdrResult.Action
			if action == "" {
				action = cfg.A2AScanning.Action
			}
			reason := hdrResult.Reason
			if reason == "" {
				reason = "a2a: header finding"
			}
			p.logger.LogAnomaly(r.Method, targetURL, "a2a_header", reason, clientIP, requestID, agent, 0)
			if action == config.ActionBlock {
				p.metrics.RecordBlocked(r.URL.Hostname(), "a2a_header", time.Since(start), agentLabel)
				http.Error(w, "blocked: "+reason, http.StatusForbidden)
				return
			}
		}
	}

	// Capture observer: record forward URL verdict for policy replay.
	{
		findings := urlResultToFindings(result)
		action := ""
		if !result.Allowed {
			action = config.ActionBlock
		}
		p.captureObs.ObserveURLVerdict(r.Context(), &capture.URLVerdictRecord{
			Subsurface:        "forward_url",
			Transport:         "forward",
			RequestID:         requestID,
			Agent:             agent,
			Request:           capture.CaptureRequest{Method: r.Method, URL: targetURL},
			RawFindings:       findings,
			EffectiveFindings: findings,
			EffectiveAction:   action,
			Outcome:           captureOutcome(action, result.Allowed),
		})
	}

	// Session profiling: record BEFORE the enforce-mode early return so adaptive
	// signals (SignalBlock) fire even for blocked requests. Pass deferClean=true
	// so later request/response findings on the same round trip do not get
	// offset by an early clean decay from the URL stage.
	sr := p.recordSessionActivity(clientIP, agent, r.URL.Hostname(), requestID, result, cfg, p.logger, true)

	forwardSessionKey := CeeSessionKey(agent, clientIP)
	var forwardRec session.Recorder
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		forwardRec = sm.GetOrCreate(forwardSessionKey)
	}
	hasFinding := !result.Allowed && !result.IsProtective()

	if !result.Allowed {
		status := http.StatusForbidden
		if result.Scanner == scanner.ScannerRateLimit {
			status = http.StatusTooManyRequests
		}
		if cfg.EnforceEnabled() {
			p.logger.LogBlocked(r.Method, targetURL, result.Scanner, result.Reason, clientIP, requestID, agent)
			p.metrics.RecordBlocked(r.URL.Hostname(), result.Scanner, time.Since(start), agentLabel)
			if cfg.ExplainBlocksEnabled() && result.Hint != "" {
				w.Header().Set("X-Pipelock-Hint", result.Hint)
			}
			http.Error(w, "blocked: "+result.Reason, status)
			return
		}
		// Audit mode: base action is "warn". Adaptive escalation may upgrade to block.
		baseAction := config.ActionWarn
		effectiveAction := decide.UpgradeAction(baseAction, sr.Level, &cfg.AdaptiveEnforcement)
		if effectiveAction == config.ActionBlock {
			sessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				sessionKey = agent + "|" + clientIP
			}
			p.logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), baseAction, effectiveAction, result.Scanner, clientIP, requestID)
			p.metrics.RecordAdaptiveUpgrade(baseAction, effectiveAction, session.EscalationLabel(sr.Level))
			p.logger.LogBlocked(r.Method, targetURL, result.Scanner, result.Reason+" (escalated)", clientIP, requestID, agent)
			p.metrics.RecordBlocked(r.URL.Hostname(), result.Scanner, time.Since(start), agentLabel)
			http.Error(w, "blocked: "+result.Reason+" (escalated)", status)
			return
		}
		p.logger.LogAnomaly(r.Method, targetURL, result.Scanner,
			result.Reason, clientIP, requestID, agent, result.Score)
	}

	if sr.Blocked {
		http.Error(w, sr.Detail, http.StatusForbidden)
		return
	}

	// block_all enforcement: deny ALL traffic (including clean) when the
	// session is at an escalation level with block_all=true.
	if sr.Level > 0 && decide.UpgradeAction("", sr.Level, &cfg.AdaptiveEnforcement) == config.ActionBlock {
		sessionKey := clientIP
		if agent != "" && agent != agentAnonymous {
			sessionKey = agent + "|" + clientIP
		}
		p.logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), "", config.ActionBlock, "session_deny", clientIP, requestID)
		p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(sr.Level))
		p.metrics.RecordBlocked(r.URL.Hostname(), "session_deny", time.Since(start), agentLabel)
		http.Error(w, "blocked: session escalation level "+session.EscalationLabel(sr.Level), http.StatusForbidden)
		return
	}

	// Budget admission check: enforce request count and domain limits.
	if err := resolved.Budget.CheckAdmission(strings.ToLower(r.URL.Hostname())); err != nil {
		reason := err.Error()
		p.logger.LogBlocked(r.Method, targetURL, "budget", reason, clientIP, requestID, agent)
		p.metrics.RecordBlocked(r.URL.Hostname(), "budget", time.Since(start), agentLabel)
		http.Error(w, "blocked: "+reason, http.StatusTooManyRequests)
		return
	}

	// Request body DLP scanning: read and scan body before Clone so the
	// cloned request gets the re-wrapped buffered bytes.
	if cfg.RequestBodyScanning.Enabled && r.Body != nil && r.Body != http.NoBody {
		buf, bodyResult := scanRequestBody(r.Context(), r.Body, r.Header.Get("Content-Type"),
			r.Header.Get("Content-Encoding"), cfg.RequestBodyScanning.MaxBodyBytes, sc, agent)

		// Capture observer: record forward body DLP verdict for policy replay.
		{
			bodyAction := ""
			if !bodyResult.Clean {
				bodyAction = bodyResult.Action
				if bodyAction == "" {
					bodyAction = cfg.RequestBodyScanning.Action
				}
			}
			p.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
				Subsurface:      "dlp_body_forward",
				Transport:       "forward",
				RequestID:       requestID,
				Agent:           agent,
				Request:         capture.CaptureRequest{Method: r.Method, URL: targetURL},
				TransformKind:   capture.TransformJoinedFields,
				RawFindings:     bodyScanToFindings(bodyResult),
				EffectiveAction: bodyAction,
				Outcome:         captureOutcome(bodyAction, bodyResult.Clean),
			})
		}

		if !bodyResult.Clean {
			hasFinding = true
			action := bodyResult.Action
			if action == "" {
				action = cfg.RequestBodyScanning.Action
			}

			// Determine scanner label: address_protection vs body_dlp.
			scannerLabel := scannerLabelBodyDLP
			if len(bodyResult.AddressFindings) > 0 && len(bodyResult.DLPMatches) == 0 {
				scannerLabel = scannerLabelAddressProtection
			}

			patternNames := dlpMatchNames(bodyResult.DLPMatches)
			bundleRules := dlpBundleRules(bodyResult.DLPMatches)
			reason := bodyResult.Reason
			if reason == "" {
				reason = fmt.Sprintf("request body contains secret: %s", strings.Join(patternNames, ", "))
			}

			// Emit telemetry for both finding types independently.
			// A request can trigger both DLP and address findings simultaneously.
			if len(bodyResult.DLPMatches) > 0 {
				p.metrics.RecordBodyDLP(action, agentLabel)
				p.logger.LogBodyDLP(r.Method, targetURL, action, clientIP, requestID, agent, len(bodyResult.DLPMatches), patternNames, bundleRules)
			}
			if len(bodyResult.AddressFindings) > 0 {
				for _, f := range bodyResult.AddressFindings {
					verdictLabel := "unknown"
					if f.Verdict == addressprotect.VerdictLookalike {
						verdictLabel = "lookalike"
					}
					p.metrics.RecordAddressFinding(f.Chain, verdictLabel)
				}
				addrNames := make([]string, len(bodyResult.AddressFindings))
				for i, f := range bodyResult.AddressFindings {
					addrNames[i] = f.Explanation
				}
				p.logger.LogBodyScan(r.Method, targetURL, audit.EventAddressProtection, action, clientIP, requestID, agent, len(bodyResult.AddressFindings), addrNames)
			}

			// Fail-closed: when buf is nil the body was consumed but couldn't
			// be buffered (oversize, compressed, read error, multipart parse
			// error). Always block regardless of enforce mode — forwarding an
			// empty body corrupts the upstream request.
			if buf == nil {
				p.metrics.RecordBlocked(r.URL.Hostname(), scannerLabel, time.Since(start), agentLabel)
				http.Error(w, "blocked: "+reason, http.StatusForbidden)
				return
			}

			// Adaptive enforcement: upgrade the body action.
			// DLP-only exemption: skip upgrade for DLP pattern findings on
			// adaptive-exempt destinations. Address protection findings and
			// fail-closed body errors are NOT exempted.
			originalBodyAction := action
			fwdBodyExempt := scannerLabel == scannerLabelBodyDLP &&
				len(bodyResult.DLPMatches) > 0 &&
				isAdaptiveExempt(r.URL.Hostname(), cfg.AdaptiveEnforcement.ExemptDomains)
			if !fwdBodyExempt {
				action = decide.UpgradeAction(action, sr.Level, &cfg.AdaptiveEnforcement)
			}
			if action != originalBodyAction {
				sessionKey := clientIP
				if agent != "" && agent != agentAnonymous {
					sessionKey = agent + "|" + clientIP
				}
				p.logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), originalBodyAction, action, scannerLabel, clientIP, requestID)
				p.metrics.RecordAdaptiveUpgrade(originalBodyAction, action, session.EscalationLabel(sr.Level))
			}

			if action == config.ActionBlock && cfg.EnforceEnabled() {
				p.metrics.RecordBlocked(r.URL.Hostname(), scannerLabel, time.Since(start), agentLabel)
				http.Error(w, "blocked: "+reason, http.StatusForbidden)
				return
			}
			// Escalation can upgrade to block even in audit mode.
			if action == config.ActionBlock && !cfg.EnforceEnabled() {
				p.metrics.RecordBlocked(r.URL.Hostname(), scannerLabel, time.Since(start), agentLabel)
				http.Error(w, "blocked: "+reason+" (escalated)", http.StatusForbidden)
				return
			}
		}

		// Re-wrap body so the forwarded request gets the buffered bytes.
		r.Body = io.NopCloser(bytes.NewReader(buf))
		r.ContentLength = int64(len(buf))
	}

	// Request header DLP scanning.
	// hadFinding is true even in audit/warn mode so near-miss signals are recorded.
	forwardHeaderBlocked, forwardHeaderHadFinding := p.evalHeaderDLP(r.Context(), r.Header, cfg, sc, p.logger, r.Method, targetURL, r.URL.Hostname(), clientIP, requestID, agent, start)

	// Capture observer: record forward header DLP verdict for policy replay.
	{
		hdrAction := ""
		if forwardHeaderBlocked {
			hdrAction = config.ActionBlock
		} else if forwardHeaderHadFinding {
			hdrAction = config.ActionWarn
		}
		p.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
			Subsurface:      "dlp_header_forward",
			Transport:       "forward",
			RequestID:       requestID,
			Agent:           agent,
			Request:         capture.CaptureRequest{Method: r.Method, URL: targetURL},
			TransformKind:   capture.TransformHeaderValue,
			EffectiveAction: hdrAction,
			Outcome:         captureOutcome(hdrAction, !forwardHeaderHadFinding),
		})
	}

	if forwardHeaderHadFinding {
		hasFinding = true
	}
	if forwardHeaderHadFinding && cfg.AdaptiveEnforcement.Enabled && !isAdaptiveExempt(r.URL.Hostname(), cfg.AdaptiveEnforcement.ExemptDomains) {
		// Record adaptive signal for header DLP findings.
		// Blocked → SignalBlock (high confidence); warn-mode → SignalNearMiss.
		// Skip for adaptive-exempt destinations — auth headers to trusted
		// services are expected and should not feed escalation.
		headerSignal := session.SignalNearMiss
		if forwardHeaderBlocked {
			headerSignal = session.SignalBlock
		}
		if forwardRec != nil {
			decide.RecordEscalation(forwardRec, headerSignal, decide.EscalationParams{
				Threshold: cfg.AdaptiveEnforcement.EscalationThreshold,
				Logger:    p.logger,
				Metrics:   p.metrics,
				Session:   forwardSessionKey,
				ClientIP:  clientIP,
				RequestID: requestID,
			})
		}
	}
	if forwardHeaderBlocked {
		http.Error(w, "blocked: request header contains secret", http.StatusForbidden)
		return
	}

	// Re-check block_all after header DLP near-miss may have escalated the session.
	if forwardHeaderHadFinding && cfg.AdaptiveEnforcement.Enabled {
		if forwardRec != nil {
			if decide.UpgradeAction("", forwardRec.EscalationLevel(), &cfg.AdaptiveEnforcement) == config.ActionBlock {
				p.logger.LogAdaptiveUpgrade(forwardSessionKey, session.EscalationLabel(forwardRec.EscalationLevel()), "", config.ActionBlock, "session_deny", clientIP, requestID)
				p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(forwardRec.EscalationLevel()))
				http.Error(w, "blocked: session escalation level critical", http.StatusForbidden)
				return
			}
		}
	}

	// CEE pre-forward admission: check cross-request entropy and fragment
	// reassembly before the outbound request leaves. Forward proxy has
	// URL path, query params, and request body as outbound data.
	ceeCfg := ceeEffectiveConfig(cfg.CrossRequestDetection, cfg.EnforceEnabled())
	if ceeCfg.Enabled {
		sessionKey := CeeSessionKey(agent, clientIP)
		outbound := extractOutboundPayload(r)
		keys := queryParamKeys(r.URL)

		ceeRes := ceeAdmit(r.Context(), sessionKey, outbound, keys, targetURL, agent, clientIP, requestID,
			ceeCfg, p.entropyTrackerPtr.Load(), p.fragmentBufferPtr.Load(), sc, p.logger, p.metrics)

		// Capture observer: record forward CEE verdict for policy replay.
		ceeFindings := ceeResultToFindings(ceeRes)
		ceeAction := ""
		if ceeRes.Blocked {
			ceeAction = config.ActionBlock
		} else if ceeRes.EntropyHit || ceeRes.FragmentHit {
			ceeAction = config.ActionWarn
		}
		p.captureObs.ObserveCEEVerdict(r.Context(), &capture.CEERecord{
			Subsurface:        "cee_forward",
			Transport:         "forward",
			RequestID:         requestID,
			Agent:             agent,
			Request:           capture.CaptureRequest{Method: r.Method, URL: targetURL},
			TransformKind:     capture.TransformCEEWindow,
			RawFindings:       ceeFindings,
			EffectiveFindings: ceeFindings,
			EffectiveAction:   ceeAction,
			Outcome:           captureOutcome(ceeAction, !ceeRes.Blocked && !ceeRes.EntropyHit && !ceeRes.FragmentHit),
		})

		if ceeRes.EntropyHit || ceeRes.FragmentHit || ceeRes.Blocked {
			hasFinding = true
		}

		if sm := p.sessionMgrPtr.Load(); sm != nil && cfg.AdaptiveEnforcement.Enabled {
			ceeRecordSignals(ceeRes, sm, sessionKey, cfg.AdaptiveEnforcement.EscalationThreshold, p.logger, p.metrics, clientIP, requestID)

			// Re-check block_all after CEE may have escalated the session. Use the
			// live recorder so mid-request escalations are reflected immediately.
			fwdRec := sm.GetOrCreate(sessionKey)
			if decide.UpgradeAction("", fwdRec.EscalationLevel(), &cfg.AdaptiveEnforcement) == config.ActionBlock {
				p.logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(fwdRec.EscalationLevel()), "", config.ActionBlock, "session_deny", clientIP, requestID)
				p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(fwdRec.EscalationLevel()))
				p.metrics.RecordBlocked(r.URL.Hostname(), "session_deny", time.Since(start), agentLabel)
				http.Error(w, "blocked: session escalation level "+session.EscalationLabel(fwdRec.EscalationLevel()), http.StatusForbidden)
				return
			}
		}

		if ceeRes.Blocked {
			p.metrics.RecordBlocked(r.URL.Hostname(), "cross_request", time.Since(start), agentLabel)
			http.Error(w, "blocked: "+ceeRes.Reason, http.StatusForbidden)
			return
		}
	}

	// Clone request with context keys so CheckRedirect uses the per-agent
	// config/scanner for redirect enforcement, not the global default.
	ctx := context.WithValue(r.Context(), ctxKeyClientIP, clientIP)
	ctx = context.WithValue(ctx, ctxKeyRequestID, requestID)
	ctx = context.WithValue(ctx, ctxKeyAgent, agent)
	ctx = context.WithValue(ctx, ctxKeyAgentConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeyAgentScanner, sc)
	outReq := r.Clone(ctx)
	outReq.RequestURI = ""         // required for http.Client
	outReq.Header.Del(AgentHeader) // strip internal identity header before upstream
	removeHopByHopHeaders(outReq.Header)

	resp, err := p.client.Do(outReq)
	if err != nil {
		p.logger.LogError(r.Method, targetURL, clientIP, requestID, agent, err)
		http.Error(w, "forward proxy fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck // response body

	// Size limit: tighter of max_response_mb and remaining byte budget.
	maxBytes := int64(cfg.FetchProxy.MaxResponseMB) * 1024 * 1024
	budgetRemaining := resolved.Budget.RemainingBytes()
	if budgetRemaining >= 0 && budgetRemaining < maxBytes {
		maxBytes = budgetRemaining
	}

	// A2A SSE streaming: if the response is an A2A event stream, scan each
	// event via field-aware walker with rolling-tail cross-event injection
	// detection. Must run before the buffered response scan path.
	if isA2A && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		// Fail-closed: compressed SSE streams cannot be scanned.
		if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
			p.logger.LogBlocked(r.Method, targetURL, "a2a_stream", "compressed A2A stream cannot be scanned", clientIP, requestID, agent)
			p.metrics.RecordBlocked(r.URL.Hostname(), "a2a_stream", time.Since(start), agentLabel)
			http.Error(w, "blocked: compressed A2A stream cannot be scanned", http.StatusForbidden)
			return
		}
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		flusher, _ := w.(http.Flusher)
		if err := mcp.ScanA2AStream(r.Context(), resp.Body, w, flusher, sc, &cfg.A2AScanning); err != nil {
			// Distinguish scanning findings from internal/IO errors. In warn
			// mode, findings are logged but the stream has already been
			// forwarded (events are written before scanning the next one),
			// so we only record the anomaly. Block mode and internal errors
			// terminate the stream.
			if errors.Is(err, mcp.ErrA2AStreamFinding) && cfg.A2AScanning.Action == config.ActionWarn {
				p.logger.LogAnomaly(r.Method, targetURL, "a2a_stream", err.Error(), clientIP, requestID, agent, 0)
			} else {
				p.logger.LogBlocked(r.Method, targetURL, "a2a_stream", err.Error(), clientIP, requestID, agent)
				p.metrics.RecordBlocked(r.URL.Hostname(), "a2a_stream", time.Since(start), agentLabel)
			}
		} else {
			duration := time.Since(start)
			p.metrics.RecordAllowed(duration, agentLabel)
			p.logger.LogForwardHTTP(r.Method, targetURL, clientIP, requestID, agent, resp.StatusCode, 0, duration)
			if forwardRec != nil && cfg.AdaptiveEnforcement.Enabled && !hasFinding {
				forwardRec.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
			}
		}
		return
	}

	// Response injection scanning: buffer-then-scan-then-send when enabled.
	// Headers are copied AFTER the scan decision so blocked responses don't
	// leak upstream headers (Set-Cookie, Content-Encoding, etc.) to the client.
	// Skip for response-exempt domains. Use the final response origin after
	// redirects — an exempt host that 302s to a non-exempt host must be scanned.
	fwdRespHost := resp.Request.URL.Hostname()
	fwdRespExempt := isResponseScanExempt(fwdRespHost, cfg.ResponseScanning.ExemptDomains)
	if sc.ResponseScanningEnabled() && fwdRespExempt {
		p.logger.LogAnomaly(r.Method, targetURL, "response_scan", fmt.Sprintf("response scan skipped: host %q matched exempt_domains", fwdRespHost), clientIP, requestID, agent, 0)
	}
	if sc.ResponseScanningEnabled() && !fwdRespExempt {
		// Fail-closed on compressed responses: regex can't match compressed content.
		if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
			p.logger.LogBlocked(r.Method, targetURL, "response_scan", "compressed response cannot be scanned", clientIP, requestID, agent)
			p.metrics.RecordBlocked(r.URL.Hostname(), "response_scan", time.Since(start), agentLabel)
			http.Error(w, "blocked: compressed response cannot be scanned", http.StatusForbidden)
			return
		}

		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		if readErr != nil {
			p.logger.LogError(r.Method, targetURL, clientIP, requestID, agent, readErr)
			http.Error(w, "blocked: response read error", http.StatusForbidden)
			return
		}

		// A2A response body scanning: field-aware walk for Agent Card drift
		// detection and structured A2A message scanning. Runs before the
		// generic response injection scanner so A2A-specific findings
		// (card drift, field-level DLP) are reported with precise context.
		if isA2A && len(respBody) > 0 {
			var a2aResult mcp.A2AScanResult
			if mcp.IsAgentCardPath(r.URL.Path) {
				cardKey := mcp.CardCacheKeyFromRequest(targetURL, r.Header.Get("Authorization"))
				cardResult := mcp.ScanAgentCard(r.Context(), respBody, sc, p.a2aCardBaseline, cardKey, &cfg.A2AScanning)
				a2aResult = cardResult.Findings
				a2aResult.Clean = cardResult.Clean
				// Promote card-level findings to the result.
				if !cardResult.Clean {
					if a2aResult.Action == "" {
						a2aResult.Action = cardResult.Action
					}
					if a2aResult.Reason == "" {
						a2aResult.Reason = cardResult.Reason
					}
				}
			} else {
				a2aResult = mcp.ScanA2AResponseBody(r.Context(), respBody, sc, &cfg.A2AScanning)
			}
			if !a2aResult.Clean {
				hasFinding = true
				a2aAction := a2aResult.Action
				if a2aAction == "" {
					a2aAction = cfg.A2AScanning.Action
				}
				a2aReason := a2aResult.Reason
				if a2aReason == "" {
					a2aReason = "a2a: response finding"
				}
				p.logger.LogAnomaly(r.Method, targetURL, "a2a_response", a2aReason, clientIP, requestID, agent, 0)
				if a2aAction == config.ActionBlock {
					p.metrics.RecordBlocked(r.URL.Hostname(), "a2a_response", time.Since(start), agentLabel)
					http.Error(w, "blocked: "+a2aReason, http.StatusForbidden)
					return
				}
			}
		}

		scanResult := sc.ScanResponse(r.Context(), string(respBody))

		// Capture observer: record forward response scan verdict for policy replay.
		{
			fwdRespAction := sc.ResponseAction()
			if scanResult.Clean {
				fwdRespAction = ""
			}
			p.captureObs.ObserveResponseVerdict(r.Context(), &capture.ResponseVerdictRecord{
				Subsurface:        "response_forward",
				Transport:         "forward",
				RequestID:         requestID,
				Agent:             agent,
				Request:           capture.CaptureRequest{Method: r.Method, URL: targetURL},
				TransformKind:     capture.TransformRaw,
				RawFindings:       responseMatchesToFindings(scanResult.Matches, fwdRespAction),
				EffectiveFindings: responseMatchesToFindings(scanResult.Matches, fwdRespAction),
				EffectiveAction:   fwdRespAction,
				Outcome:           captureOutcome(fwdRespAction, scanResult.Clean),
			})
		}

		// Filter out suppressed findings (parity with fetch proxy).
		if !scanResult.Clean && len(cfg.Suppress) > 0 {
			var kept []scanner.ResponseMatch
			for _, m := range scanResult.Matches {
				if !config.IsSuppressed(m.PatternName, targetURL, cfg.Suppress) {
					kept = append(kept, m)
				}
			}
			scanResult.Matches = kept
			scanResult.Clean = len(kept) == 0
		}
		if !scanResult.Clean {
			hasFinding = true
			action := sc.ResponseAction()
			patternNames := make([]string, len(scanResult.Matches))
			for i, match := range scanResult.Matches {
				patternNames[i] = match.PatternName
			}
			bundleRules := responseBundleRules(scanResult.Matches)
			reason := fmt.Sprintf("response injection: %s", strings.Join(patternNames, ", "))

			// Adaptive enforcement: upgrade the response action before the switch.
			// Parity with fetch (filterAndActOnResponseScan) and WebSocket (upstreamToClient).
			originalAction := action
			if forwardRec != nil {
				action = decide.UpgradeAction(action, forwardRec.EscalationLevel(), &cfg.AdaptiveEnforcement)
				if action != originalAction {
					sessionKey := clientIP
					if agent != "" && agent != agentAnonymous {
						sessionKey = agent + "|" + clientIP
					}
					p.logger.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(forwardRec.EscalationLevel()), originalAction, action, "response_scan", clientIP, requestID)
					p.metrics.RecordAdaptiveUpgrade(originalAction, action, session.EscalationLabel(forwardRec.EscalationLevel()))
				}
			}

			switch action {
			case config.ActionBlock, config.ActionAsk:
				p.logger.LogBlocked(r.Method, targetURL, "response_scan", reason, clientIP, requestID, agent)
				p.metrics.RecordBlocked(r.URL.Hostname(), "response_scan", time.Since(start), agentLabel)
				http.Error(w, "blocked: response contains injection", http.StatusForbidden)
				return
			case config.ActionStrip:
				// Record SignalStrip for adaptive enforcement scoring.
				// Parity with fetch (filterAndActOnResponseScan) and WebSocket (upstreamToClient).
				if sm := p.sessionMgrPtr.Load(); sm != nil && cfg.AdaptiveEnforcement.Enabled {
					sessionKey := clientIP
					if agent != "" && agent != agentAnonymous {
						sessionKey = agent + "|" + clientIP
					}
					sess := sm.GetOrCreate(sessionKey)
					decide.RecordEscalation(sess, session.SignalStrip, decide.EscalationParams{
						Threshold: cfg.AdaptiveEnforcement.EscalationThreshold,
						Logger:    p.logger,
						Metrics:   p.metrics,
						Session:   sessionKey,
						ClientIP:  clientIP,
						RequestID: requestID,
					})
				}
				if scanResult.TransformedContent != "" {
					respBody = []byte(scanResult.TransformedContent)
					// Remove body-derived validators that no longer match the stripped content.
					resp.Header.Del("Etag")
					resp.Header.Del("Content-Md5")
					resp.Header.Del("Digest")
				} else {
					p.logger.LogBlocked(r.Method, targetURL, "response_scan", reason+" (strip failed)", clientIP, requestID, agent)
					p.metrics.RecordBlocked(r.URL.Hostname(), "response_scan", time.Since(start), agentLabel)
					http.Error(w, "blocked: response contains injection", http.StatusForbidden)
					return
				}
				p.logger.LogResponseScan(targetURL, clientIP, requestID, agent, config.ActionStrip, len(scanResult.Matches), patternNames, bundleRules)
			default:
				p.logger.LogResponseScan(targetURL, clientIP, requestID, agent, action, len(scanResult.Matches), patternNames, bundleRules)
			}
		}

		// Scan passed — now copy upstream headers and write response.
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		n, _ := w.Write(respBody)
		written := int64(n)

		sc.RecordRequest(strings.ToLower(r.URL.Hostname()), int(written))
		_ = resolved.Budget.RecordBytes(written)

		if budgetRemaining >= 0 && written >= budgetRemaining {
			reason := fmt.Sprintf("response truncated at byte budget: %d bytes written", written)
			p.logger.LogAnomaly(r.Method, targetURL, "budget_truncated", reason, clientIP, requestID, agent, 0)
			return
		}

		duration := time.Since(start)
		p.metrics.RecordAllowed(duration, agentLabel)
		p.logger.LogForwardHTTP(r.Method, targetURL, clientIP, requestID, agent, resp.StatusCode, int(written), duration)
		if forwardRec != nil && cfg.AdaptiveEnforcement.Enabled && !hasFinding {
			forwardRec.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
		}
		return
	}

	// No response scanning: copy headers and stream directly for lower latency.
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	written, _ := io.Copy(w, io.LimitReader(resp.Body, maxBytes))

	// Record data budget for the target domain
	sc.RecordRequest(strings.ToLower(r.URL.Hostname()), int(written))

	// Record bytes for per-agent budget tracking.
	_ = resolved.Budget.RecordBytes(written)

	// Detect truncated response due to budget exhaustion.
	if budgetRemaining >= 0 && written >= budgetRemaining {
		reason := fmt.Sprintf("response truncated at byte budget: %d bytes written", written)
		p.logger.LogAnomaly(r.Method, targetURL, "budget_truncated", reason, clientIP, requestID, agent, 0)
		return
	}

	duration := time.Since(start)
	p.metrics.RecordAllowed(duration, agentLabel)
	p.logger.LogForwardHTTP(r.Method, targetURL, clientIP, requestID, agent, resp.StatusCode, int(written), duration)
	if forwardRec != nil && cfg.AdaptiveEnforcement.Enabled && !hasFinding {
		forwardRec.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
	}
}

// copyResponseHeaders copies upstream response headers to the client response,
// stripping hop-by-hop headers and Content-Length (which may be stale after
// body truncation or stripping).
func copyResponseHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	removeHopByHopHeaders(dst)
	dst.Del("Content-Length")
}

// dlpMatchNames extracts pattern names from a slice of DLP matches.
func dlpMatchNames(matches []scanner.TextDLPMatch) []string {
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.PatternName
	}
	return names
}

// dlpBundleRules extracts bundle provenance from DLP matches.
// Returns nil when no matches originate from a community bundle,
// so the audit logger omits the field for built-in patterns.
func dlpBundleRules(matches []scanner.TextDLPMatch) []audit.BundleRuleHit {
	var hits []audit.BundleRuleHit
	for _, m := range matches {
		if m.Bundle != "" {
			hits = append(hits, audit.BundleRuleHit{
				RuleID:        m.PatternName,
				Bundle:        m.Bundle,
				BundleVersion: m.BundleVersion,
			})
		}
	}
	return hits
}

// responseBundleRules extracts bundle provenance from response scan matches.
// Returns nil when no matches originate from a community bundle.
func responseBundleRules(matches []scanner.ResponseMatch) []audit.BundleRuleHit {
	var hits []audit.BundleRuleHit
	for _, m := range matches {
		if m.Bundle != "" {
			hits = append(hits, audit.BundleRuleHit{
				RuleID:        m.PatternName,
				Bundle:        m.Bundle,
				BundleVersion: m.BundleVersion,
			})
		}
	}
	return hits
}

// removeHopByHopHeaders strips RFC 7230 section 6.1 hop-by-hop headers
// from an http.Header. Per the RFC, the Connection header value lists
// additional header names that are hop-by-hop for this connection and
// must also be removed before forwarding.
func removeHopByHopHeaders(h http.Header) {
	// First, parse Connection header for additional hop-by-hop names.
	// e.g., "Connection: X-Foo, close" means X-Foo is also hop-by-hop.
	if connValues := h.Values("Connection"); len(connValues) > 0 {
		for _, v := range connValues {
			for _, name := range strings.Split(v, ",") {
				name = strings.TrimSpace(name)
				if name != "" {
					h.Del(name)
				}
			}
		}
	}

	// Then remove the standard hop-by-hop headers.
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}
