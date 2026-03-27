// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
	plwsutil "github.com/luckyPipewrench/pipelock/internal/wsutil"
)

// wsSemaphore limits concurrent WebSocket proxy connections.
// Capacity is fixed on first use (sync.Once). Config reload changes to
// max_concurrent_connections require a restart to take effect.
var (
	wsSem     *tunnelSemaphore
	wsSemOnce sync.Once
)

func getWSSemaphore(capacity int) *tunnelSemaphore {
	wsSemOnce.Do(func() {
		wsSem = newTunnelSemaphore(capacity)
	})
	return wsSem
}

// wsRelay holds per-connection state for a proxied WebSocket connection.
type wsRelay struct {
	clientConn   net.Conn
	upstreamConn net.Conn
	scanner      *scanner.Scanner
	proxy        *Proxy
	cfg          *config.Config
	agent        string
	clientIP     string
	requestID    string
	targetURL    string
	hostname     string
	maxMsg       int
	scanText     bool
	allowBinary  bool
	rec          session.Recorder // live escalation level for UpgradeAction; nil when profiling disabled
}

// escalationLevel returns the live escalation level from the session recorder.
// Returns 0 (normal) when the recorder is nil (profiling disabled).
func (r *wsRelay) escalationLevel() int {
	if r.rec != nil {
		return r.rec.EscalationLevel()
	}
	return 0
}

// recordSignal records an adaptive enforcement signal on the relay's session
// recorder. No-op when the recorder is nil or adaptive enforcement is disabled.
func (r *wsRelay) recordSignal(sig session.SignalType, log *audit.Logger) {
	if r.rec == nil || !r.cfg.AdaptiveEnforcement.Enabled {
		return
	}
	sessionKey := r.clientIP
	if r.agent != "" && r.agent != agentAnonymous {
		sessionKey = r.agent + "|" + r.clientIP
	}
	decide.RecordEscalation(r.rec, sig, decide.EscalationParams{
		Threshold: r.cfg.AdaptiveEnforcement.EscalationThreshold,
		Logger:    log,
		Metrics:   r.proxy.metrics,
		Session:   sessionKey,
		ClientIP:  r.clientIP,
		RequestID: r.requestID,
	})
}

// wsRelayStats collects per-connection counters for audit logging.
type wsRelayStats struct {
	clientToServer int64
	serverToClient int64
	textFrames     int64
	binaryFrames   int64
	blocked        bool // true if relay terminated due to a policy/DLP/injection block
}

// handleWebSocket handles /ws WebSocket proxy requests.
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
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

	if !cfg.WebSocketProxy.Enabled {
		http.Error(w, "WebSocket proxy not enabled", http.StatusNotFound)
		return
	}

	log := p.logger.With("agent", agent)

	// Extract and validate target URL. Uses the same extraction logic as /fetch
	// to handle unencoded '&' in target URLs without silent truncation.
	targetURL := extractTargetURL(r)
	if targetURL == "" {
		http.Error(w, "missing 'url' query parameter", http.StatusBadRequest)
		return
	}

	targetURL = stripFetchControlChars(targetURL)

	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") {
		http.Error(w, "invalid URL: must be ws or wss", http.StatusBadRequest)
		return
	}

	// Map ws->http, wss->https for the scanner pipeline (scanner expects HTTP schemes).
	scanScheme := schemeHTTP
	if parsed.Scheme == "wss" {
		scanScheme = schemeHTTPS
	}
	scanURL := scanScheme + "://" + parsed.Host + parsed.RequestURI()

	// Run through all 9 scanner layers.
	result := sc.Scan(r.Context(), scanURL)

	// Session profiling: record BEFORE the enforce-mode early return so adaptive
	// signals (SignalBlock) fire even for blocked requests. Pass deferClean=true
	// so header DLP findings on the same handshake don't get offset by early decay.
	sr := p.recordSessionActivity(clientIP, agent, parsed.Hostname(), requestID, result, cfg, log, true)
	wsHasFinding := !result.Allowed && !result.IsProtective()

	if !result.Allowed {
		status := http.StatusForbidden
		if result.Scanner == scanner.ScannerRateLimit {
			status = http.StatusTooManyRequests
		}
		if cfg.EnforceEnabled() {
			log.LogBlocked("WS", targetURL, result.Scanner, result.Reason, clientIP, requestID, agent)
			p.metrics.RecordWSBlocked()
			if cfg.ExplainBlocksEnabled() && result.Hint != "" {
				w.Header().Set("X-Pipelock-Hint", result.Hint)
			}
			http.Error(w, "WebSocket blocked: "+result.Reason, status)
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
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), baseAction, effectiveAction, result.Scanner, clientIP, requestID)
			p.metrics.RecordAdaptiveUpgrade(baseAction, effectiveAction, session.EscalationLabel(sr.Level))
			log.LogBlocked("WS", targetURL, result.Scanner, result.Reason+" (escalated)", clientIP, requestID, agent)
			p.metrics.RecordWSBlocked()
			http.Error(w, "WebSocket blocked: "+result.Reason+" (escalated)", status)
			return
		}
		log.LogAnomaly("WS", targetURL, result.Scanner,
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
		log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), "", config.ActionBlock, "session_deny", clientIP, requestID)
		p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(sr.Level))
		p.metrics.RecordWSBlocked()
		http.Error(w, "WebSocket blocked: session escalation level "+session.EscalationLabel(sr.Level), http.StatusForbidden)
		return
	}

	// Budget admission check: enforce request count and domain limits.
	if err := resolved.Budget.CheckAdmission(strings.ToLower(parsed.Hostname())); err != nil {
		reason := err.Error()
		log.LogBlocked("WS", targetURL, "budget", reason, clientIP, requestID, agent)
		p.metrics.RecordWSBlocked()
		http.Error(w, "WebSocket blocked: "+reason, http.StatusTooManyRequests)
		return
	}

	// Check connection semaphore.
	sem := getWSSemaphore(cfg.WebSocketProxy.MaxConcurrentConnections)
	if !sem.TryAcquire() {
		http.Error(w, "too many active WebSocket connections", http.StatusServiceUnavailable)
		return
	}
	defer sem.Release()

	// Build headers for upstream handshake.
	fwdHeaders := p.buildWSForwardHeaders(r, parsed, cfg, sc)

	// DLP-scan forwarded header values regardless of destination or enforce mode.
	// In audit mode, findings are logged as anomalies but traffic is allowed.
	if blocked, reason := p.dlpScanWSHeaders(r.Context(), fwdHeaders, sc); blocked {
		wsHasFinding = true
		// Record session activity so adaptive enforcement sees header-DLP hits.
		headerSR := p.recordSessionActivity(clientIP, agent, parsed.Hostname(), requestID, scanner.Result{Allowed: false, Score: 0.9}, cfg, log, false)
		if cfg.EnforceEnabled() {
			log.LogWSBlocked(targetURL, audit.DirectionClientToServer, audit.ScannerDLP, reason, clientIP, requestID)
			p.metrics.RecordWSBlocked()
			http.Error(w, "WebSocket blocked: "+reason, http.StatusForbidden)
			return
		}
		log.LogAnomaly("WS", targetURL, audit.ScannerDLP, reason, clientIP, requestID, agent, 0)
		// Re-check block_all after header DLP may have escalated the session.
		if cfg.AdaptiveEnforcement.Enabled && headerSR.Level > 0 &&
			decide.UpgradeAction("", headerSR.Level, &cfg.AdaptiveEnforcement) == config.ActionBlock {
			sessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				sessionKey = agent + "|" + clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(headerSR.Level), "", config.ActionBlock, "session_deny", clientIP, requestID)
			p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(headerSR.Level))
			p.metrics.RecordWSBlocked()
			http.Error(w, "WebSocket blocked: session escalation level "+session.EscalationLabel(headerSR.Level), http.StatusForbidden)
			return
		}
	}

	// Upgrade the client connection.
	upgrader := ws.HTTPUpgrader{
		Timeout: 10 * time.Second,
	}
	clientConn, _, _, upgradeErr := upgrader.Upgrade(r, w)
	if upgradeErr != nil {
		log.LogError("WS", targetURL, clientIP, requestID, agent, fmt.Errorf("client upgrade: %w", upgradeErr))
		// If Upgrade fails, it already wrote the HTTP error response.
		return
	}
	defer clientConn.Close() //nolint:errcheck // best effort

	// Dial upstream via SSRF-safe dialer.
	upstreamConn, dialErr := p.wsDialUpstream(r.Context(), targetURL, fwdHeaders, cfg)
	if dialErr != nil {
		log.LogError("WS", targetURL, clientIP, requestID, agent, fmt.Errorf("upstream dial: %w", dialErr))
		plwsutil.WriteCloseFrame(clientConn, ws.StatusInternalServerError, "upstream dial failed")
		return
	}
	defer upstreamConn.Close() //nolint:errcheck // best effort

	p.metrics.IncrActiveWS()
	log.LogWSOpen(targetURL, clientIP, requestID, agent)

	scanTextFrames := cfg.WebSocketProxy.ScanTextFrames == nil || *cfg.WebSocketProxy.ScanTextFrames

	// Obtain a live session recorder for the relay. This provides live
	// escalation level lookups instead of a stale snapshot, so that
	// escalation changes during long-lived WS connections take effect.
	var wsRec session.Recorder
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		sessionKey := clientIP
		if agent != "" && agent != agentAnonymous {
			sessionKey = agent + "|" + clientIP
		}
		wsRec = sm.GetOrCreate(sessionKey)
	}

	// Deferred clean decay: only apply if the entire handshake was clean
	// (no URL scan hit, no header DLP hit). This prevents same-handshake
	// raise+decay when a header carries a secret but the URL is clean.
	if wsRec != nil && cfg.AdaptiveEnforcement.Enabled && !wsHasFinding {
		wsRec.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
	}

	relay := &wsRelay{
		clientConn:   clientConn,
		upstreamConn: upstreamConn,
		scanner:      sc,
		proxy:        p,
		cfg:          cfg,
		agent:        agent,
		clientIP:     clientIP,
		requestID:    requestID,
		targetURL:    targetURL,
		hostname:     strings.ToLower(parsed.Hostname()),
		maxMsg:       cfg.WebSocketProxy.MaxMessageBytes,
		scanText:     scanTextFrames,
		allowBinary:  cfg.WebSocketProxy.AllowBinaryFrames,
		rec:          wsRec,
	}

	if isResponseScanExempt(relay.hostname, cfg.ResponseScanning.ExemptDomains) {
		log.LogAnomaly("WS", targetURL, "response_scan", fmt.Sprintf("response scan skipped: host %q matched exempt_domains", relay.hostname), clientIP, requestID, agent, 0)
	}

	stats := relay.run(r.Context())

	p.metrics.DecrActiveWS()
	duration := time.Since(start)
	if stats.blocked {
		p.metrics.RecordWSBlocked()
	} else {
		p.metrics.RecordWSCompleted()
	}
	p.metrics.RecordWSStats(duration, stats.clientToServer, stats.serverToClient)
	log.LogWSClose(targetURL, clientIP, requestID, agent,
		stats.clientToServer, stats.serverToClient,
		stats.textFrames, stats.binaryFrames, duration)

	sc.RecordRequest(relay.hostname, int(stats.clientToServer+stats.serverToClient))

	// Record WebSocket bytes for per-agent budget tracking. WebSocket
	// connections are streaming: bytes are tracked after close and enforced
	// on the next admission check, not mid-stream.
	_ = resolved.Budget.RecordBytes(stats.clientToServer + stats.serverToClient)
}

// buildWSForwardHeaders builds the HTTP headers to forward during upstream WS handshake.
// Follows the allowlist approach: forward known-safe headers, strip everything else.
func (p *Proxy) buildWSForwardHeaders(r *http.Request, parsed *url.URL, cfg *config.Config, _ *scanner.Scanner) http.Header {
	fwd := make(http.Header)

	// Authorization (required by most authenticated WS APIs).
	if v := r.Header.Get("Authorization"); v != "" {
		fwd.Set("Authorization", v)
	}

	// Provider-specific auth headers.
	for _, key := range []string{"X-Api-Key", "X-Goog-Api-Key"} {
		if v := r.Header.Get(key); v != "" {
			fwd.Set(key, v)
		}
	}

	// Subprotocol negotiation.
	if v := r.Header.Get("Sec-WebSocket-Protocol"); v != "" {
		fwd.Set("Sec-WebSocket-Protocol", v)
	}

	// Origin policy.
	switch cfg.WebSocketProxy.OriginPolicy {
	case config.OriginPolicyForward:
		if v := r.Header.Get("Origin"); v != "" {
			fwd.Set("Origin", v)
		}
	case "strip":
		// Do not forward Origin.
	default: // "rewrite"
		scheme := schemeHTTPS
		if parsed.Scheme == "ws" {
			scheme = schemeHTTP
		}
		fwd.Set("Origin", scheme+"://"+parsed.Host)
	}

	// Cookies (opt-in only).
	if cfg.WebSocketProxy.ForwardCookies {
		if v := r.Header.Get("Cookie"); v != "" {
			fwd.Set("Cookie", v)
		}
	}

	// User-Agent with pipelock suffix.
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = cfg.FetchProxy.UserAgent
	}
	fwd.Set("User-Agent", ua+" pipelock/"+Version)

	return fwd
}

// dlpScanWSHeaders runs DLP scanning on all forwarded header values before the
// upstream handshake. Headers are scanned regardless of destination (no
// allowlist skip) because agents can exfiltrate secrets in any header value.
func (p *Proxy) dlpScanWSHeaders(ctx context.Context, headers http.Header, sc *scanner.Scanner) (blocked bool, reason string) {
	// Scan all headers that buildWSForwardHeaders may forward. This covers
	// auth headers, cookies, origin, subprotocol, and user-agent. An agent
	// can exfiltrate data in any of these values.
	for _, key := range []string{
		"Authorization", "X-Api-Key", "X-Goog-Api-Key", "Cookie",
		"Origin", "Sec-WebSocket-Protocol", "User-Agent",
	} {
		val := headers.Get(key)
		if val == "" {
			continue
		}
		result := sc.ScanTextForDLP(ctx, val)
		if !result.Clean {
			names := make([]string, len(result.Matches))
			for i, m := range result.Matches {
				names[i] = m.PatternName
			}
			return true, fmt.Sprintf("DLP match in %s header: %s", key, strings.Join(names, ", "))
		}
	}
	return false, ""
}

// isHostAllowlisted checks if a hostname matches any pattern in the allowlist.
// Supports leading wildcard patterns (e.g., "*.openai.com").
func isHostAllowlisted(hostname string, allowlist []string) bool {
	hostname = strings.ToLower(hostname)
	for _, pattern := range allowlist {
		pattern = strings.ToLower(pattern)
		if pattern == hostname {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".openai.com"
			if strings.HasSuffix(hostname, suffix) {
				return true
			}
		}
	}
	return false
}

// wsDialUpstream dials the upstream WebSocket server using the SSRF-safe dialer.
func (p *Proxy) wsDialUpstream(ctx context.Context, targetURL string, fwdHeaders http.Header, cfg *config.Config) (net.Conn, error) {
	timeout := time.Duration(cfg.WebSocketProxy.MaxConnectionSeconds) * time.Second
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := ws.Dialer{
		NetDial:    p.ssrfSafeDialContext,
		Header:     ws.HandshakeHeaderHTTP(fwdHeaders),
		Timeout:    30 * time.Second,
		Extensions: nil, // disable permessage-deflate; relay does not handle compressed frames
	}

	conn, _, _, err := dialer.Dial(dialCtx, targetURL)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// run starts bidirectional frame relay. Returns stats when both directions complete.
func (r *wsRelay) run(ctx context.Context) wsRelayStats {
	maxDuration := time.Duration(r.cfg.WebSocketProxy.MaxConnectionSeconds) * time.Second
	idleTimeout := time.Duration(r.cfg.WebSocketProxy.IdleTimeoutSeconds) * time.Second

	ctx, cancel := context.WithTimeout(ctx, maxDuration)
	defer cancel()

	// Use separate per-direction counters to avoid data races. The goroutine
	// writes c2s*, the main goroutine writes s2c*, and we sum after wg.Wait().
	var c2sBytes, c2sText, c2sBinary int64
	var c2sBlocked bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		c2sBytes, c2sText, c2sBinary, c2sBlocked = r.clientToUpstream(ctx, cancel, idleTimeout)
	}()

	s2cBytes, s2cText, s2cBinary, s2cBlocked := r.upstreamToClient(ctx, cancel, idleTimeout)

	wg.Wait()
	return wsRelayStats{
		clientToServer: c2sBytes,
		serverToClient: s2cBytes,
		textFrames:     c2sText + s2cText,
		binaryFrames:   c2sBinary + s2cBinary,
		blocked:        c2sBlocked || s2cBlocked,
	}
}

// clientToUpstream reads frames from client, DLP-scans text, writes to upstream.
func (r *wsRelay) clientToUpstream(ctx context.Context, cancel context.CancelFunc, idleTimeout time.Duration) (bytesTransferred, textFrames, binaryFrames int64, blocked bool) {
	defer cancel()
	frag := &plwsutil.FragmentState{MaxBytes: r.maxMsg}
	var crossMsgTail []byte // rolling tail for cross-message DLP scanning
	log := r.proxy.logger.With("agent", r.agent)

	for {
		select {
		case <-ctx.Done():
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusGoingAway, "connection timeout")
			return
		default:
		}

		// Kill switch: terminate WebSocket relay when activated mid-stream.
		if r.proxy.ks != nil && r.proxy.ks.IsActive() {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "kill switch active")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "kill switch active")
			blocked = true
			return
		}

		// block_all check: if the session has escalated to a level with
		// block_all=true, close the WebSocket immediately. This prevents
		// clean frames from flowing after escalation during long-lived connections.
		if decide.UpgradeAction("", r.escalationLevel(), &r.cfg.AdaptiveEnforcement) == config.ActionBlock {
			sessionKey := r.clientIP
			if r.agent != "" && r.agent != agentAnonymous {
				sessionKey = r.agent + "|" + r.clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), "", config.ActionBlock, "session_deny", r.clientIP, r.requestID)
			r.proxy.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(r.escalationLevel()))
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "session escalation")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "session escalation")
			blocked = true
			return
		}

		_ = r.clientConn.SetReadDeadline(time.Now().Add(idleTimeout))

		hdr, err := ws.ReadHeader(r.clientConn)
		if err != nil {
			if !plwsutil.IsExpectedCloseErr(err) {
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusGoingAway, "client disconnected")
			}
			return
		}

		// Guard against OOM: reject frames exceeding limits before allocating.
		if hdr.OpCode.IsControl() && hdr.Length > plwsutil.MaxControlPayload {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusProtocolError, "control frame too large")
			return
		}
		if !hdr.OpCode.IsControl() && hdr.Length > int64(r.maxMsg) {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			return
		}

		// Reject compressed frames (RSV1 = permessage-deflate indicator).
		// Compressed bytes bypass DLP pattern matching entirely.
		if hdr.Rsv1() {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusProtocolError, "compressed frames not supported")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusProtocolError, "compressed frames not supported")
			blocked = true
			return
		}

		// Read payload. Hard guard mirrors the size checks above; if this fires
		// it means a code change broke the earlier validation.
		if hdr.Length < 0 || hdr.Length > int64(r.maxMsg) {
			return
		}
		payload := make([]byte, hdr.Length)
		if hdr.Length > 0 {
			if _, err := io.ReadFull(r.clientConn, payload); err != nil {
				return
			}
		}

		// Unmask client frames (clients must mask per RFC 6455).
		if hdr.Masked {
			ws.Cipher(payload, hdr.Mask, 0)
		}

		r.proxy.metrics.RecordWSFrame(opCodeLabel(hdr.OpCode))

		// Control frames: forward as-is.
		if hdr.OpCode.IsControl() {
			if hdr.OpCode == ws.OpClose {
				// Forward close frame to upstream, then exit.
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusNormalClosure, "client closed")
				return
			}
			// Ping/Pong: forward to upstream (proxy is CLIENT to upstream).
			err = wsutil.WriteClientMessage(r.upstreamConn, hdr.OpCode, payload)
			if err != nil {
				return
			}
			continue
		}

		// Binary frames.
		if hdr.OpCode == ws.OpBinary || (hdr.OpCode == ws.OpContinuation && frag.Active && frag.Opcode == ws.OpBinary) {
			binaryFrames++
			if !r.allowBinary {
				log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, "ws_protocol", "binary frames not allowed", r.clientIP, r.requestID)
				r.proxy.metrics.RecordWSScanHit("ws_protocol")
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "binary frames not allowed")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "binary frames not allowed")
				blocked = true
				return
			}
		}

		// Fragment reassembly for text frames.
		complete, msg, closeCode, closeReason := frag.Process(hdr, payload)
		if closeCode != 0 {
			log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, "ws_protocol", closeReason, r.clientIP, r.requestID)
			plwsutil.WriteCloseFrame(r.clientConn, closeCode, closeReason)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, closeCode, closeReason)
			blocked = true
			return
		}

		if !complete {
			// Fragment accumulated, not yet complete. Buffer until the full
			// message is available for scanning before forwarding.
			continue
		}

		// Complete message available. Count and scan.
		if frag.Opcode == ws.OpText || hdr.OpCode == ws.OpText {
			textFrames++

			// UTF-8 validation per RFC 6455.
			if !utf8.Valid(msg) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				return
			}

			// DLP scanning on reassembled text.
			// Cross-message DLP: prepend tail of previous message to catch
			// secrets split across separate WebSocket message boundaries.
			if r.scanText {
				var scanInput []byte
				if len(crossMsgTail) > 0 {
					scanInput = append(crossMsgTail, msg...)
				} else {
					scanInput = msg
				}
				dlpResult := r.scanner.ScanTextForDLP(ctx, string(scanInput))

				// Update rolling tail for next message (always, regardless of result).
				if len(msg) >= crossMsgOverlap {
					crossMsgTail = make([]byte, crossMsgOverlap)
					copy(crossMsgTail, msg[len(msg)-crossMsgOverlap:])
				} else {
					crossMsgTail = append(crossMsgTail, msg...)
					if len(crossMsgTail) > crossMsgOverlap {
						crossMsgTail = crossMsgTail[len(crossMsgTail)-crossMsgOverlap:]
					}
				}

				if !dlpResult.Clean {
					names := make([]string, len(dlpResult.Matches))
					for i, m := range dlpResult.Matches {
						names[i] = m.PatternName
					}
					wsBundleRules := dlpBundleRules(dlpResult.Matches)
					if r.cfg.EnforceEnabled() {
						r.recordSignal(session.SignalBlock, log)
						reason := fmt.Sprintf("DLP match: %s", strings.Join(names, ", "))
						log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, audit.ScannerDLP, reason, r.clientIP, r.requestID)
						r.proxy.metrics.RecordWSScanHit(audit.ScannerDLP)
						plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "DLP violation")
						plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "DLP violation")
						blocked = true
						return
					}
					// Audit mode: adaptive escalation may upgrade warn to block.
					baseAction := config.ActionWarn
					effectiveAction := decide.UpgradeAction(baseAction, r.escalationLevel(), &r.cfg.AdaptiveEnforcement)
					if effectiveAction == config.ActionBlock {
						r.recordSignal(session.SignalBlock, log)
						sessionKey := r.clientIP
						if r.agent != "" && r.agent != agentAnonymous {
							sessionKey = r.agent + "|" + r.clientIP
						}
						log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), baseAction, effectiveAction, audit.ScannerDLP, r.clientIP, r.requestID)
						r.proxy.metrics.RecordAdaptiveUpgrade(baseAction, effectiveAction, session.EscalationLabel(r.escalationLevel()))
						reason := fmt.Sprintf("DLP match: %s (escalated)", strings.Join(names, ", "))
						log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, audit.ScannerDLP, reason, r.clientIP, r.requestID)
						r.proxy.metrics.RecordWSScanHit(audit.ScannerDLP)
						plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "DLP violation")
						plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "DLP violation")
						blocked = true
						return
					}
					// Warn/audit: near-miss signal so adaptive scoring sees the finding.
					r.recordSignal(session.SignalNearMiss, log)
					log.LogWSScan(r.targetURL, audit.DirectionClientToServer, r.clientIP, r.requestID, "audit", len(dlpResult.Matches), names, wsBundleRules)
				}

				// Address poisoning detection alongside DLP.
				if checker := r.scanner.AddressChecker(); checker != nil {
					addrResult := checker.CheckText(string(scanInput), r.agent)
					if len(addrResult.Findings) > 0 {
						addrAction := addressprotect.StrictestAction(addrResult.Findings)
						names := make([]string, len(addrResult.Findings))
						for i, f := range addrResult.Findings {
							names[i] = f.Explanation
						}
						// Record metrics for every finding, not just the first.
						for _, f := range addrResult.Findings {
							verdictLabel := "unknown"
							if f.Verdict == addressprotect.VerdictLookalike {
								verdictLabel = "lookalike"
							}
							r.proxy.metrics.RecordAddressFinding(f.Chain, verdictLabel)
						}
						// Adaptive enforcement: upgrade the address action.
						originalAddrAction := addrAction
						addrAction = decide.UpgradeAction(addrAction, r.escalationLevel(), &r.cfg.AdaptiveEnforcement)
						if addrAction != originalAddrAction {
							sessionKey := r.clientIP
							if r.agent != "" && r.agent != agentAnonymous {
								sessionKey = r.agent + "|" + r.clientIP
							}
							log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), originalAddrAction, addrAction, scannerLabelAddressProtection, r.clientIP, r.requestID)
							r.proxy.metrics.RecordAdaptiveUpgrade(originalAddrAction, addrAction, session.EscalationLabel(r.escalationLevel()))
						}
						if r.cfg.EnforceEnabled() && addrAction == config.ActionBlock {
							r.recordSignal(session.SignalBlock, log)
							// Use the blocking finding for the reason, not necessarily Findings[0].
							var blockExplanation string
							for _, f := range addrResult.Findings {
								if f.Action == config.ActionBlock {
									blockExplanation = f.Explanation
									break
								}
							}
							reason := fmt.Sprintf("address poisoning: %s", blockExplanation)
							log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, scannerLabelAddressProtection, reason, r.clientIP, r.requestID)
							plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "address poisoning detected")
							plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "address poisoning detected")
							blocked = true
							return
						}
						// Escalation can upgrade to block even in audit mode, but only
						// when UpgradeAction actually changed the action. If addrAction
						// was already block from config (not from escalation), audit
						// mode allows it through and logs it below.
						if !r.cfg.EnforceEnabled() && addrAction == config.ActionBlock && addrAction != originalAddrAction {
							r.recordSignal(session.SignalBlock, log)
							reason := fmt.Sprintf("address poisoning: %s (escalated)", names[0])
							log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, scannerLabelAddressProtection, reason, r.clientIP, r.requestID)
							plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "address poisoning detected")
							plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "address poisoning detected")
							blocked = true
							return
						}
						// Warn/audit mode: near-miss signal for address findings.
						r.recordSignal(session.SignalNearMiss, log)
						log.LogWSScan(r.targetURL, audit.DirectionClientToServer, r.clientIP, r.requestID, scannerLabelAddressProtection, len(addrResult.Findings), names, nil)
					}
				}
			}
		}

		// CEE: record outbound frame for cross-request exfiltration detection.
		// Entropy tracking applies to all frame types (text + binary) since
		// binary frames can carry high-entropy exfiltrated data. Fragment
		// buffering only applies to text frames (DLP patterns match text).
		if ceeCfg := ceeEffectiveConfig(r.cfg.CrossRequestDetection, r.cfg.EnforceEnabled()); ceeCfg.Enabled {
			isText := frag.Opcode == ws.OpText || hdr.OpCode == ws.OpText
			sessionKey := ceeSessionKey(r.agent, r.clientIP)

			// Pass fragment buffer only for text frames; binary content
			// doesn't match DLP text patterns.
			var fb *scanner.FragmentBuffer
			if isText {
				fb = r.proxy.fragmentBufferPtr.Load()
			}

			ceeRes := ceeAdmit(ctx, sessionKey, msg, nil, r.targetURL, r.agent, r.clientIP, r.requestID,
				ceeCfg, r.proxy.entropyTrackerPtr.Load(), fb, r.scanner, r.proxy.logger, r.proxy.metrics)

			if sm := r.proxy.sessionMgrPtr.Load(); sm != nil && r.cfg.AdaptiveEnforcement.Enabled {
				ceeRecordSignals(ceeRes, sm, sessionKey, r.cfg.AdaptiveEnforcement.EscalationThreshold, r.proxy.logger, r.proxy.metrics, r.clientIP, r.requestID)
			}

			if ceeRes.Blocked {
				log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, "cross_request", ceeRes.Reason, r.clientIP, r.requestID)
				r.proxy.metrics.RecordWSScanHit("cross_request")
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "cross-request exfiltration detected")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "cross-request exfiltration detected")
				blocked = true
				return
			}
		}

		// Forward complete message to upstream (proxy is CLIENT, so masked).
		opCode := hdr.OpCode
		if frag.Opcode != 0 {
			opCode = frag.Opcode
		}
		err = wsutil.WriteClientMessage(r.upstreamConn, opCode, msg)
		if err != nil {
			return
		}
		bytesTransferred += int64(len(msg))
		frag.Reset()
	}
}

// upstreamToClient reads frames from upstream, injection-scans text, writes to client.
func (r *wsRelay) upstreamToClient(ctx context.Context, cancel context.CancelFunc, idleTimeout time.Duration) (bytesTransferred, textFrames, binaryFrames int64, blocked bool) {
	defer cancel()
	frag := &plwsutil.FragmentState{MaxBytes: r.maxMsg}
	log := r.proxy.logger.With("agent", r.agent)

	for {
		select {
		case <-ctx.Done():
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusGoingAway, "connection timeout")
			return
		default:
		}

		// Kill switch: terminate WebSocket relay when activated mid-stream.
		if r.proxy.ks != nil && r.proxy.ks.IsActive() {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "kill switch active")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "kill switch active")
			blocked = true
			return
		}

		// block_all check: if the session has escalated to a level with
		// block_all=true, close the WebSocket immediately.
		if decide.UpgradeAction("", r.escalationLevel(), &r.cfg.AdaptiveEnforcement) == config.ActionBlock {
			sessionKey := r.clientIP
			if r.agent != "" && r.agent != agentAnonymous {
				sessionKey = r.agent + "|" + r.clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), "", config.ActionBlock, "session_deny", r.clientIP, r.requestID)
			r.proxy.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(r.escalationLevel()))
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "session escalation")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "session escalation")
			blocked = true
			return
		}

		_ = r.upstreamConn.SetReadDeadline(time.Now().Add(idleTimeout))

		hdr, err := ws.ReadHeader(r.upstreamConn)
		if err != nil {
			if !plwsutil.IsExpectedCloseErr(err) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusGoingAway, "upstream disconnected")
			}
			return
		}

		// Guard against OOM: reject frames exceeding limits before allocating.
		if hdr.OpCode.IsControl() && hdr.Length > plwsutil.MaxControlPayload {
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusProtocolError, "control frame too large")
			return
		}
		if !hdr.OpCode.IsControl() && hdr.Length > int64(r.maxMsg) {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			return
		}

		// Reject compressed frames (RSV1 = permessage-deflate indicator).
		// Compressed bytes bypass DLP pattern matching entirely.
		if hdr.Rsv1() {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusProtocolError, "compressed frames not supported")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusProtocolError, "compressed frames not supported")
			blocked = true
			return
		}

		// Read payload. Hard guard mirrors the size checks above; if this fires
		// it means a code change broke the earlier validation.
		if hdr.Length < 0 || hdr.Length > int64(r.maxMsg) {
			return
		}
		payload := make([]byte, hdr.Length)
		if hdr.Length > 0 {
			if _, err := io.ReadFull(r.upstreamConn, payload); err != nil {
				return
			}
		}

		// Server frames should not be masked, but unmask if they are.
		if hdr.Masked {
			ws.Cipher(payload, hdr.Mask, 0)
		}

		r.proxy.metrics.RecordWSFrame(opCodeLabel(hdr.OpCode))

		// Control frames.
		if hdr.OpCode.IsControl() {
			if hdr.OpCode == ws.OpClose {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusNormalClosure, "upstream closed")
				return
			}
			// Forward Ping/Pong to client (proxy is SERVER to client, no masking).
			err = wsutil.WriteServerMessage(r.clientConn, hdr.OpCode, payload)
			if err != nil {
				return
			}
			continue
		}

		// Binary frames.
		if hdr.OpCode == ws.OpBinary || (hdr.OpCode == ws.OpContinuation && frag.Active && frag.Opcode == ws.OpBinary) {
			binaryFrames++
			if !r.allowBinary {
				log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "ws_protocol", "binary frames not allowed", r.clientIP, r.requestID)
				r.proxy.metrics.RecordWSScanHit("ws_protocol")
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "binary frames not allowed")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "binary frames not allowed")
				blocked = true
				return
			}
		}

		// Fragment reassembly.
		complete, msg, closeCode, closeReason := frag.Process(hdr, payload)
		if closeCode != 0 {
			log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "ws_protocol", closeReason, r.clientIP, r.requestID)
			plwsutil.WriteCloseFrame(r.clientConn, closeCode, closeReason)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, closeCode, closeReason)
			blocked = true
			return
		}

		if !complete {
			// Fragment accumulated, not yet complete. Buffer until the full
			// message is available for scanning before forwarding.
			continue
		}

		// Complete message. Count and scan.
		if frag.Opcode == ws.OpText || hdr.OpCode == ws.OpText {
			textFrames++

			// UTF-8 validation.
			if !utf8.Valid(msg) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				return
			}

			// Response injection scanning.
			// Skip for response-exempt domains (e.g. trusted LLM providers).
			if r.scanText && r.scanner.ResponseScanningEnabled() && !isResponseScanExempt(r.hostname, r.cfg.ResponseScanning.ExemptDomains) {
				scanResult := r.scanner.ScanResponse(ctx, string(msg))
				if !scanResult.Clean {
					patternNames := make([]string, len(scanResult.Matches))
					for i, m := range scanResult.Matches {
						patternNames[i] = m.PatternName
					}
					respBundleRules := responseBundleRules(scanResult.Matches)
					r.proxy.metrics.RecordWSScanHit("injection")

					// Adaptive enforcement: upgrade the response action before the switch.
					wsAction := r.scanner.ResponseAction()
					originalWSAction := wsAction
					wsAction = decide.UpgradeAction(wsAction, r.escalationLevel(), &r.cfg.AdaptiveEnforcement)
					if wsAction != originalWSAction {
						sessionKey := r.clientIP
						if r.agent != "" && r.agent != agentAnonymous {
							sessionKey = r.agent + "|" + r.clientIP
						}
						log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), originalWSAction, wsAction, "response_scan", r.clientIP, r.requestID)
						r.proxy.metrics.RecordAdaptiveUpgrade(originalWSAction, wsAction, session.EscalationLabel(r.escalationLevel()))
					}

					switch wsAction {
					case config.ActionBlock:
						reason := fmt.Sprintf("injection detected: %s", strings.Join(patternNames, ", "))
						log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "response_scan", reason, r.clientIP, r.requestID)
						plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "injection detected")
						plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "injection detected")
						blocked = true
						return
					case config.ActionStrip:
						// Record SignalStrip for adaptive enforcement scoring.
						if sm := r.proxy.sessionMgrPtr.Load(); sm != nil && r.cfg.AdaptiveEnforcement.Enabled {
							sessionKey := r.clientIP
							if r.agent != "" && r.agent != agentAnonymous {
								sessionKey = r.agent + "|" + r.clientIP
							}
							sess := sm.GetOrCreate(sessionKey)
							decide.RecordEscalation(sess, session.SignalStrip, decide.EscalationParams{
								Threshold: r.cfg.AdaptiveEnforcement.EscalationThreshold,
								Logger:    log,
								Metrics:   r.proxy.metrics,
								Session:   sessionKey,
								ClientIP:  r.clientIP,
								RequestID: r.requestID,
							})
						}
						if scanResult.TransformedContent != "" {
							msg = []byte(scanResult.TransformedContent)
						} else {
							// Cannot strip, fall back to block.
							reason := fmt.Sprintf("injection detected (strip failed): %s", strings.Join(patternNames, ", "))
							log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "response_scan", reason, r.clientIP, r.requestID)
							plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "injection detected")
							plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "injection detected")
							blocked = true
							return
						}
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, config.ActionStrip, len(scanResult.Matches), patternNames, respBundleRules)
					case config.ActionWarn:
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, config.ActionWarn, len(scanResult.Matches), patternNames, respBundleRules)
					case config.ActionAsk:
						// HITL not supported for WebSocket (no request/response cycle).
						// Fail closed: block.
						reason := fmt.Sprintf("injection detected (ask not supported for WS): %s", strings.Join(patternNames, ", "))
						log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "response_scan", reason, r.clientIP, r.requestID)
						plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "injection detected")
						plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "injection detected")
						blocked = true
						return
					default:
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, wsAction, len(scanResult.Matches), patternNames, respBundleRules)
					}
				}
			}
		}

		// Forward complete message to client (proxy is SERVER, no masking).
		opCode := hdr.OpCode
		if frag.Opcode != 0 {
			opCode = frag.Opcode
		}
		err = wsutil.WriteServerMessage(r.clientConn, opCode, msg)
		if err != nil {
			return
		}
		bytesTransferred += int64(len(msg))
		frag.Reset()
	}
}

const (
	// crossMsgOverlap is how many bytes of the previous text message to retain
	// for cross-message DLP scanning. Secrets split across separate WebSocket
	// messages (each FIN=1) would evade per-message scanning without this overlap.
	// 512 bytes covers any single-line DLP pattern with headroom.
	crossMsgOverlap = 512
)

// opCodeLabel returns a human-readable label for metrics.
func opCodeLabel(op ws.OpCode) string {
	switch op {
	case ws.OpText:
		return "text"
	case ws.OpBinary:
		return "binary"
	default:
		return "control"
	}
}
